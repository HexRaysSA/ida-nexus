"""Portable log archives for ida-nexus semantic and agent sessions."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
import uuid
import zipfile
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

from ida_nexus.paths import STATE_DIR

ARCHIVE_FORMAT = "ida-nexus-logs"
ARCHIVE_SCHEMA = 1
TOC_NAME = "ida-nexus-logs.json"
DEFAULT_SESSIONS_DIR = STATE_DIR / "sessions"
DEFAULT_LOGS_DIR = STATE_DIR / "logs"

_AGENT_SESSION_PATH_SUFFIX = "_session_path"
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")


class LogArchiveError(ValueError):
    """Raised when a log archive cannot be created or opened safely."""


@dataclass(frozen=True)
class MissingAgentSession:
    semantic_session: Path
    kind: str
    recorded_path: str


@dataclass(frozen=True)
class LogArchiveResult:
    output: Path
    session_count: int
    agent_session_count: int
    operational_log_count: int
    missing_agent_sessions: tuple[MissingAgentSession, ...]


@dataclass(frozen=True)
class LogArchiveView:
    """Temporary filesystem view used by the dashboard."""

    archive_path: Path
    sessions_dir: Path
    path_map: dict[str, Path]
    session_agent_paths: dict[tuple[str, str], str]
    source_paths: dict[Path, str]


@dataclass
class _AgentReference:
    kind: str
    recorded_path: str
    source_path: Path | None
    archive_path: str | None = None


@dataclass
class _SessionSource:
    source_path: Path
    archive_path: str
    agent_sessions: list[_AgentReference]


def _read_json_records(path: Path) -> Iterator[dict[str, Any]]:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as file:
            for line in file:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(record, dict):
                    yield record
    except OSError as exc:
        raise LogArchiveError(f"cannot read session file {path}: {exc}") from exc


def _is_semantic_session(path: Path) -> bool:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as file:
            for line in file:
                if not line.strip():
                    continue
                try:
                    first = json.loads(line)
                except json.JSONDecodeError:
                    return False
                return isinstance(first, dict) and first.get("schema") == 1
    except OSError:
        return False
    return False


def _canonical_file(path: Path, *, label: str) -> Path:
    resolved = path.expanduser().resolve()
    if not resolved.is_file():
        raise LogArchiveError(f"{label} does not exist or is not a file: {path}")
    return resolved


def _select_sessions(
    session_files: Sequence[Path] | None, sessions_dir: Path
) -> list[Path]:
    if session_files:
        selected: list[Path] = []
        for requested in session_files:
            path = _canonical_file(requested, label="session file")
            if not _is_semantic_session(path):
                raise LogArchiveError(
                    f"not an ida-nexus semantic session (schema 1): {requested}"
                )
            selected.append(path)
    else:
        directory = sessions_dir.expanduser().resolve()
        if not directory.is_dir():
            raise LogArchiveError(f"sessions directory does not exist: {directory}")
        selected = [
            path.resolve()
            for path in sorted(directory.glob("*.jsonl"))
            if path.is_file() and _is_semantic_session(path)
        ]

    unique = list(dict.fromkeys(selected))
    if not unique:
        raise LogArchiveError("no ida-nexus semantic sessions found")
    return sorted(unique, key=lambda path: str(path))


def _find_agent_file(recorded_path: str, semantic_session: Path) -> Path | None:
    try:
        recorded = Path(recorded_path).expanduser()
        candidates = [recorded]
        if not recorded.is_absolute():
            candidates.append(semantic_session.parent / recorded)
        for candidate in candidates:
            if candidate.is_file():
                resolved = candidate.resolve()
                if resolved != semantic_session:
                    return resolved

        # Benchmark bundles retain the MCP trace below logs/ida-nexus while
        # the corresponding agent transcript is logs/session.jsonl.
        for ancestor in (semantic_session.parent, semantic_session.parent.parent):
            candidate = ancestor / "session.jsonl"
            if candidate.is_file() and candidate.resolve() != semantic_session:
                return candidate.resolve()
    except (OSError, ValueError):
        pass
    return None


def iter_agent_session_paths(session: object) -> Iterator[tuple[str, str]]:
    """Yield ``(agent kind, path)`` pairs from conventional session metadata."""

    if not isinstance(session, dict):
        return
    for field, value in session.items():
        if not isinstance(field, str) or not field.endswith(_AGENT_SESSION_PATH_SUFFIX):
            continue
        kind = field[: -len(_AGENT_SESSION_PATH_SUFFIX)]
        if kind and isinstance(value, str) and value:
            yield kind, value


def _agent_references(path: Path) -> list[_AgentReference]:
    references: list[_AgentReference] = []
    seen: set[tuple[str, str]] = set()
    for record in _read_json_records(path):
        for kind, value in iter_agent_session_paths(record.get("session")):
            if (kind, value) in seen:
                continue
            seen.add((kind, value))
            references.append(
                _AgentReference(kind, value, _find_agent_file(value, path))
            )

    # OMP stores delegated sessions beside ``parent.jsonl`` in
    # ``parent/*.jsonl``. Include the whole delegation group, including agents
    # that never received or called an IDA Nexus tool and therefore cannot
    # appear in a semantic trace of their own.
    for reference in list(references):
        source = reference.source_path
        if source is None:
            continue
        children = source.with_suffix("")
        try:
            candidates = sorted(children.glob("*.jsonl")) if children.is_dir() else []
        except OSError:
            candidates = []
        for candidate in candidates:
            try:
                child = candidate.resolve()
            except OSError:
                continue
            key = (reference.kind, str(child))
            if not child.is_file() or key in seen:
                continue
            seen.add(key)
            references.append(_AgentReference(reference.kind, str(child), child))
    return references


def _archive_component(value: str, *, default: str) -> str:
    component = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._")
    return (component or default)[:120]


def _archive_basename(path: Path) -> str:
    return _archive_component(path.name, default="session.jsonl")


def _operational_logs(logs_dir: Path, output: Path) -> list[tuple[Path, str]]:
    root = logs_dir.expanduser().resolve()
    if not root.is_dir():
        return []

    logs: list[tuple[Path, str]] = []
    used_members: set[str] = set()
    for path in sorted(root.rglob("*")):
        try:
            if path.is_symlink() or not path.is_file():
                continue
            resolved = path.resolve()
        except OSError:
            continue
        if resolved == output:
            continue
        relative = path.relative_to(root)
        parts = [part.replace("\\", "_") for part in relative.parts]
        member = str(PurePosixPath("logs", *parts))
        if member in used_members:
            suffix = hashlib.sha256(str(relative).encode()).hexdigest()[:8]
            member = f"{member}.{suffix}"
        used_members.add(member)
        logs.append((resolved, member))
    return logs


def _zip_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = (stat.S_IFREG | 0o600) << 16
    return info


def _write_file(
    archive: zipfile.ZipFile, source: Path, archive_path: str
) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    try:
        with (
            source.open("rb") as input_file,
            archive.open(_zip_info(archive_path), "w") as output_file,
        ):
            while chunk := input_file.read(1024 * 1024):
                output_file.write(chunk)
                digest.update(chunk)
                size += len(chunk)
    except OSError as exc:
        raise LogArchiveError(f"cannot archive {source}: {exc}") from exc
    return size, digest.hexdigest()


def _timestamp() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def create_log_archive(
    output: Path,
    session_files: Sequence[Path] | None = None,
    *,
    sessions_dir: Path = DEFAULT_SESSIONS_DIR,
    logs_dir: Path = DEFAULT_LOGS_DIR,
    overwrite: bool = False,
) -> LogArchiveResult:
    """Create a ZIP containing semantic sessions and their linked transcripts."""

    sessions = _select_sessions(session_files, sessions_dir)
    output = output.expanduser().resolve()
    if output.exists() and not overwrite:
        raise LogArchiveError(f"output already exists (use --force): {output}")
    if output in sessions:
        raise LogArchiveError("output path cannot be one of the selected sessions")
    output.parent.mkdir(parents=True, exist_ok=True)
    operational_logs = _operational_logs(logs_dir, output)

    session_sources: list[_SessionSource] = []
    for index, path in enumerate(sessions, start=1):
        session_sources.append(
            _SessionSource(
                path,
                f"sessions/{index:04d}-{_archive_basename(path)}",
                _agent_references(path),
            )
        )

    agents: dict[Path, tuple[str, str]] = {}
    for session in session_sources:
        for reference in session.agent_sessions:
            if reference.source_path is None:
                continue
            existing = agents.get(reference.source_path)
            if existing is None:
                index = len(agents) + 1
                kind = _archive_component(reference.kind, default="agent")
                member = (
                    f"agent-sessions/{index:04d}-{kind}-"
                    f"{_archive_basename(reference.source_path)}"
                )
                agents[reference.source_path] = (reference.kind, member)
            reference.archive_path = agents[reference.source_path][1]

    if output in agents:
        raise LogArchiveError("output path cannot be a linked agent session")

    missing = tuple(
        MissingAgentSession(
            session.source_path, reference.kind, reference.recorded_path
        )
        for session in session_sources
        for reference in session.agent_sessions
        if reference.source_path is None
    )

    temporary = output.parent / f".{output.name}.tmp-{uuid.uuid4().hex}"
    file_entries: list[dict[str, Any]] = []
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with (
            os.fdopen(fd, "w+b") as archive_file,
            zipfile.ZipFile(archive_file, "w", allowZip64=True) as archive,
        ):
            for session in session_sources:
                size, digest = _write_file(
                    archive, session.source_path, session.archive_path
                )
                file_entries.append(
                    {
                        "kind": "semantic_session",
                        "source_path": str(session.source_path),
                        "archive_path": session.archive_path,
                        "size": size,
                        "sha256": digest,
                    }
                )
            for source, (kind, archive_path) in agents.items():
                size, digest = _write_file(archive, source, archive_path)
                file_entries.append(
                    {
                        "kind": "agent_session",
                        "agent": kind,
                        "source_path": str(source),
                        "archive_path": archive_path,
                        "size": size,
                        "sha256": digest,
                    }
                )
            # Operational logs are carried under logs/ as-is. They are not
            # dashboard data and do not need original-path entries in the TOC.
            for source, archive_path in operational_logs:
                _write_file(archive, source, archive_path)

            path_map = {
                entry["source_path"]: entry["archive_path"] for entry in file_entries
            }
            toc = {
                "format": ARCHIVE_FORMAT,
                "schema": ARCHIVE_SCHEMA,
                "created_at": _timestamp(),
                "sessions_root": str(sessions_dir.expanduser().resolve()),
                "sessions": [
                    {
                        "source_path": str(session.source_path),
                        "archive_path": session.archive_path,
                        "agent_sessions": [
                            {
                                "kind": reference.kind,
                                "recorded_path": reference.recorded_path,
                                "source_path": (
                                    str(reference.source_path)
                                    if reference.source_path is not None
                                    else None
                                ),
                                "archive_path": reference.archive_path,
                            }
                            for reference in session.agent_sessions
                        ],
                    }
                    for session in session_sources
                ],
                "files": file_entries,
                "path_map": path_map,
            }
            archive.writestr(
                _zip_info(TOC_NAME),
                json.dumps(toc, ensure_ascii=False, indent=2) + "\n",
            )
        os.replace(temporary, output)
        try:
            output.chmod(0o600)
        except OSError:
            pass
    except Exception:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise

    return LogArchiveResult(
        output,
        len(session_sources),
        len(agents),
        len(operational_logs),
        missing,
    )


def _member_name(value: object, *, field: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise LogArchiveError(f"invalid {field} in {TOC_NAME}")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise LogArchiveError(f"unsafe {field} in {TOC_NAME}: {value!r}")
    return str(path)


def _load_toc(archive: zipfile.ZipFile) -> dict[str, Any]:
    names = [item.filename for item in archive.infolist()]
    if len(names) != len(set(names)):
        raise LogArchiveError("archive contains duplicate ZIP member names")
    try:
        info = archive.getinfo(TOC_NAME)
    except KeyError as exc:
        raise LogArchiveError(f"archive is missing {TOC_NAME}") from exc
    if info.file_size > 16 * 1024 * 1024:
        raise LogArchiveError(f"{TOC_NAME} is unexpectedly large")
    try:
        toc = json.loads(archive.read(info).decode("utf-8"))
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        OSError,
        RuntimeError,
        zipfile.BadZipFile,
    ) as exc:
        raise LogArchiveError(f"cannot read {TOC_NAME}: {exc}") from exc
    if not isinstance(toc, dict):
        raise LogArchiveError(f"{TOC_NAME} must contain a JSON object")
    if toc.get("format") != ARCHIVE_FORMAT or toc.get("schema") != ARCHIVE_SCHEMA:
        raise LogArchiveError(f"unsupported log archive format/schema in {TOC_NAME}")
    return toc


def _extract_member(
    archive: zipfile.ZipFile,
    member: str,
    destination: Path,
    expected_size: int,
    expected_hash: str,
) -> None:
    try:
        info = archive.getinfo(member)
    except KeyError as exc:
        raise LogArchiveError(
            f"archive is missing file listed in TOC: {member}"
        ) from exc
    if info.is_dir() or info.file_size != expected_size:
        raise LogArchiveError(f"size mismatch for archive member: {member}")

    destination.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    size = 0
    try:
        with archive.open(info) as input_file, destination.open("xb") as output_file:
            while chunk := input_file.read(1024 * 1024):
                size += len(chunk)
                if size > expected_size:
                    raise LogArchiveError(f"size mismatch for archive member: {member}")
                output_file.write(chunk)
                digest.update(chunk)
    except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
        raise LogArchiveError(f"cannot extract archive member {member}: {exc}") from exc
    if size != expected_size or digest.hexdigest() != expected_hash:
        raise LogArchiveError(f"checksum mismatch for archive member: {member}")


def _extract_log_archive(archive_path: Path, root: Path) -> LogArchiveView:
    try:
        archive_file = zipfile.ZipFile(archive_path)
    except (OSError, zipfile.BadZipFile) as exc:
        raise LogArchiveError(f"cannot open log archive {archive_path}: {exc}") from exc

    with archive_file as archive:
        toc = _load_toc(archive)
        raw_files = toc.get("files")
        raw_sessions = toc.get("sessions")
        raw_path_map = toc.get("path_map")
        if not isinstance(raw_files, list) or not isinstance(raw_sessions, list):
            raise LogArchiveError(f"invalid files/sessions tables in {TOC_NAME}")
        if not isinstance(raw_path_map, dict):
            raise LogArchiveError(f"invalid path_map in {TOC_NAME}")

        members: dict[str, tuple[str, str, Path]] = {}
        source_paths: dict[Path, str] = {}
        semantic_members: set[str] = set()
        for raw in raw_files:
            if not isinstance(raw, dict):
                raise LogArchiveError(f"invalid file entry in {TOC_NAME}")
            kind = raw.get("kind")
            source = raw.get("source_path")
            member = _member_name(raw.get("archive_path"), field="archive_path")
            size = raw.get("size")
            digest = raw.get("sha256")
            if kind not in ("semantic_session", "agent_session"):
                raise LogArchiveError(f"invalid file kind in {TOC_NAME}")
            if not isinstance(source, str) or not source:
                raise LogArchiveError(f"invalid source_path in {TOC_NAME}")
            if not isinstance(size, int) or size < 0:
                raise LogArchiveError(f"invalid file size in {TOC_NAME}")
            if not isinstance(digest, str) or not _HASH_RE.fullmatch(digest):
                raise LogArchiveError(f"invalid file checksum in {TOC_NAME}")
            expected_parent = (
                "sessions" if kind == "semantic_session" else "agent-sessions"
            )
            member_path = PurePosixPath(member)
            if len(member_path.parts) != 2 or member_path.parts[0] != expected_parent:
                raise LogArchiveError(f"invalid {kind} archive path: {member}")
            if member in members:
                raise LogArchiveError(f"duplicate file entry in {TOC_NAME}: {member}")
            destination = root.joinpath(*member_path.parts)
            members[member] = (source, kind, destination)
            source_paths[destination.resolve()] = source
            if kind == "semantic_session":
                semantic_members.add(member)
            _extract_member(archive, member, destination, size, digest)

        path_map: dict[str, Path] = {}
        for source, raw_member in raw_path_map.items():
            if not isinstance(source, str) or not source:
                raise LogArchiveError(f"invalid path_map key in {TOC_NAME}")
            member = _member_name(raw_member, field="path_map value")
            file_entry = members.get(member)
            if file_entry is None or file_entry[0] != source:
                raise LogArchiveError(f"path_map does not match files table: {source}")
            path_map[source] = file_entry[2]
        expected_path_map = {
            source: destination for source, _kind, destination in members.values()
        }
        if path_map != expected_path_map:
            raise LogArchiveError(f"path_map is incomplete in {TOC_NAME}")

        session_agent_paths: dict[tuple[str, str], str] = {}
        listed_sessions: set[str] = set()
        for raw_session in raw_sessions:
            if not isinstance(raw_session, dict):
                raise LogArchiveError(f"invalid session entry in {TOC_NAME}")
            member = _member_name(
                raw_session.get("archive_path"), field="session archive_path"
            )
            source = raw_session.get("source_path")
            file_entry = members.get(member)
            if (
                member not in semantic_members
                or not isinstance(source, str)
                or file_entry is None
                or file_entry[0] != source
            ):
                raise LogArchiveError(
                    f"session table does not match files table: {member}"
                )
            listed_sessions.add(member)
            raw_agents = raw_session.get("agent_sessions")
            if not isinstance(raw_agents, list):
                raise LogArchiveError(f"invalid agent_sessions in {TOC_NAME}")
            for raw_agent in raw_agents:
                if not isinstance(raw_agent, dict):
                    raise LogArchiveError(f"invalid agent session entry in {TOC_NAME}")
                kind = raw_agent.get("kind")
                recorded = raw_agent.get("recorded_path")
                agent_source = raw_agent.get("source_path")
                agent_member = raw_agent.get("archive_path")
                if (
                    not isinstance(kind, str)
                    or not kind
                    or not isinstance(recorded, str)
                ):
                    raise LogArchiveError(
                        f"invalid agent session reference in {TOC_NAME}"
                    )
                if agent_source is None and agent_member is None:
                    continue
                if not isinstance(agent_source, str):
                    raise LogArchiveError(f"invalid agent source path in {TOC_NAME}")
                normalized_member = _member_name(
                    agent_member, field="agent archive_path"
                )
                agent_entry = members.get(normalized_member)
                if (
                    agent_entry is None
                    or agent_entry[1] != "agent_session"
                    or agent_entry[0] != agent_source
                ):
                    raise LogArchiveError(
                        f"agent session table does not match files table: {recorded}"
                    )
                semantic_path = str(file_entry[2].resolve())
                session_agent_paths[(semantic_path, recorded)] = agent_source

        if listed_sessions != semantic_members:
            raise LogArchiveError(f"sessions table is incomplete in {TOC_NAME}")

    return LogArchiveView(
        archive_path,
        (root / "sessions").resolve(),
        path_map,
        session_agent_paths,
        source_paths,
    )


@contextmanager
def open_log_archive(path: Path) -> Iterator[LogArchiveView]:
    """Validate and extract a log archive for the duration of the context."""

    archive_path = _canonical_file(path, label="log archive")
    with tempfile.TemporaryDirectory(prefix="ida-nexus-logs-") as directory:
        yield _extract_log_archive(archive_path, Path(directory).resolve())


def _default_output() -> Path:
    stamp = datetime.now(UTC).astimezone().strftime("%Y%m%d-%H%M%S")
    return Path.cwd() / f"ida-nexus-logs-{stamp}.zip"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ida-nexus logs",
        description=(
            "Create a ZIP containing ida-nexus semantic sessions, linked "
            "agent transcripts, and operational logs."
        ),
    )
    parser.add_argument(
        "session_files",
        nargs="*",
        type=Path,
        help="Semantic session JSONL files (default: collect every local session)",
    )
    parser.add_argument("-o", "--output", type=Path, help="Output ZIP path")
    parser.add_argument(
        "--sessions-dir",
        type=Path,
        default=DEFAULT_SESSIONS_DIR,
        help="Local semantic sessions directory used when no files are given",
    )
    parser.add_argument(
        "--force", action="store_true", help="Replace an existing output ZIP"
    )
    args = parser.parse_args(argv)

    output = args.output or _default_output()
    try:
        result = create_log_archive(
            output,
            args.session_files or None,
            sessions_dir=args.sessions_dir,
            overwrite=args.force,
        )
    except (LogArchiveError, OSError, zipfile.BadZipFile) as exc:
        print(f"ida-nexus logs: error: {exc}", file=sys.stderr)
        return 2

    for missing in result.missing_agent_sessions:
        print(
            "ida-nexus logs: warning: linked "
            f"{missing.kind} session not found: {missing.recorded_path} "
            f"(from {missing.semantic_session})",
            file=sys.stderr,
        )
    print(f"created {result.output}")
    print(
        f"included {result.session_count} semantic session(s), "
        f"{result.agent_session_count} linked agent session(s), and "
        f"{result.operational_log_count} operational log file(s)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
