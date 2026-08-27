#!/usr/bin/env python3
"""Keep every ida-nexus version declaration in sync.

The release workflow calls this script with one of ``dev``, ``release-patch``,
or ``release-minor``. An exact version can also be supplied for local use.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
PROJECT_NAME = "ida-nexus"
VERSION_RE = re.compile(
    r"^(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*)"
    r"(?:(?:-dev\.|\.dev)(?P<dev>[1-9]\d*))?$"
)

JSON_FIELDS: dict[str, tuple[tuple[str, ...], ...]] = {
    "ida-plugin.json": (("plugin", "version"),),
}
MANAGED_FILES = (
    "pyproject.toml",
    "uv.lock",
    "ida-plugin.json",
    "ida_nexus/_http.py",
)


class VersionError(RuntimeError):
    """Raised when version declarations are missing or inconsistent."""


def _read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def _json_value(document: Any, pointer: tuple[str, ...], path: str) -> Any:
    value = document
    try:
        for component in pointer:
            value = value[component]
    except (KeyError, TypeError) as exc:
        rendered = "/".join(pointer)
        raise VersionError(f"{path}: missing JSON field {rendered!r}") from exc
    return value


def _current_version(pyproject_text: str) -> str:
    try:
        version = tomllib.loads(pyproject_text)["project"]["version"]
    except (KeyError, tomllib.TOMLDecodeError) as exc:
        raise VersionError("pyproject.toml: missing project.version") from exc
    if not isinstance(version, str) or VERSION_RE.fullmatch(version) is None:
        raise VersionError(f"pyproject.toml: unsupported project.version {version!r}")
    return version


def _replace_exact(text: str, old: str, new: str, path: str, expected: int = 1) -> str:
    count = text.count(old)
    if count != expected:
        raise VersionError(
            f"{path}: expected {expected} occurrence(s) of {old!r}, found {count}"
        )
    return text.replace(old, new)


def _replace_json_versions(path: str, text: str, old: str, new: str) -> str:
    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        raise VersionError(f"{path}: invalid JSON: {exc}") from exc

    pointers = JSON_FIELDS[path]
    for pointer in pointers:
        actual = _json_value(document, pointer, path)
        if actual != old:
            rendered = "/".join(pointer)
            raise VersionError(f"{path}: {rendered} is {actual!r}, expected {old!r}")

    pattern = re.compile(rf'(?m)^(\s*"version"\s*:\s*)"{re.escape(old)}"(,?)$')
    matches = list(pattern.finditer(text))
    if len(matches) < len(pointers):
        raise VersionError(
            f"{path}: found only {len(matches)} formatted version field(s); expected {len(pointers)}"
        )
    replacements = 0

    def replace(match: re.Match[str]) -> str:
        nonlocal replacements
        if replacements >= len(pointers):
            return match.group(0)
        replacements += 1
        return f'{match.group(1)}"{new}"{match.group(2)}'

    return pattern.sub(replace, text)


def _updated_files(old: str, new: str) -> dict[str, str]:
    texts = {path: _read(path) for path in MANAGED_FILES}

    for path in JSON_FIELDS:
        texts[path] = _replace_json_versions(path, texts[path], old, new)

    texts["pyproject.toml"] = _replace_exact(
        texts["pyproject.toml"],
        f'version = "{old}"',
        f'version = "{new}"',
        "pyproject.toml",
    )

    uv_pattern = re.compile(
        rf'(\[\[package\]\]\nname = "{re.escape(PROJECT_NAME)}"\nversion = ")'
        rf'{re.escape(old)}("\n)'
    )
    uv_text, count = uv_pattern.subn(rf"\g<1>{new}\g<2>", texts["uv.lock"])
    if count != 1:
        raise VersionError(
            f"uv.lock: expected one {PROJECT_NAME!r} package version, found {count}"
        )
    texts["uv.lock"] = uv_text

    texts["ida_nexus/_http.py"] = _replace_exact(
        texts["ida_nexus/_http.py"],
        f'server_version = "ida-nexus/{old}"',
        f'server_version = "ida-nexus/{new}"',
        "ida_nexus/_http.py",
    )

    # The plugin archive ships only the entry point; ida_nexus itself is
    # installed from PyPI as a pythonDependency, pinned to this same release.
    texts["ida-plugin.json"] = _replace_exact(
        texts["ida-plugin.json"],
        f'"ida-nexus=={old}"',
        f'"ida-nexus=={new}"',
        "ida-plugin.json",
    )
    return texts


def _next_version(current: str, requested: str) -> str:
    exact = VERSION_RE.fullmatch(requested)
    if exact:
        # Always use one spelling across Python packaging and the IDA plugin.
        dev = exact.group("dev")
        base = f"{exact.group('major')}.{exact.group('minor')}.{exact.group('patch')}"
        return f"{base}-dev.{dev}" if dev else base

    aliases = {
        "dev": "dev",
        "patch": "patch",
        "minor": "minor",
        "major": "major",
        "release-patch": "patch",
        "release-minor": "minor",
        "release-major": "major",
    }
    try:
        bump = aliases[requested]
    except KeyError as exc:
        raise VersionError(
            f"unknown version {requested!r}; use dev, release-patch, release-minor, "
            "release-major, or an exact version"
        ) from exc

    match = VERSION_RE.fullmatch(current)
    assert match is not None
    major, minor, patch = (
        int(match.group(name)) for name in ("major", "minor", "patch")
    )
    dev = match.group("dev")
    if bump == "dev":
        if dev is None:
            patch += 1
            dev_number = 1
        else:
            dev_number = int(dev) + 1
        return f"{major}.{minor}.{patch}-dev.{dev_number}"
    if bump == "patch":
        if dev is None:
            patch += 1
        return f"{major}.{minor}.{patch}"
    if bump == "minor":
        return f"{major}.{minor + 1}.0"
    return f"{major + 1}.0.0"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "version", nargs="?", help="exact version or dev/release-{patch,minor,major}"
    )
    parser.add_argument(
        "--check", action="store_true", help="verify all version declarations"
    )
    args = parser.parse_args(argv)
    if args.check == (args.version is not None):
        parser.error("provide exactly one of VERSION or --check")

    try:
        pyproject_text = _read("pyproject.toml")
        current = _current_version(pyproject_text)
        if args.check:
            # Replacing a version with itself exercises every declaration validator.
            _updated_files(current, current)
            print(current)
            return 0

        new = _next_version(current, args.version)
        texts = _updated_files(current, new)
        for path, text in texts.items():
            (ROOT / path).write_text(text, encoding="utf-8")
        print(new)
        return 0
    except (OSError, VersionError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
