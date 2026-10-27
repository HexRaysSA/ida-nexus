"""Inspect packed and unpacked IDA database state without opening IDA."""

from __future__ import annotations

import ctypes
import errno
import os
import shutil
import sys
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Literal, TypedDict

from ._registry import canonical_path

_B_TREE_DIRTY_OFFSET = 18
_B_TREE_SIGNATURE_OFFSET = 19
_B_TREE_SIGNATURE = b"B-tree v2"
_B_TREE_HEADER_SIZE = _B_TREE_SIGNATURE_OFFSET + len(_B_TREE_SIGNATURE)
_UNPACKED_SUFFIXES = (".id0", ".id1", ".id2", ".nam", ".til")
_POSIX_PROBE_LOCK = threading.Lock()

DatabaseFileStateName = Literal[
    "missing",
    "packed",
    "in_use",
    "crashed",
    "unpacked",
    "unknown",
]
DatabaseRecovery = Literal["none", "repaired", "restored"]


class DatabaseFileState(TypedDict):
    """Observable state of one IDA database's packed and unpacked files."""

    state: DatabaseFileStateName
    requested_path: str
    idb_path: str
    id0_path: str
    packed_database_exists: bool
    unpacked_files: list[str]
    dirty: bool | None
    error: str | None


def expected_idb_path(path: str | os.PathLike[str]) -> str:
    """Return the database path IDA uses for an executable or existing IDB."""

    source = canonical_path(path)
    return source if source.lower().endswith((".i64", ".idb")) else source + ".i64"


def unpacked_database_paths(idb_path: str | os.PathLike[str]) -> tuple[Path, ...]:
    """Return the conventional unpacked component paths for an IDB."""

    path = Path(canonical_path(idb_path))
    return tuple(path.with_suffix(suffix) for suffix in _UNPACKED_SUFFIXES)


def _network_filesystem(path: Path) -> bool | None:
    """Return whether lock semantics are untrusted for this filesystem."""

    if os.name == "nt":
        if str(path).startswith(("\\\\", "//")):
            return True
        root = path.anchor
        if not root:
            return None
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        get_drive_type = kernel32.GetDriveTypeW
        get_drive_type.argtypes = (wintypes.LPCWSTR,)
        get_drive_type.restype = wintypes.UINT
        drive_type = get_drive_type(root)
        if drive_type in (0, 1):
            return None
        return drive_type == 4

    if sys.platform == "darwin":

        class Fsid(ctypes.Structure):
            _fields_ = [("value", ctypes.c_int32 * 2)]

        class StatFs(ctypes.Structure):
            _fields_ = [
                ("f_bsize", ctypes.c_uint32),
                ("f_iosize", ctypes.c_int32),
                ("f_blocks", ctypes.c_uint64),
                ("f_bfree", ctypes.c_uint64),
                ("f_bavail", ctypes.c_uint64),
                ("f_files", ctypes.c_uint64),
                ("f_ffree", ctypes.c_uint64),
                ("f_fsid", Fsid),
                ("f_owner", ctypes.c_uint32),
                ("f_type", ctypes.c_uint32),
                ("f_flags", ctypes.c_uint32),
                ("f_fssubtype", ctypes.c_uint32),
                ("f_fstypename", ctypes.c_char * 16),
                ("f_mntonname", ctypes.c_char * 1024),
                ("f_mntfromname", ctypes.c_char * 1024),
                ("f_reserved", ctypes.c_uint32 * 8),
            ]

        status = StatFs()
        statfs = ctypes.CDLL(None, use_errno=True).statfs
        statfs.argtypes = (ctypes.c_char_p, ctypes.POINTER(StatFs))
        statfs.restype = ctypes.c_int
        if statfs(os.fsencode(path), ctypes.byref(status)) != 0:
            return None
        return not bool(status.f_flags & 0x00001000)

    if sys.platform.startswith("linux"):
        try:
            lines = (
                Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines()
            )
        except OSError:
            return None
        target = str(path.resolve())
        selected: tuple[int, str] | None = None
        for line in lines:
            try:
                mount, filesystem = line.split(" - ", 1)
                mount_point = mount.split()[4]
                mount_point = (
                    mount_point.replace("\\040", " ")
                    .replace("\\011", "\t")
                    .replace("\\012", "\n")
                    .replace("\\134", "\\")
                )
                if os.path.commonpath((target, mount_point)) != mount_point:
                    continue
                candidate = (len(mount_point), filesystem.split()[0])
                if selected is None or candidate[0] > selected[0]:
                    selected = candidate
            except (IndexError, ValueError):
                continue
        if selected is None:
            return None
        return selected[1] in {
            "9p",
            "afs",
            "ceph",
            "cifs",
            "fuse.sshfs",
            "glusterfs",
            "nfs",
            "nfs4",
            "smb3",
        }
    return None


@contextmanager
def _locked_posix_header(
    path: Path,
) -> Iterator[tuple[bool | None, bytes | None, str | None]]:
    import fcntl

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except OSError as error:
        yield None, None, str(error)
        return
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            if error.errno in {errno.EACCES, errno.EAGAIN}:
                yield True, None, None
            else:
                yield None, None, str(error)
            return
        try:
            yield False, os.read(fd, _B_TREE_HEADER_SIZE), None
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


@contextmanager
def _locked_windows_header(
    path: Path,
) -> Iterator[tuple[bool | None, bytes | None, str | None]]:
    if os.name != "nt":
        raise RuntimeError("Windows database header reader requires Windows")
    from ctypes import wintypes

    generic_read = 0x80000000
    generic_write = 0x40000000
    share_all = 0x00000001 | 0x00000002 | 0x00000004
    open_existing = 3
    sharing_violation = 32
    invalid_handle = ctypes.c_void_p(-1).value

    win_dll = ctypes.WinDLL
    get_last_error = ctypes.get_last_error
    kernel32 = win_dll("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    create_file.restype = wintypes.HANDLE
    handle = create_file(
        str(path),
        generic_read | generic_write,
        share_all,
        None,
        open_existing,
        0,
        None,
    )
    if handle == invalid_handle:
        error_code = get_last_error()
        if error_code == sharing_violation:
            yield True, None, None
        else:
            yield None, None, f"CreateFileW failed with Windows error {error_code}"
        return

    try:
        buffer = ctypes.create_string_buffer(_B_TREE_HEADER_SIZE)
        read = wintypes.DWORD()
        read_file = kernel32.ReadFile
        read_file.argtypes = (
            wintypes.HANDLE,
            wintypes.LPVOID,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            wintypes.LPVOID,
        )
        read_file.restype = wintypes.BOOL
        if not read_file(handle, buffer, len(buffer), ctypes.byref(read), None):
            error_code = get_last_error()
            yield None, None, f"ReadFile failed with Windows error {error_code}"
            return
        yield False, buffer.raw[: read.value], None
    finally:
        close_handle = kernel32.CloseHandle
        close_handle.argtypes = (wintypes.HANDLE,)
        close_handle.restype = wintypes.BOOL
        close_handle(handle)


@contextmanager
def _locked_unpacked_header(
    path: Path,
) -> Iterator[tuple[bool | None, bytes | None, str | None]]:
    if os.name == "nt":
        with _locked_windows_header(path) as result:
            yield result
        return
    # flock locks belong to open file descriptions, not Python threads. An RPC
    # failure and SSE disconnect can probe concurrently and mistake our own
    # exclusive reader lock for a live IDA owner. Serialize local readers while
    # retaining the nonblocking exclusive OS probe against external owners.
    with _POSIX_PROBE_LOCK, _locked_posix_header(path) as result:
        yield result


def _backup_unpacked_database(state: DatabaseFileState) -> str:
    """Durably copy crash leftovers before IDA restores a packed database."""

    timestamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    backup = Path(
        f"{state['idb_path']}.crash-{timestamp}-{os.getpid()}-{time.time_ns() % 1_000_000:06d}"
    )
    backup.mkdir(mode=0o700)
    for source_name in state["unpacked_files"]:
        source = Path(source_name)
        if not source.is_file() or source.is_symlink():
            raise OSError(f"unsafe unpacked database component: {source}")
        destination = backup / source.name
        with source.open("rb") as input_file, destination.open("xb") as output_file:
            shutil.copyfileobj(input_file, output_file, length=1024 * 1024)
            output_file.flush()
            os.fsync(output_file.fileno())
        shutil.copystat(source, destination, follow_symlinks=False)
    if os.name != "nt":
        directory_fd = os.open(backup, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    return str(backup)


@contextmanager
def _locked_database_state(
    path: str | os.PathLike[str],
    *,
    output_database: str | os.PathLike[str] | None = None,
) -> Iterator[DatabaseFileState]:
    """Inspect the state, retaining native-file exclusion until the caller exits."""

    requested = canonical_path(path)
    idb_path = (
        canonical_path(output_database)
        if output_database is not None
        else expected_idb_path(requested)
    )
    unpacked = unpacked_database_paths(idb_path)
    existing = [str(component) for component in unpacked if component.exists()]
    id0_path = unpacked[0]
    packed_exists = Path(idb_path).is_file()

    common: DatabaseFileState = {
        "state": "unknown",
        "requested_path": requested,
        "idb_path": idb_path,
        "id0_path": str(id0_path),
        "packed_database_exists": packed_exists,
        "unpacked_files": existing,
        "dirty": None,
        "error": None,
    }
    if not id0_path.exists():
        if existing:
            common["error"] = "unpacked database components exist without .id0"
        else:
            common["state"] = "packed" if packed_exists else "missing"
        yield common
        return

    if _network_filesystem(id0_path) is True:
        common["error"] = (
            "database is on a network filesystem where file locks are not reliable"
        )
        yield common
        return

    with _locked_unpacked_header(id0_path) as (locked, header, error):
        if locked is True:
            common["state"] = "in_use"
        elif locked is None or header is None:
            common["error"] = error or "could not inspect .id0"
        elif len(header) < _B_TREE_HEADER_SIZE:
            common["error"] = "the .id0 B-tree header is truncated"
        elif header[_B_TREE_SIGNATURE_OFFSET:_B_TREE_HEADER_SIZE] != _B_TREE_SIGNATURE:
            common["error"] = "the .id0 B-tree signature is invalid"
        else:
            dirty_byte = header[_B_TREE_DIRTY_OFFSET]
            if dirty_byte not in (0, 1):
                common["error"] = (
                    f"the .id0 isTreeOpen byte has invalid value {dirty_byte}"
                )
            else:
                common["dirty"] = bool(dirty_byte)
                common["state"] = "crashed" if dirty_byte else "unpacked"
        yield common


def probe_database_state(
    path: str | os.PathLike[str],
    *,
    output_database: str | os.PathLike[str] | None = None,
) -> DatabaseFileState:
    """Classify an IDB as packed, live, crashed, clean-unpacked, or unknown.

    The ``.id0`` lock is authoritative for a live local session. The B-tree
    ``isTreeOpen`` byte is read only while the probe owns the lock and therefore
    distinguishes crash leftovers from a deliberately unpacked clean database.
    Advisory locks may be unreliable on network filesystems; callers must treat
    an unlocked result on such storage as untrusted.
    """
    with _locked_database_state(path, output_database=output_database) as state:
        return state


def _discard_failed_launch_extraction(source: str, expected_idb: str) -> str:
    """Discard extraction only after a guarded launch failed before native open.

    The caller must establish final process exit and preservation of pre-launch
    data in a packed base or crash backup. Keep .id0 locked until all components
    are removed; unlink it last so another IDA cannot acquire it mid-cleanup.
    """
    with _locked_database_state(source, output_database=expected_idb) as state:
        if state["state"] not in {"crashed", "unpacked"}:
            return ""
        removed = 0
        failure = ""
        for component in reversed(state["unpacked_files"]):
            try:
                os.remove(component)
            except OSError as error:
                failure = f" Could not remove {component}: {error}"
                # Retain .id0 if another component could not be removed.
                break
            else:
                removed += 1
        return (
            f"Removed {removed} unpacked database files left by the failed worker "
            f"next to {expected_idb}.{failure}"
        )


__all__ = [
    "DatabaseFileState",
    "DatabaseFileStateName",
    "DatabaseRecovery",
    "expected_idb_path",
    "probe_database_state",
]
