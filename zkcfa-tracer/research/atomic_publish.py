"""Small fail-closed helpers for immutable inputs and directory publication."""

from __future__ import annotations

import ctypes
import errno
import os
from pathlib import Path
import stat
import sys
from typing import Mapping


def _identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def copy_regular_once(
    source: Path, destination: Path, *, mode: int = 0o400
) -> None:
    """Copy one regular, non-symlink input and reject concurrent mutation.

    The source is opened exactly once with ``O_NOFOLLOW`` where available.
    The descriptor identity is checked before and after the copy; the private
    destination is the only file callers should subsequently parse or hash.
    """

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(source, flags)
    destination_created = False
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError(f"input is not a regular file: {source}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("xb") as output:
            destination_created = True
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
        after = os.fstat(descriptor)
        if _identity(before) != _identity(after):
            raise ValueError(f"input changed while it was snapshotted: {source}")
        destination.chmod(mode)
    except Exception:
        if destination_created:
            destination.unlink(missing_ok=True)
        raise
    finally:
        os.close(descriptor)


def snapshot_regular_files(
    sources: Mapping[str, Path], directory: Path
) -> dict[str, Path]:
    """Create private read-only snapshots, keyed like ``sources``."""

    result: dict[str, Path] = {}
    for index, (label, source) in enumerate(sources.items()):
        safe_label = "".join(
            character if character.isalnum() else "-" for character in label
        ).strip("-")
        destination = directory / f"{index:02d}-{safe_label or 'input'}"
        copy_regular_once(source, destination)
        result[label] = destination
    return result


def rename_noreplace(source: Path, destination: Path) -> None:
    """Atomically publish a directory without replacing an existing name.

    macOS and Linux expose different no-replace rename entry points. Unknown
    platforms fail closed instead of using overwrite-capable ``os.rename``.
    """

    library = ctypes.CDLL(None, use_errno=True)
    encoded_source = os.fsencode(os.fspath(source))
    encoded_destination = os.fsencode(os.fspath(destination))
    if sys.platform == "darwin":
        function = getattr(library, "renamex_np", None)
        if function is None:
            raise RuntimeError("renamex_np is unavailable; refusing unsafe publish")
        function.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
        function.restype = ctypes.c_int
        # <stdio.h>: RENAME_EXCL rejects an existing destination atomically.
        result = function(encoded_source, encoded_destination, 0x00000004)
    elif sys.platform.startswith("linux"):
        function = getattr(library, "renameat2", None)
        if function is None:
            raise RuntimeError("renameat2 is unavailable; refusing unsafe publish")
        function.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        function.restype = ctypes.c_int
        result = function(-100, encoded_source, -100, encoded_destination, 1)
    else:
        raise RuntimeError(
            f"no atomic no-replace directory primitive for {sys.platform!r}"
        )
    if result != 0:
        error = ctypes.get_errno()
        if error == errno.EEXIST:
            raise FileExistsError(error, os.strerror(error), destination)
        raise OSError(error, os.strerror(error), destination)
