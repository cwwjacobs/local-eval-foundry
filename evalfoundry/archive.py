"""Canonical archive helpers used by release pack builders."""

from __future__ import annotations

import hashlib
import os
import tempfile
import zipfile
from pathlib import Path

_FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)
_FILE_MODE = 0o100644 << 16


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonicalize_zip(path: str | Path) -> str:
    """Rewrite a ZIP into a byte-stable release representation.

    Entries are sorted by path, timestamps and permissions are fixed, duplicate
    names are rejected, and files use ZIP_STORED so output does not vary with a
    platform's zlib implementation.
    """
    archive_path = Path(path).expanduser().resolve()
    if not archive_path.is_file():
        raise FileNotFoundError(f"Archive not found: {archive_path}")

    with zipfile.ZipFile(archive_path, "r") as source:
        names = source.namelist()
        if len(names) != len(set(names)):
            raise ValueError(f"Archive contains duplicate paths: {archive_path}")
        entries = {name: source.read(name) for name in names if not name.endswith("/")}

    with tempfile.NamedTemporaryFile(
        dir=archive_path.parent, delete=False, suffix=".canonical.zip"
    ) as temporary:
        temporary_path = Path(temporary.name)

    try:
        with zipfile.ZipFile(temporary_path, "w", compression=zipfile.ZIP_STORED) as target:
            for name in sorted(entries):
                info = zipfile.ZipInfo(filename=name, date_time=_FIXED_ZIP_TIME)
                info.compress_type = zipfile.ZIP_STORED
                info.create_system = 3
                info.external_attr = _FILE_MODE
                info.flag_bits |= 0x800
                target.writestr(info, entries[name])
        os.replace(temporary_path, archive_path)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()

    return sha256_file(archive_path)
