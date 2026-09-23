from __future__ import annotations

import tempfile
import unittest
import zipfile
from pathlib import Path

from evalfoundry.archive import canonicalize_zip


class CanonicalArchiveTests(unittest.TestCase):
    def test_order_and_timestamps_do_not_change_release_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            first = root / "first.zip"
            second = root / "second.zip"

            with zipfile.ZipFile(first, "w", zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("pack/z.txt", b"last")
                archive.writestr("pack/a.txt", b"first")

            with zipfile.ZipFile(second, "w", zipfile.ZIP_DEFLATED) as archive:
                old = zipfile.ZipInfo("pack/a.txt", date_time=(2001, 2, 3, 4, 5, 6))
                new = zipfile.ZipInfo("pack/z.txt", date_time=(2026, 7, 19, 1, 2, 4))
                archive.writestr(old, b"first")
                archive.writestr(new, b"last")

            first_hash = canonicalize_zip(first)
            second_hash = canonicalize_zip(second)

            self.assertEqual(first_hash, second_hash)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            with zipfile.ZipFile(first) as archive:
                self.assertEqual(["pack/a.txt", "pack/z.txt"], archive.namelist())
                for info in archive.infolist():
                    self.assertEqual((1980, 1, 1, 0, 0, 0), info.date_time)
                    self.assertEqual(zipfile.ZIP_STORED, info.compress_type)


if __name__ == "__main__":
    unittest.main()
