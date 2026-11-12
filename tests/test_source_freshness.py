import os
import tempfile
import unittest
from pathlib import Path

from source_freshness import inspect_freshness


class SourceFreshnessTests(unittest.TestCase):
    def test_recent_database_write_is_fresh(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            database = root / "message.db"
            database.write_bytes(b"db")
            os.utime(database, (9_950, 9_950))

            result = inspect_freshness(root, 1, now=10_000)

            self.assertTrue(result["fresh"])
            self.assertEqual(result["newest_file"], "message.db")

    def test_old_database_write_is_stale(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            database = root / "message.db-wal"
            database.write_bytes(b"wal")
            os.utime(database, (9_000, 9_000))

            result = inspect_freshness(root, 1, now=10_000)

            self.assertFalse(result["fresh"])

    def test_reader_created_shm_does_not_fake_freshness(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            database = root / "message.db"
            database.write_bytes(b"db")
            shm = root / "message.db-shm"
            shm.write_bytes(b"reader state")
            os.utime(database, (9_000, 9_000))
            os.utime(shm, (9_999, 9_999))

            result = inspect_freshness(root, 1, now=10_000)

            self.assertFalse(result["fresh"])
            self.assertEqual(result["newest_file"], "message.db")


if __name__ == "__main__":
    unittest.main()
