import hashlib
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from core.file_cache_index import PersistentFileCacheIndex


class PersistentFileCacheIndexTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.files = self.root / "msg" / "file"
        self.index = self.root / "index"
        self.files.mkdir(parents=True)
        self.payload = self.files / "nested" / "report.pdf"
        self.payload.parent.mkdir()
        self.payload.write_bytes(b"first-payload")

    def _metadata(self, content=None):
        payload = self.payload.read_bytes() if content is None else content
        return {
            "size": len(payload),
            "md5": hashlib.md5(payload).hexdigest(),
            "fileext": "pdf",
        }

    def _new_index(self):
        return PersistentFileCacheIndex(str(self.files), str(self.index))

    @property
    def resolved_payload(self):
        return os.path.realpath(self.payload)

    def test_hash_is_reused_across_fresh_instances(self):
        original = PersistentFileCacheIndex._hash_stable
        with mock.patch.object(
            PersistentFileCacheIndex,
            "_hash_stable",
            side_effect=original,
        ) as hasher:
            first = self._new_index().find(
                self._metadata(), self.payload.stat().st_mtime
            )
            second = self._new_index().find(
                self._metadata(), self.payload.stat().st_mtime
            )

        self.assertEqual(first, self.resolved_payload)
        self.assertEqual(second, self.resolved_payload)
        self.assertEqual(hasher.call_count, 1)

    def test_changed_same_size_file_is_rehashed_and_old_digest_fails_closed(self):
        old_metadata = self._metadata()
        first = self._new_index()
        self.assertEqual(
            first.find(old_metadata, self.payload.stat().st_mtime),
            self.resolved_payload,
        )
        replacement = b"other-payload"
        self.assertEqual(len(replacement), self.payload.stat().st_size)
        time.sleep(0.002)
        self.payload.write_bytes(replacement)

        second = self._new_index()
        self.assertIsNone(second.find(old_metadata, self.payload.stat().st_mtime))
        self.assertEqual(
            second.find(self._metadata(), self.payload.stat().st_mtime),
            self.resolved_payload,
        )

    def test_long_lived_instance_does_not_return_stale_digest_after_mutation(self):
        old_metadata = self._metadata()
        index = self._new_index()
        self.assertEqual(
            index.find(old_metadata, self.payload.stat().st_mtime),
            self.resolved_payload,
        )
        replacement = b"other-payload"
        time.sleep(0.002)
        self.payload.write_bytes(replacement)

        self.assertIsNone(index.find(old_metadata, self.payload.stat().st_mtime))

    def test_deleted_file_is_removed_on_next_process_refresh(self):
        metadata = self._metadata()
        first = self._new_index()
        self.assertEqual(first.find(metadata, self.payload.stat().st_mtime), self.resolved_payload)
        self.payload.unlink()

        second = self._new_index()
        self.assertIsNone(second.find(metadata, time.time()))

    def test_no_md5_fallback_requires_close_timestamp_and_extension(self):
        timestamp = self.payload.stat().st_mtime
        metadata = {"size": self.payload.stat().st_size, "md5": "", "fileext": "pdf"}
        index = self._new_index()

        self.assertEqual(index.find(metadata, timestamp), self.resolved_payload)
        self.assertIsNone(index.find(metadata, timestamp + 61))
        self.assertIsNone(index.find({**metadata, "fileext": "docx"}, timestamp))

    def test_index_does_not_write_outside_its_cache_directory(self):
        sentinel = self.root / "cursor.json"
        sentinel.write_text('{"cursor":7}\n')
        before = sentinel.read_bytes()

        self._new_index().find(self._metadata(), self.payload.stat().st_mtime)

        self.assertEqual(sentinel.read_bytes(), before)
        self.assertTrue(all(str(path).startswith(str(self.index)) for path in self.index.iterdir()))

    def test_symlink_candidate_outside_root_is_rejected(self):
        outside = self.root / "private.pdf"
        outside.write_bytes(b"outside-data")
        link = self.files / "outside.pdf"
        link.symlink_to(outside)
        metadata = {
            "size": outside.stat().st_size,
            "md5": hashlib.md5(outside.read_bytes()).hexdigest(),
            "fileext": "pdf",
        }

        result = self._new_index().find(metadata, outside.stat().st_mtime)

        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
