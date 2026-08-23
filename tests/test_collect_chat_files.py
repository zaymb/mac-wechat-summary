import hashlib
import json
import os
import tempfile
import unittest

from collect_chat_files import (
    _append_manifest,
    _copy_verified,
    _destination_path,
    _event_id,
    _manifest_ids,
    _safe_name,
    _write_daily_summary,
)


class CollectorHelpersTests(unittest.TestCase):
    def test_safe_name_strips_paths_and_controls(self):
        self.assertEqual(_safe_name("../folder/notes\x00.pdf"), "notes.pdf")
        self.assertEqual(_safe_name(".."), "unnamed")

    def test_copy_is_verified_and_same_content_is_reused(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source = os.path.join(temp_dir, "source.bin")
            destination_dir = os.path.join(temp_dir, "dest")
            os.makedirs(destination_dir)
            with open(source, "wb") as handle:
                handle.write(b"payload")
            record = {
                "title": "report.pdf",
                "timestamp": 100.0,
                "size": 7,
                "md5": hashlib.md5(b"payload").hexdigest(),
            }

            destination, identical = _destination_path(
                destination_dir, record
            )
            self.assertFalse(identical)
            _copy_verified(source, destination, record)
            with open(destination, "rb") as handle:
                self.assertEqual(handle.read(), b"payload")

            same_destination, identical = _destination_path(
                destination_dir, record
            )
            self.assertTrue(identical)
            self.assertEqual(same_destination, destination)

    def test_name_collision_gets_non_destructive_suffix(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            existing = os.path.join(temp_dir, "report.pdf")
            with open(existing, "wb") as handle:
                handle.write(b"old")
            record = {
                "title": "report.pdf",
                "timestamp": 100.0,
                "size": 3,
                "md5": hashlib.md5(b"new").hexdigest(),
            }
            destination, identical = _destination_path(temp_dir, record)
            self.assertFalse(identical)
            self.assertNotEqual(destination, existing)
            self.assertTrue(destination.endswith(".pdf"))

    def test_manifest_event_ids_are_idempotent(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = os.path.join(temp_dir, "2026-07-27.jsonl")
            record = {
                "timestamp": 100.0,
                "md5": hashlib.md5(b"x").hexdigest(),
                "title": "x.txt",
            }
            event_id = _event_id("chat", record)
            _append_manifest(path, {"event_id": event_id, "title": "x.txt"})
            self.assertEqual(_manifest_ids(path), {event_id})
            with open(path, encoding="utf-8") as handle:
                line = handle.readline()
            self.assertEqual(json.loads(line)["event_id"], event_id)

    def test_daily_summary_deduplicates_same_content(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = os.path.join(temp_dir, "2026-07-27.jsonl")
            shared = {
                "md5": hashlib.md5(b"x").hexdigest(),
                "title": "x.txt",
                "stored_name": "x.txt",
                "size": 1,
            }
            _append_manifest(path, {"event_id": "one", **shared})
            _append_manifest(path, {"event_id": "two", **shared})
            summary_path = _write_daily_summary(path)
            with open(summary_path, encoding="utf-8") as handle:
                summary = json.load(handle)
            self.assertEqual(summary["unique_file_count"], 1)
            self.assertEqual(summary["files"][0]["title"], "x.txt")


if __name__ == "__main__":
    unittest.main()
