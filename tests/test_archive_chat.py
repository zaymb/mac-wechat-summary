import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from unittest import mock

import archive_chat
from archive_chat import _read_recovery_descriptor, _write_json_atomic


class ArchiveRecoveryDescriptorTests(unittest.TestCase):
    def test_round_trip_preserves_exact_bounds(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = os.path.join(temp_dir, "descriptor.json")
            expected = {
                "schema_version": 1,
                "run_id": "round-1",
                "chat": "可爱小克",
                "from_ts": 100.0,
                "through_ts": 200.0,
                "status": "pending",
            }
            _write_json_atomic(path, expected)

            self.assertEqual(_read_recovery_descriptor(path), expected)
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)

    def test_rejects_reversed_bounds(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = os.path.join(temp_dir, "descriptor.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump({"from_ts": 200, "through_ts": 100}, handle)

            with self.assertRaisesRegex(ValueError, "through_ts"):
                _read_recovery_descriptor(path)

    def test_large_window_is_fully_written_before_cursor_advances(self):
        total = 10_001

        class FakeDB:
            def __init__(self, *_args, **_kwargs):
                pass

            def resolve_username(self, _chat):
                return "room@chatroom"

            def iter_messages_ascending(
                self, _username, since_ts, until_ts, batch_size
            ):
                self.assert_bounds = (since_ts, until_ts, batch_size)
                for start in range(0, total, batch_size):
                    yield [
                        {
                            "sender": "sender",
                            "text": f"message-{index}",
                            "timestamp": 1000.0 + index,
                            "type": 1,
                        }
                        for index in range(start, min(start + batch_size, total))
                    ]

        with tempfile.TemporaryDirectory() as temp_dir:
            cursor = os.path.join(temp_dir, "archive-cursor.json")
            digest_cursor = os.path.join(temp_dir, "digest-cursor.json")
            archive_dir = os.path.join(temp_dir, "archive")
            descriptor = os.path.join(temp_dir, "descriptor.json")
            argv = [
                "archive_chat.py", "--chat", "room", "--limit", "1000",
                "--descriptor-file", descriptor, "--run-id", "large-window",
            ]
            with (
                mock.patch.object(archive_chat, "CURSOR_FILE", cursor),
                mock.patch.object(archive_chat, "DIGEST_CURSOR_FILE", digest_cursor),
                mock.patch.object(archive_chat, "ARCHIVE_DIR", archive_dir),
                mock.patch("core.config.load_config", return_value={"db_dir": temp_dir}),
                mock.patch("core.key_extractor.get_cached_keys", return_value={"db": {}}),
                mock.patch("core.wechat_db.WeChatDB", FakeDB),
                mock.patch.object(sys, "argv", argv),
                redirect_stdout(StringIO()),
                redirect_stderr(StringIO()),
            ):
                self.assertEqual(archive_chat.main(), 0)

            with open(cursor, encoding="utf-8") as handle:
                cursor_value = json.load(handle)["room"]["last_ts"]
            with open(descriptor, encoding="utf-8") as handle:
                descriptor_value = json.load(handle)
            # slice_path is relative to archive_chat.BASE, so resolve it from
            # the configured archive directory for this isolated test.
            slice_path = os.path.join(
                archive_dir,
                "room",
                os.path.basename(descriptor_value["slice_path"]),
            )
            with open(slice_path, encoding="utf-8") as handle:
                body = handle.read()

            self.assertEqual(descriptor_value["messages"], total)
            self.assertEqual(cursor_value, 1000.0 + total - 1)
            self.assertIn("message-0", body)
            self.assertIn(f"message-{total - 1}", body)
            self.assertLess(body.index("message-0"), body.index("message-10000"))


if __name__ == "__main__":
    unittest.main()
