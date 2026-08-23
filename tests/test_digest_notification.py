import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from digest_notification import (
    FILE_SECTION_HEADER,
    TELEGRAM_TEXT_LIMIT,
    _telegram_units,
    append_file_section,
)


ROOT = Path(__file__).resolve().parents[1]


class DigestNotificationTests(unittest.TestCase):
    def test_appends_deduplicated_clean_file_titles(self):
        summary = {
            "files": [
                {"title": "one.pdf"},
                {"title": "one.pdf"},
                {"title": "two\nlines.txt"},
            ],
        }
        text = append_file_section("digest", summary)
        self.assertEqual(
            text,
            "digest\n\n📎 文件分享\n- one.pdf\n- two lines.txt",
        )

    def test_no_files_leaves_notification_unchanged(self):
        self.assertEqual(
            append_file_section("digest", {"files": []}),
            "digest",
        )

    def test_preserves_file_section_inside_telegram_limit(self):
        summary = {"files": [{"title": "important.pdf"}]}
        text = append_file_section("x" * 5000, summary)
        self.assertLessEqual(_telegram_units(text), TELEGRAM_TEXT_LIMIT)
        self.assertIn(FILE_SECTION_HEADER, text)
        self.assertTrue(text.endswith("- important.pdf"))

    def test_helper_sends_formatted_text_and_records_auditable_receipt(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            token = root / "token"
            token.write_text("test-token", encoding="utf-8")
            summary = root / "summary.json"
            summary.write_text(
                json.dumps({"files": [{"title": "one.pdf"}]}),
                encoding="utf-8",
            )
            ledger = root / "ledger.jsonl"
            args_log = root / "curl-args"
            fake_curl = root / "curl"
            fake_curl.write_text(
                "#!/bin/sh\n"
                "printf '%s\\n' \"$@\" > \"$FAKE_CURL_ARGS\"\n"
                "printf '%s\\n' '{\"ok\":true,\"result\":{\"message_id\":99}}'\n",
                encoding="utf-8",
            )
            fake_curl.chmod(0o700)

            env = {
                **os.environ,
                "WECHAT_DIGEST_TOKEN_FILE": str(token),
                "WECHAT_DIGEST_NOTIFICATION_LEDGER": str(ledger),
                "WECHAT_DIGEST_CURL_BIN": str(fake_curl),
                "WECHAT_DIGEST_FILE_SUMMARY": str(summary),
                "WECHAT_DIGEST_FILE_SLICE_ID": "slice-a",
                "FAKE_CURL_ARGS": str(args_log),
            }
            result = subprocess.run(
                [str(ROOT / "send_digest_notification.sh"),
                 "--slice-id", "slice-a"],
                input="digest",
                text=True,
                capture_output=True,
                check=False,
                env=env,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            sent_args = args_log.read_text(encoding="utf-8")
            self.assertIn("text=digest\n\n📎 文件分享\n- one.pdf", sent_args)
            receipt = json.loads(ledger.read_text(encoding="utf-8"))
            self.assertEqual(receipt["schema_version"], 2)
            self.assertEqual(receipt["file_count"], 1)
            self.assertEqual(len(receipt["text_sha256"]), 64)

    def test_helper_does_not_attach_today_files_to_another_slice(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            token = root / "token"
            token.write_text("test-token", encoding="utf-8")
            summary = root / "summary.json"
            summary.write_text(
                json.dumps({"files": [{"title": "one.pdf"}]}),
                encoding="utf-8",
            )
            ledger = root / "ledger.jsonl"
            args_log = root / "curl-args"
            fake_curl = root / "curl"
            fake_curl.write_text(
                "#!/bin/sh\n"
                "printf '%s\\n' \"$@\" > \"$FAKE_CURL_ARGS\"\n"
                "printf '%s\\n' '{\"ok\":true,\"result\":{\"message_id\":99}}'\n",
                encoding="utf-8",
            )
            fake_curl.chmod(0o700)

            env = {
                **os.environ,
                "WECHAT_DIGEST_TOKEN_FILE": str(token),
                "WECHAT_DIGEST_NOTIFICATION_LEDGER": str(ledger),
                "WECHAT_DIGEST_CURL_BIN": str(fake_curl),
                "WECHAT_DIGEST_FILE_SUMMARY": str(summary),
                "WECHAT_DIGEST_FILE_SLICE_ID": "current-slice",
                "FAKE_CURL_ARGS": str(args_log),
            }
            result = subprocess.run(
                [str(ROOT / "send_digest_notification.sh"),
                 "--slice-id", "recovered-slice"],
                input="digest",
                text=True,
                capture_output=True,
                check=False,
                env=env,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn(FILE_SECTION_HEADER,
                             args_log.read_text(encoding="utf-8"))
            receipt = json.loads(ledger.read_text(encoding="utf-8"))
            self.assertEqual(receipt["file_count"], 0)


if __name__ == "__main__":
    unittest.main()
