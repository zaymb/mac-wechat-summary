import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
NOTIFIER = ROOT / "send_digest_notification.sh"


class FailClosedChatIdTests(unittest.TestCase):
    """F4: no hardcoded chat ID; the helper refuses to deliver without one."""

    def _run(self, env_extra, text="digest", slice_id="slice-a"):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            token = root / "token"
            token.write_text("test-token", encoding="utf-8")
            ledger = root / "ledger.jsonl"
            curl_log = root / "curl-args"
            fake_curl = root / "curl"
            fake_curl.write_text(
                "#!/bin/sh\n"
                'printf \'%s\\n\' "$@" > "$FAKE_CURL_ARGS"\n'
                'printf \'%s\\n\' \'{"ok":true,"result":{"message_id":1}}\'\n',
                encoding="utf-8",
            )
            fake_curl.chmod(0o700)
            env = {
                **os.environ,
                "WECHAT_DIGEST_TOKEN_FILE": str(token),
                "WECHAT_DIGEST_NOTIFICATION_LEDGER": str(ledger),
                "WECHAT_DIGEST_CURL_BIN": str(fake_curl),
                "FAKE_CURL_ARGS": str(curl_log),
                # Ensure no ambient value leaks into the test.
                "WECHAT_DIGEST_CHAT_ID": "",
            }
            env.update(env_extra)
            result = subprocess.run(
                [str(NOTIFIER), "--slice-id", slice_id],
                input=text,
                text=True,
                capture_output=True,
                check=False,
                env=env,
            )
            curl_args = (curl_log.read_text(encoding="utf-8")
                         if curl_log.exists() else None)
            return result, curl_args

    def test_missing_chat_id_fails_closed_without_contacting_telegram(self):
        result, curl_args = self._run({})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("digest chat ID is not configured", result.stderr)
        self.assertIsNone(curl_args)

    def test_env_chat_id_is_used(self):
        result, curl_args = self._run({"WECHAT_DIGEST_CHAT_ID": "-100200300"})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIsNotNone(curl_args)
        self.assertIn("chat_id=-100200300", curl_args)

    def test_private_runtime_file_is_used(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            chat_id_file = Path(temp_dir) / "chat-id"
            chat_id_file.write_text("-100400500\n", encoding="utf-8")
            result, curl_args = self._run({
                "WECHAT_DIGEST_CHAT_ID_FILE": str(chat_id_file),
            })
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIsNotNone(curl_args)
        self.assertIn("chat_id=-100400500", curl_args)

    def test_no_hardcoded_ids_in_tracked_shell(self):
        for name in ("send_digest_notification.sh", "wechat_digest.sh",
                     "wechat_digest_lib.sh"):
            source = (ROOT / name).read_text(encoding="utf-8")
            for banned in ("8690704851", "5407838851"):
                self.assertNotIn(banned, source)


if __name__ == "__main__":
    unittest.main()
