import json
import shlex
import tempfile
import unittest
from pathlib import Path

from digest_timeout_alert import process_event


class DigestTimeoutAlertTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.ledger = self.root / "events.jsonl"
        self.state = self.root / "state.json"
        self.notify_log = self.root / "notifier.jsonl"

    def _notifier(self, *, fail_first=False):
        script = self.root / "notifier"
        notify_log = shlex.quote(str(self.notify_log))
        script.write_text(
            "#!/bin/sh\n"
            "set -eu\n"
            "count=0\n"
            f"[ ! -f {notify_log} ] || count=$(wc -l < {notify_log})\n"
            "python3 -c 'import json,os,sys; print(json.dumps({\"args\":sys.argv[1:],\"chat\":os.environ.get(\"WECHAT_DIGEST_CHAT_ID\"),\"text\":sys.stdin.read()}))' \"$@\""
            f" >> {notify_log}\n"
            + ("[ \"$count\" -gt 0 ] || exit 7\n" if fail_first else "")
            + "exit 0\n",
            encoding="utf-8",
        )
        script.chmod(0o700)
        return script

    def _event(self, run_id, status="timeout", **kwargs):
        return process_event(
            ledger_path=self.ledger,
            state_path=self.state,
            run_id=run_id,
            stage=kwargs.pop("stage", "archive"),
            status=status,
            occurred_at=kwargs.pop("occurred_at", "2026-08-22T19:05:07+10:00"),
            timeout_seconds=60 if status == "timeout" else None,
            notifier=kwargs.pop("notifier", None),
            chat_id=kwargs.pop("chat_id", "test-family-channel"),
            **kwargs,
        )

    def _rows(self):
        return [
            json.loads(line)
            for line in self.ledger.read_text(encoding="utf-8").splitlines()
        ]

    def test_consecutive_timeouts_are_durable_but_notify_once_per_streak(self):
        notifier = self._notifier()
        first = self._event("round-1904", notifier=notifier)
        second = self._event("round-2104", notifier=notifier)

        self.assertEqual(first["notification"], "sent")
        self.assertEqual(second["notification"], "suppressed")
        pipeline = [r for r in self._rows() if r["record_type"] == "pipeline_status"]
        self.assertEqual([r["timeout_streak"] for r in pipeline], [1, 2])
        self.assertEqual(
            pipeline[1]["notification_suppression_reason"],
            "active_timeout_streak",
        )
        notifications = self.notify_log.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(notifications), 1)

    def test_accepts_wrapper_run_id_with_numeric_timezone_offset(self):
        notifier = self._notifier()

        result = self._event("20260822T230415+1000-12345", notifier=notifier)

        self.assertTrue(result["recorded"])
        self.assertEqual(result["notification"], "sent")

    def test_success_resets_streak_so_a_later_timeout_alerts_again(self):
        notifier = self._notifier()
        self._event("round-1904", notifier=notifier)
        recovered = self._event("round-2104", status="success", notifier=notifier)
        later = self._event("round-2304", notifier=notifier)

        self.assertEqual(recovered["notification"], "not_applicable")
        self.assertEqual(later["timeout_streak"], 1)
        self.assertEqual(later["notification"], "sent")
        self.assertEqual(
            len(self.notify_log.read_text(encoding="utf-8").splitlines()), 2
        )

    def test_duplicate_timeout_suppresses_event_and_delivery_after_success(self):
        notifier = self._notifier()
        first = self._event("round-1904", notifier=notifier)
        duplicate = self._event("round-1904", notifier=notifier)

        self.assertTrue(first["recorded"])
        self.assertEqual(duplicate["notification"], "duplicate_suppressed")
        pipeline = [r for r in self._rows() if r["record_type"] == "pipeline_status"]
        delivery = [r for r in self._rows() if r["record_type"] == "notification_delivery"]
        self.assertEqual(len(pipeline), 1)
        self.assertEqual(len(delivery), 1)
        self.assertEqual(
            len(self.notify_log.read_text(encoding="utf-8").splitlines()), 1
        )

    def test_failed_delivery_is_receipted_and_duplicate_can_retry(self):
        notifier = self._notifier(fail_first=True)
        failed = self._event("round-1904", notifier=notifier)
        retried = self._event("round-1904", notifier=notifier)

        self.assertEqual(failed["notification"], "failed")
        self.assertFalse(retried["recorded"])
        self.assertTrue(retried["retry"])
        self.assertEqual(retried["notification"], "sent")
        rows = self._rows()
        pipeline = [r for r in rows if r["record_type"] == "pipeline_status"]
        delivery = [r for r in rows if r["record_type"] == "notification_delivery"]
        self.assertEqual(len(pipeline), 1)
        self.assertEqual([r["status"] for r in delivery], ["failed", "sent"])

    def test_missing_state_rebuilds_streak_from_ledger_without_realerting(self):
        notifier = self._notifier()
        self._event("round-1904", notifier=notifier)
        self.state.unlink()

        second = self._event("round-2104", notifier=notifier)

        self.assertEqual(second["notification"], "suppressed")
        self.assertEqual(second["timeout_streak"], 2)
        self.assertEqual(
            len(self.notify_log.read_text(encoding="utf-8").splitlines()), 1
        )

    def test_replaying_older_failed_event_after_later_delivery_is_suppressed(self):
        notifier = self._notifier(fail_first=True)
        first = self._event("round-1904", notifier=notifier)
        second = self._event("round-2104", notifier=notifier)
        replay = self._event("round-1904", notifier=notifier)

        self.assertEqual(first["notification"], "failed")
        self.assertEqual(second["notification"], "sent")
        self.assertEqual(replay["notification"], "duplicate_suppressed")
        self.assertEqual(
            len(self.notify_log.read_text(encoding="utf-8").splitlines()), 2
        )

    def test_empty_and_silent_are_recorded_as_healthy_not_timeout(self):
        self._event("round-empty", status="empty")
        self._event("round-silent", status="silent")

        pipeline = [r for r in self._rows() if r["record_type"] == "pipeline_status"]
        self.assertEqual([r["status"] for r in pipeline], ["empty", "silent"])
        self.assertTrue(all(r["timeout_seconds"] is None for r in pipeline))
        self.assertFalse(self.notify_log.exists())


if __name__ == "__main__":
    unittest.main()
