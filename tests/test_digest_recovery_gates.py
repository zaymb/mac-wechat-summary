import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from archive_chat import (
    _read_recovery_descriptor,
    _write_json_atomic,
    _write_text_atomic,
)


ROOT = Path(__file__).resolve().parents[1]


class DescriptorGateTests(unittest.TestCase):
    """F2: only a success/empty descriptor may settle a recovery retry."""

    def _run_gate(self, descriptor_path):
        return subprocess.run(
            [
                "bash", "-c",
                'source "$1/wechat_digest_lib.sh" && '
                'if descriptor_is_recoverable "$2"; then exit 0; else exit 1; fi',
                "gate", str(ROOT), str(descriptor_path),
            ],
            capture_output=True,
            text=True,
            check=False,
        )

    def _recovery_context(self, retry, descriptor_path):
        return subprocess.run(
            [
                "bash", "-c",
                'source "$1/wechat_digest_lib.sh" && '
                'recovery_context_json "$2" "$3"',
                "context", str(ROOT), json.dumps(retry), str(descriptor_path),
            ],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_success_and_empty_are_recoverable(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            for status in ("success", "empty"):
                path = os.path.join(temp_dir, f"{status}.json")
                with open(path, "w", encoding="utf-8") as handle:
                    json.dump({"status": status}, handle)
                self.assertEqual(self._run_gate(path).returncode, 0, status)

    def test_pending_or_invalid_or_missing_is_not_recoverable(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            pending = os.path.join(temp_dir, "pending.json")
            with open(pending, "w", encoding="utf-8") as handle:
                json.dump({"status": "pending"}, handle)
            broken = os.path.join(temp_dir, "broken.json")
            with open(broken, "w", encoding="utf-8") as handle:
                handle.write("{not json")
            missing = os.path.join(temp_dir, "missing.json")

            for bad in (pending, broken, missing, ""):
                self.assertNotEqual(self._run_gate(bad).returncode, 0, bad)

    def test_failed_recovery_produces_no_prompt_context(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            descriptor = os.path.join(temp_dir, "pending.json")
            with open(descriptor, "w", encoding="utf-8") as handle:
                json.dump({"status": "pending"}, handle)
            result = self._recovery_context({"run_id": "failed"}, descriptor)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, "")

    def test_success_descriptor_builds_exact_prompt_context(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            descriptor = os.path.join(temp_dir, "success.json")
            value = {
                "status": "success",
                "slice_id": "slice-a",
                "slice_window": "one-window",
                "slice_label": "one-label",
                "slice_path": "archive/one.md",
            }
            with open(descriptor, "w", encoding="utf-8") as handle:
                json.dump(value, handle)
            result = self._recovery_context({"run_id": "failed"}, descriptor)
            self.assertEqual(result.returncode, 0, result.stderr)
            context = json.loads(result.stdout)
            self.assertEqual(context["recovery_descriptor"], value)
            self.assertEqual(context["slice_id"], "slice-a")


class AtomicSliceWriteTests(unittest.TestCase):
    """F3: canonical slices are replaced atomically, never partially."""

    def test_write_replaces_existing_slice_atomically(self):
        # Exercise the production primitive. At replacement time the
        # canonical path must still contain the complete old file while the
        # staging path already contains the complete new file.
        with tempfile.TemporaryDirectory() as temp_dir:
            path = os.path.join(temp_dir, "slice.md")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("previous canonical slice\n")

            lines = ["---", "chat: x", "---", "", "[00:00] a: hi"]
            body = "\n".join(lines) + "\n"
            real_replace = os.replace
            observed = {}

            def checking_replace(source, destination):
                with open(destination, encoding="utf-8") as handle:
                    observed["canonical_before_replace"] = handle.read()
                with open(source, encoding="utf-8") as handle:
                    observed["staging_before_replace"] = handle.read()
                real_replace(source, destination)

            from unittest import mock
            with mock.patch("archive_chat.os.replace", checking_replace):
                _write_text_atomic(path, body)

            with open(path, encoding="utf-8") as handle:
                self.assertEqual(handle.read(), body)
            self.assertEqual(
                observed["canonical_before_replace"],
                "previous canonical slice\n",
            )
            self.assertEqual(observed["staging_before_replace"], body)

            # The same primitive underpins the descriptor writer.
            desc = os.path.join(temp_dir, "d.json")
            expected = {"from_ts": 1.0, "through_ts": 2.0,
                        "status": "success"}
            _write_json_atomic(desc, expected)
            self.assertEqual(_read_recovery_descriptor(desc), expected)


if __name__ == "__main__":
    unittest.main()
