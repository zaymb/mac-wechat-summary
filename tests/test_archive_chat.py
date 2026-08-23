import json
import os
import tempfile
import unittest

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


if __name__ == "__main__":
    unittest.main()
