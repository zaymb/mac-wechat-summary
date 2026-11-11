import os
import sqlite3
import tempfile
import unittest

from core.wechat_db import WeChatDB


def _make_db(db, n_rows, start_ts=1000.0):
    for i in range(n_rows):
        db.execute(
            "INSERT INTO chat VALUES (?, ?, ?, ?, ?, ?)",
            (int((start_ts + i) * 1000), 1, start_ts + i,
             f"message-{i}", 0, 3),
        )
    db.commit()


def _fake_db(db_path):
    inst = object.__new__(WeChatDB)
    inst._contacts = {}
    inst._nick_to_remark = {}
    inst._load_contacts = lambda: None
    inst._find_msg_table = lambda username=None: ([db_path], "chat")
    return inst


class IterMessagesAscendingTests(unittest.TestCase):
    def _seed(self, temp_dir):
        db_path = os.path.join(temp_dir, "messages.sqlite")
        conn = sqlite3.connect(db_path)
        conn.execute(
            """
            CREATE TABLE chat (
                sort_seq INTEGER,
                local_type INTEGER,
                create_time REAL,
                message_content BLOB,
                WCDB_CT_message_content INTEGER,
                status INTEGER
            )
            """
        )
        conn.execute("CREATE INDEX chat_SORTSEQ ON chat(sort_seq)")
        return conn, db_path

    def test_default_get_messages_still_returns_newest_limit(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            conn, db_path = self._seed(temp_dir)
            _make_db(conn, 12)
            conn.close()

            db = _fake_db(db_path)
            messages = db.get_messages("room@chatroom", limit=5)

            self.assertEqual(len(messages), 5)
            # Newest five survive; the oldest are dropped (documented behavior).
            self.assertEqual(
                [m["text"] for m in messages],
                [f"message-{i}" for i in range(7, 12)],
            )

    def test_iter_yields_10001_rows_in_order_with_no_gap(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            conn, db_path = self._seed(temp_dir)
            total = 10_001
            _make_db(conn, total)
            conn.close()

            db = _fake_db(db_path)
            collected = []
            batches = 0
            for chunk in db.iter_messages_ascending(
                "room@chatroom", since_ts=999.0, batch_size=1000
            ):
                batches += 1
                collected.extend(chunk)

            self.assertGreater(batches, 1)
            self.assertEqual(len(collected), total)
            self.assertEqual([m["timestamp"] for m in collected],
                             [1000.0 + i for i in range(total)])
            self.assertEqual([m["text"] for m in collected],
                             [f"message-{i}" for i in range(total)])

    def test_iter_honors_inclusive_upper_bound(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            conn, db_path = self._seed(temp_dir)
            _make_db(conn, 2501)  # forces multiple batches
            conn.close()

            db = _fake_db(db_path)
            collected = []
            for chunk in db.iter_messages_ascending(
                "room@chatroom",
                since_ts=1100.0,
                until_ts=1200.0,
                batch_size=100,
            ):
                collected.extend(chunk)

            self.assertEqual(len(collected), 100)
            self.assertTrue(all(1100.0 < m["timestamp"] <= 1200.0
                                for m in collected))

    def test_iter_never_loses_identical_boundary_timestamps(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            conn, db_path = self._seed(temp_dir)
            # 99 distinct timestamps then a block of 5 identical ones that
            # straddles the first batch boundary.
            for i in range(99):
                conn.execute(
                    "INSERT INTO chat VALUES (?, ?, ?, ?, ?, ?)",
                    (1000000 + i, 1, 1000.0 + i, f"m{i}", 0, 3),
                )
            for j in range(5):
                conn.execute(
                    "INSERT INTO chat VALUES (?, ?, ?, ?, ?, ?)",
                    (1099000 + j, 1, 1099.0, f"dup{j}", 0, 3),
                )
            conn.commit()
            conn.close()

            db = _fake_db(db_path)
            batches = [
                chunk
                for chunk in db.iter_messages_ascending(
                    "room@chatroom", since_ts=0.0, batch_size=100
                )
            ]
            self.assertGreaterEqual(len(batches), 2)
            duplicates = [
                message["text"]
                for batch in batches
                for message in batch
                if message["text"].startswith("dup")
            ]
            self.assertEqual(set(duplicates), {f"dup{i}" for i in range(5)})
            self.assertEqual(len(duplicates), 5)

    def test_iter_handles_more_than_two_batches_at_one_timestamp(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            conn, db_path = self._seed(temp_dir)
            total = 250
            for i in range(total):
                conn.execute(
                    "INSERT INTO chat VALUES (?, ?, ?, ?, ?, ?)",
                    (1234000 + i, 1, 1234.0, f"same-{i}", 0, 3),
                )
            conn.commit()
            conn.close()

            db = _fake_db(db_path)
            collected = [
                message
                for chunk in db.iter_messages_ascending(
                    "room@chatroom", since_ts=1000.0, batch_size=100
                )
                for message in chunk
            ]

            self.assertEqual(len(collected), total)
            self.assertEqual(
                {message["text"] for message in collected},
                {f"same-{i}" for i in range(total)},
            )

    def test_iter_falls_back_to_snapshot_when_live_shard_is_malformed(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            conn, db_path = self._seed(temp_dir)
            _make_db(conn, 12)
            conn.close()

            class MalformedConnection:
                def execute(self, *_args, **_kwargs):
                    raise sqlite3.DatabaseError("database disk image is malformed")

                def close(self):
                    pass

            db = _fake_db(db_path)
            db._open_encrypted_conn = lambda _path: MalformedConnection()
            db._open_snapshot_conn = lambda path: sqlite3.connect(path)

            messages = [
                message
                for chunk in db.iter_messages_ascending(
                    "room@chatroom", since_ts=999.0, batch_size=5
                )
                for message in chunk
            ]

            self.assertEqual(
                [message["text"] for message in messages],
                [f"message-{i}" for i in range(12)],
            )


if __name__ == "__main__":
    unittest.main()
