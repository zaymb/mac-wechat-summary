import hashlib
import os
import sqlite3
import tempfile
import unittest

from core.wechat_db import WeChatDB, _clean_msg_text


class CleanMessageTests(unittest.TestCase):
    def test_link_keeps_real_url_and_decodes_entities(self):
        xml = """
        <msg><appmsg>
          <title><![CDATA[Useful article]]></title>
          <type>5</type>
          <url><![CDATA[https://example.com/read?a=1&amp;b=2]]></url>
        </appmsg></msg>
        """
        self.assertEqual(
            _clean_msg_text(xml),
            "[链接] Useful article — https://example.com/read?a=1&b=2",
        )

    def test_non_http_url_is_not_exposed(self):
        xml = """
        <msg><appmsg>
          <title>Mini program</title>
          <type>33</type>
          <url>weixin://dl/business/?ticket=private</url>
        </appmsg></msg>
        """
        self.assertEqual(_clean_msg_text(xml), "[链接] Mini program")

    def test_file_never_exposes_cdn_url(self):
        xml = """
        <msg><appmsg>
          <title><![CDATA[notes.pdf]]></title>
          <type> 6 </type>
          <url>https://cdn.example/private-token</url>
          <appattach><totallen>3</totallen></appattach>
        </appmsg></msg>
        """
        self.assertEqual(_clean_msg_text(xml), "[文件] notes.pdf")


class FileMessageTests(unittest.TestCase):
    def test_incremental_scan_returns_file_and_non_file_watermark(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = os.path.join(temp_dir, "messages.sqlite")
            conn = sqlite3.connect(db_path)
            conn.execute(
                """
                CREATE TABLE chat (
                    local_type INTEGER,
                    create_time REAL,
                    message_content BLOB,
                    WCDB_CT_message_content INTEGER,
                    status INTEGER
                )
                """
            )
            payload = """
            wxid_sender:
            <msg><appmsg>
              <title><![CDATA[notes.pdf]]></title>
              <type>6</type>
              <appattach>
                <totallen>3</totallen>
                <md5>900150983cd24fb0d6963f7d28e17f72</md5>
                <fileext>pdf</fileext>
              </appattach>
            </appmsg></msg>
            """.strip().replace("wxid_sender:\n            ", "wxid_sender:\n")
            conn.execute(
                "INSERT INTO chat VALUES (?, ?, ?, ?, ?)",
                (49, 100.0, payload, 0, 3),
            )
            conn.execute(
                "INSERT INTO chat VALUES (?, ?, ?, ?, ?)",
                (1, 101.0, "plain text", 0, 3),
            )
            conn.commit()
            conn.close()

            db = object.__new__(WeChatDB)
            db._contacts = {"wxid_sender": "Sender"}
            db._nick_to_remark = {}
            db._load_contacts = lambda: None
            db._find_msg_table = lambda _username: ([db_path], "chat")
            db._find_cached_file = lambda metadata, _ts: (
                "/cache/file" if metadata["md5"] else None
            )

            files, watermark = db.get_file_messages(
                "room@chatroom",
                since_ts=0,
                include_scan_watermark=True,
            )

            self.assertEqual(watermark, 101.0)
            self.assertEqual(len(files), 1)
            self.assertEqual(files[0]["sender"], "Sender")
            self.assertEqual(files[0]["title"], "notes.pdf")
            self.assertEqual(files[0]["size"], 3)
            self.assertEqual(files[0]["cache_path"], "/cache/file")

    def test_cache_lookup_uses_content_md5_not_filename(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            account_dir = os.path.join(temp_dir, "account")
            db_dir = os.path.join(account_dir, "db_storage")
            cache_dir = os.path.join(account_dir, "msg", "file", "2026-07")
            os.makedirs(db_dir)
            os.makedirs(cache_dir)
            cache_path = os.path.join(cache_dir, "opaque-cache-name.pdf")
            with open(cache_path, "wb") as handle:
                handle.write(b"abc")

            db = object.__new__(WeChatDB)
            db.db_dir = db_dir
            db._file_cache_by_size = None
            db._file_md5_cache = {}
            metadata = {
                "size": 3,
                "md5": hashlib.md5(b"abc").hexdigest(),
                "fileext": "pdf",
            }
            self.assertEqual(
                db.find_cached_file(metadata, os.path.getmtime(cache_path)),
                cache_path,
            )


class MessageBoundsTests(unittest.TestCase):
    def test_get_messages_honors_inclusive_recovery_upper_bound(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = os.path.join(temp_dir, "messages.sqlite")
            conn = sqlite3.connect(db_path)
            conn.execute(
                """
                CREATE TABLE chat (
                    local_type INTEGER,
                    create_time REAL,
                    message_content BLOB,
                    WCDB_CT_message_content INTEGER,
                    status INTEGER
                )
                """
            )
            for ts in (100.0, 101.0, 102.0):
                conn.execute(
                    "INSERT INTO chat VALUES (?, ?, ?, ?, ?)",
                    (1, ts, f"message-{ts}", 0, 3),
                )
            conn.commit()
            conn.close()

            db = object.__new__(WeChatDB)
            db._contacts = {}
            db._nick_to_remark = {}
            db._load_contacts = lambda: None
            db._find_msg_table = lambda _username: ([db_path], "chat")

            messages = db.get_messages(
                "room@chatroom", since_ts=100.0, until_ts=101.0
            )

            self.assertEqual([m["timestamp"] for m in messages], [101.0])


if __name__ == "__main__":
    unittest.main()
