import fcntl
import hashlib
import json
import multiprocessing
import os
import shutil
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from core.snapshot_cache import (
    DecryptedSnapshotCache,
    SnapshotCacheError,
    SourceChangedError,
)
from core.wechat_db import WeChatDB


KEY = "11" * 32
REL_PATH = "message/message_0.db"


def _copy_decrypt(source, destination, _key):
    shutil.copyfile(source, destination)
    return max(1, os.path.getsize(source) // 4096)


def _noop_wal(_source, _destination, _key):
    return 0


def _counted_slow_decrypt(counter_path):
    def decrypt(source, destination, _key):
        with open(counter_path, "a+", encoding="ascii") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            handle.write("build\n")
            handle.flush()
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        time.sleep(0.2)
        shutil.copyfile(source, destination)
        return 1

    return decrypt


def _cache_worker(db_dir, cache_dir, counter_path, queue):
    cache = DecryptedSnapshotCache(
        db_dir,
        cache_dir,
        database_decryptor=_counted_slow_decrypt(counter_path),
        wal_patcher=_noop_wal,
    )
    try:
        path = cache.get_snapshot(REL_PATH, KEY)
        with sqlite3.connect(path) as conn:
            value = conn.execute("SELECT value FROM sample").fetchone()[0]
        queue.put((value, cache.last_event["status"]))
    finally:
        cache.close()


class SnapshotCacheTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db_dir = self.root / "db_storage"
        self.cache_dir = self.root / "cache"
        self.source = self.db_dir / REL_PATH
        self.source.parent.mkdir(parents=True)
        self._write_source("first")

    def _write_source(self, value):
        if self.source.exists():
            self.source.unlink()
        with sqlite3.connect(self.source) as conn:
            conn.execute("CREATE TABLE sample(value TEXT)")
            conn.execute("INSERT INTO sample VALUES (?)", (value,))

    def _cache(self, **kwargs):
        return DecryptedSnapshotCache(
            str(self.db_dir),
            str(self.cache_dir),
            database_decryptor=kwargs.pop("database_decryptor", _copy_decrypt),
            wal_patcher=kwargs.pop("wal_patcher", _noop_wal),
            **kwargs,
        )

    @staticmethod
    def _read(path):
        with sqlite3.connect(path) as conn:
            return conn.execute("SELECT value FROM sample").fetchone()[0]

    def test_fresh_build_then_new_process_style_instance_hits_disk(self):
        counter = self.root / "counter"
        first = self._cache(database_decryptor=_counted_slow_decrypt(counter))
        second = self._cache(database_decryptor=_counted_slow_decrypt(counter))
        self.addCleanup(first.close)
        self.addCleanup(second.close)

        first_path = first.get_snapshot(REL_PATH, KEY)
        second_path = second.get_snapshot(REL_PATH, KEY)

        self.assertEqual(self._read(first_path), "first")
        self.assertEqual(self._read(second_path), "first")
        self.assertEqual(counter.read_text().splitlines(), ["build"])
        self.assertEqual(second.last_event["status"], "disk_hit")

    def test_db_and_wal_versions_each_invalidate_the_cache(self):
        counter = self.root / "counter"
        cache = self._cache(database_decryptor=_counted_slow_decrypt(counter))
        self.addCleanup(cache.close)
        cache.get_snapshot(REL_PATH, KEY)

        self._write_source("second")
        second = cache.get_snapshot(REL_PATH, KEY)
        self.assertEqual(self._read(second), "second")

        wal = Path(str(self.source) + "-wal")
        wal.write_bytes(b"version-one")
        cache.get_snapshot(REL_PATH, KEY)
        wal.write_bytes(b"version-two-longer")
        cache.get_snapshot(REL_PATH, KEY)

        self.assertEqual(len(counter.read_text().splitlines()), 4)

    def test_concurrent_builders_publish_once(self):
        ctx = multiprocessing.get_context("spawn")
        queue = ctx.Queue()
        counter = self.root / "counter"
        args = (str(self.db_dir), str(self.cache_dir), str(counter), queue)
        workers = [ctx.Process(target=_cache_worker, args=args) for _ in range(2)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(10)
            self.assertEqual(worker.exitcode, 0)

        results = [queue.get(timeout=2) for _ in workers]
        self.assertEqual([value for value, _status in results], ["first", "first"])
        self.assertEqual(counter.read_text().splitlines(), ["build"])
        self.assertEqual(sorted(status for _value, status in results), ["built", "locked_hit"])

    def test_sequential_fresh_process_uses_published_snapshot(self):
        ctx = multiprocessing.get_context("spawn")
        queue = ctx.Queue()
        counter = self.root / "counter"
        args = (str(self.db_dir), str(self.cache_dir), str(counter), queue)

        first = ctx.Process(target=_cache_worker, args=args)
        first.start()
        first.join(10)
        self.assertEqual(first.exitcode, 0)
        first_result = queue.get(timeout=2)

        second = ctx.Process(target=_cache_worker, args=args)
        second.start()
        second.join(10)
        self.assertEqual(second.exitcode, 0)
        second_result = queue.get(timeout=2)

        self.assertEqual(first_result, ("first", "built"))
        self.assertEqual(second_result, ("first", "disk_hit"))
        self.assertEqual(counter.read_text().splitlines(), ["build"])

    def test_crashed_builder_temp_is_cleaned(self):
        cache = self._cache()
        self.addCleanup(cache.close)
        signature = cache._source_signature(REL_PATH, KEY)
        resource_dir, _db, _manifest = cache._snapshot_paths(REL_PATH, signature)
        Path(resource_dir).mkdir(parents=True, exist_ok=True)
        orphan = Path(resource_dir) / ".build-dead.tmp"
        orphan.write_text("partial")

        cache.get_snapshot(REL_PATH, KEY)

        self.assertFalse(orphan.exists())

    def test_snapshot_validation_reads_schema_without_full_quick_check(self):
        queries = []
        real_connect = sqlite3.connect

        class RecordingConnection:
            def __init__(self, inner):
                self.inner = inner

            def execute(self, sql, *args, **kwargs):
                queries.append(sql)
                return self.inner.execute(sql, *args, **kwargs)

            def close(self):
                self.inner.close()

        def recording_connect(*args, **kwargs):
            return RecordingConnection(real_connect(*args, **kwargs))

        with mock.patch("core.snapshot_cache.sqlite3.connect", recording_connect):
            DecryptedSnapshotCache._validate_built_snapshot(str(self.source))

        self.assertTrue(any("sqlite_schema" in query for query in queries))
        self.assertFalse(any("quick_check" in query for query in queries))

    def test_snapshot_validation_rejects_non_sqlite_file(self):
        invalid = self.root / "invalid.db"
        invalid.write_bytes(b"not a sqlite database")

        with self.assertRaises(SnapshotCacheError):
            DecryptedSnapshotCache._validate_built_snapshot(str(invalid))

    def test_source_that_changes_during_both_attempts_fails_closed(self):
        calls = []

        def mutating_decrypt(source, destination, _key):
            shutil.copyfile(source, destination)
            calls.append(1)
            with sqlite3.connect(source) as conn:
                conn.execute("INSERT INTO sample VALUES (?)", (f"new-{len(calls)}",))
            return 1

        cache = self._cache(database_decryptor=mutating_decrypt)
        self.addCleanup(cache.close)

        with self.assertRaises(SourceChangedError):
            cache.get_snapshot(REL_PATH, KEY)

        resource = Path(cache.root_dir) / cache.resource_id(REL_PATH)
        published = [p for p in resource.glob("*.db") if not p.name.startswith(".")]
        self.assertEqual(published, [])
        self.assertEqual(len(calls), 2)

    def test_gc_keeps_one_published_version_and_active_old_reader_lease(self):
        old_cache = self._cache()
        new_cache = self._cache()
        self.addCleanup(old_cache.close)
        self.addCleanup(new_cache.close)
        old_lease = old_cache.get_snapshot(REL_PATH, KEY)
        self._write_source("second")

        new_lease = new_cache.get_snapshot(REL_PATH, KEY)

        self.assertTrue(Path(old_lease).exists())
        self.assertEqual(self._read(old_lease), "first")
        self.assertEqual(self._read(new_lease), "second")
        resource = Path(new_cache.root_dir) / new_cache.resource_id(REL_PATH)
        published = [p for p in resource.glob("*.db") if not p.name.startswith(".")]
        self.assertEqual(len(published), 1)
        old_cache.close()
        self.assertFalse(Path(old_lease).exists())

    def test_archive_and_collector_instances_share_same_snapshot(self):
        counter = self.root / "counter"
        archive = self._cache(database_decryptor=_counted_slow_decrypt(counter))
        collector = self._cache(database_decryptor=_counted_slow_decrypt(counter))
        self.addCleanup(archive.close)
        self.addCleanup(collector.close)

        self.assertEqual(self._read(archive.get_snapshot(REL_PATH, KEY)), "first")
        self.assertEqual(self._read(collector.get_snapshot(REL_PATH, KEY)), "first")
        self.assertEqual(counter.read_text().splitlines(), ["build"])

    def test_two_wechatdb_instances_share_snapshot_through_public_db_layer(self):
        counter = self.root / "counter"
        plaintext = self.root / "plaintext.db"
        shutil.copyfile(self.source, plaintext)
        self.source.write_bytes(b"encrypted-source-fixture")

        def counted_fixture_decrypt(_source, destination, _key):
            with open(counter, "a", encoding="ascii") as handle:
                handle.write("build\n")
            shutil.copyfile(plaintext, destination)
            return 1

        def factory(db_dir, cache_dir=None, diagnostic_sink=None):
            return DecryptedSnapshotCache(
                db_dir,
                cache_dir,
                diagnostic_sink=diagnostic_sink,
                database_decryptor=counted_fixture_decrypt,
                wal_patcher=_noop_wal,
            )

        keys = {REL_PATH: {"enc_key": KEY}}
        with mock.patch("core.wechat_db.DecryptedSnapshotCache", side_effect=factory):
            archive = WeChatDB(str(self.db_dir), keys, cache_dir=str(self.cache_dir))
            collector = WeChatDB(str(self.db_dir), keys, cache_dir=str(self.cache_dir))
            self.addCleanup(archive._snapshot_cache.close)
            self.addCleanup(collector._snapshot_cache.close)
            archive_path = archive._get_decrypted_db(REL_PATH)
            collector_path = collector._get_decrypted_db(REL_PATH)

        self.assertEqual(self._read(archive_path), "first")
        self.assertEqual(self._read(collector_path), "first")
        self.assertEqual(counter.read_text().splitlines(), ["build"])

    def test_wechatdb_invalidate_releases_old_lease_and_instance_stays_reusable(self):
        plaintext = self.root / "plaintext.db"
        shutil.copyfile(self.source, plaintext)
        self.source.write_bytes(b"encrypted-v1")

        def fixture_decrypt(_source, destination, _key):
            shutil.copyfile(plaintext, destination)
            return 1

        def factory(db_dir, cache_dir=None, diagnostic_sink=None):
            return DecryptedSnapshotCache(
                db_dir,
                cache_dir,
                diagnostic_sink=diagnostic_sink,
                database_decryptor=fixture_decrypt,
                wal_patcher=_noop_wal,
            )

        with mock.patch("core.wechat_db.DecryptedSnapshotCache", side_effect=factory):
            db = WeChatDB(
                str(self.db_dir),
                {REL_PATH: {"enc_key": KEY}},
                cache_dir=str(self.cache_dir),
            )
            self.addCleanup(db._snapshot_cache.close)
            old_lease = db._get_decrypted_db(REL_PATH)
            self.assertTrue(Path(old_lease).exists())

            db.invalidate_cache()
            self.assertFalse(Path(old_lease).exists())

            self._write_source("second")
            shutil.copyfile(self.source, plaintext)
            self.source.write_bytes(b"encrypted-v2-longer")
            new_lease = db._get_decrypted_db(REL_PATH)

        self.assertTrue(Path(new_lease).exists())
        self.assertEqual(self._read(new_lease), "second")

    def test_diagnostics_do_not_expose_path_key_or_content(self):
        events = []
        cache = self._cache(diagnostic_sink=events.append)
        self.addCleanup(cache.close)

        cache.get_snapshot(REL_PATH, KEY)
        serialized = json.dumps(events)

        self.assertNotIn(str(self.db_dir), serialized)
        self.assertNotIn(KEY, serialized)
        self.assertNotIn("first", serialized)
        self.assertIn("segments_ms", events[0])

    def test_empty_chat_mapping_is_not_persisted(self):
        cache = self._cache()
        self.addCleanup(cache.close)
        cache.put_message_shards("new-chat", [REL_PATH], [])

        self.assertIsNone(cache.get_message_shards("new-chat", [REL_PATH]))

    def test_new_table_in_existing_shard_is_found_after_initial_empty_scan(self):
        username = "late-chat"
        keys = {REL_PATH: {"enc_key": KEY}}
        db = WeChatDB(str(self.db_dir), keys, cache_dir=str(self.cache_dir))
        self.addCleanup(db._snapshot_cache.close)
        paths, table = db._find_msg_table(username)
        self.assertEqual((paths, table), ([], None))

        table_name = "Msg_" + hashlib.md5(username.encode()).hexdigest()
        with sqlite3.connect(self.source) as conn:
            conn.execute(f"CREATE TABLE [{table_name}](create_time INTEGER)")

        paths, table = db._find_msg_table(username)
        self.assertEqual(paths, [str(self.source)])
        self.assertEqual(table, table_name)

    def test_nonempty_mapping_survives_data_writes_but_not_new_shards(self):
        cache = self._cache()
        self.addCleanup(cache.close)
        cache.put_message_shards("chat", [REL_PATH], [REL_PATH])
        self.assertEqual(cache.get_message_shards("chat", [REL_PATH]), [REL_PATH])

        with sqlite3.connect(self.source) as conn:
            conn.execute("INSERT INTO sample VALUES ('ordinary-write')")
        self.assertEqual(cache.get_message_shards("chat", [REL_PATH]), [REL_PATH])

        other_rel = "message/message_1.db"
        other = self.db_dir / other_rel
        shutil.copyfile(self.source, other)
        self.assertIsNone(cache.get_message_shards("chat", [REL_PATH, other_rel]))

    def test_cache_does_not_touch_unrelated_state_or_cursor_files(self):
        state = self.root / "live-state.json"
        cursor = self.root / "live-cursor.json"
        state.write_text('{"sentinel":1}\n')
        cursor.write_text('{"cursor":99}\n')
        before = (state.read_bytes(), cursor.read_bytes())
        cache = self._cache()
        self.addCleanup(cache.close)

        cache.get_snapshot(REL_PATH, KEY)

        self.assertEqual((state.read_bytes(), cursor.read_bytes()), before)


if __name__ == "__main__":
    unittest.main()
