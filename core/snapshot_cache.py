"""Cross-process, fail-closed cache for decrypted WeChat database snapshots.

The source databases are live SQLCipher files.  A cache entry is therefore
identified by both the database and WAL versions, built under a per-resource
file lock, and published atomically only after the source stayed unchanged for
the whole build.  Cache metadata intentionally contains hashes and timings,
never encryption keys, chat content, or source paths.
"""

from __future__ import annotations

import fcntl
import atexit
import hashlib
import json
import os
import sqlite3
import sys
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Callable

from .decryptor import decrypt_database, decrypt_wal


CACHE_SCHEMA = 2
MAPPING_SCHEMA = 1


class SnapshotCacheError(RuntimeError):
    """A snapshot could not be built without risking stale/corrupt data."""


class SourceChangedError(SnapshotCacheError):
    """The live database or WAL changed while a snapshot was being built."""


def _canonical_digest(value: object) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _stat_signature(path: str) -> dict:
    """Return a metadata signature strong enough to detect live-file changes."""
    try:
        stat = os.stat(path)
    except FileNotFoundError:
        return {"exists": False}
    return {
        "exists": True,
        "device": stat.st_dev,
        "inode": stat.st_ino,
        "size": stat.st_size,
        "mtime_ns": stat.st_mtime_ns,
        "ctime_ns": stat.st_ctime_ns,
    }


def _fsync_directory(path: str) -> None:
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


@contextmanager
def _exclusive_lock(path: str):
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    with os.fdopen(fd, "a+") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


class DecryptedSnapshotCache:
    """Build and reuse immutable decrypted snapshots across fresh processes."""

    def __init__(
        self,
        db_dir: str,
        cache_dir: str | None = None,
        *,
        diagnostic_sink: Callable[[dict], None] | None = None,
        database_decryptor: Callable[[str, str, str], int] = decrypt_database,
        wal_patcher: Callable[[str, str, str], int] = decrypt_wal,
    ):
        self.db_dir = os.path.realpath(db_dir)
        base = cache_dir or os.environ.get(
            "WECHAT_SUMMARY_CACHE_DIR",
            os.path.join(tempfile.gettempdir(), "wechat_summary_cache"),
        )
        self.cache_dir = os.path.realpath(os.path.expanduser(base))
        self.root_id = hashlib.sha256(self.db_dir.encode("utf-8")).hexdigest()[:16]
        self.root_dir = os.path.join(
            self.cache_dir,
            f"v{CACHE_SCHEMA}",
            self.root_id,
        )
        self._diagnostic_sink = diagnostic_sink
        self._database_decryptor = database_decryptor
        self._wal_patcher = wal_patcher
        self._memory = {}
        self._leases = {}
        self.last_event = None
        os.makedirs(self.root_dir, mode=0o700, exist_ok=True)
        try:
            os.chmod(self.root_dir, 0o700)
        except OSError:
            pass
        atexit.register(self.close)

    @staticmethod
    def resource_id(rel_path: str) -> str:
        normalized = rel_path.replace("\\", "/")
        return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]

    def _source_signature(self, rel_path: str, enc_key_hex: str) -> dict:
        source = os.path.join(self.db_dir, rel_path)
        db_signature = _stat_signature(source)
        if not db_signature["exists"]:
            raise FileNotFoundError(source)
        return {
            "schema": CACHE_SCHEMA,
            "db": db_signature,
            "wal": _stat_signature(source + "-wal"),
            # A one-way key fingerprint prevents reuse after key rotation without
            # ever persisting or logging key material.
            "key_id": hashlib.sha256(enc_key_hex.encode("ascii")).hexdigest()[:16],
        }

    def _snapshot_paths(self, rel_path: str, signature: dict) -> tuple[str, str, str]:
        resource_id = self.resource_id(rel_path)
        version = _canonical_digest(signature)[:24]
        resource_dir = os.path.join(self.root_dir, resource_id)
        return (
            resource_dir,
            os.path.join(resource_dir, f"{version}.db"),
            os.path.join(resource_dir, f"{version}.json"),
        )

    def _valid_snapshot(self, db_path: str, manifest_path: str, signature: dict) -> bool:
        try:
            with open(manifest_path, encoding="utf-8") as handle:
                manifest = json.load(handle)
            stat = os.stat(db_path)
            if manifest.get("schema") != CACHE_SCHEMA:
                return False
            if manifest.get("source_digest") != _canonical_digest(signature):
                return False
            if manifest.get("snapshot_size") != stat.st_size:
                return False
            if manifest.get("snapshot_mtime_ns") != stat.st_mtime_ns:
                return False
            with open(db_path, "rb") as handle:
                return handle.read(16) == b"SQLite format 3\x00"
        except (OSError, ValueError, json.JSONDecodeError):
            return False

    @staticmethod
    def _validate_built_snapshot(path: str) -> None:
        try:
            uri = Path(path).resolve().as_uri() + "?mode=ro&immutable=1"
            conn = sqlite3.connect(uri, uri=True, timeout=5)
            try:
                row = conn.execute("PRAGMA quick_check(1)").fetchone()
            finally:
                conn.close()
        except sqlite3.Error as exc:
            raise SnapshotCacheError("decrypted snapshot is not readable SQLite") from exc
        if not row or row[0] != "ok":
            raise SnapshotCacheError("decrypted snapshot failed SQLite quick_check")

    def _emit(self, event: dict) -> None:
        safe_event = {
            "schema": 1,
            "event": "wechat_decrypted_snapshot",
            **event,
        }
        self.last_event = safe_event
        if self._diagnostic_sink is not None:
            self._diagnostic_sink(dict(safe_event))
        if os.environ.get("WECHAT_SUMMARY_CACHE_DIAGNOSTICS") == "1":
            print(
                "[wechat-cache] "
                + json.dumps(safe_event, sort_keys=True, separators=(",", ":")),
                file=sys.stderr,
            )

    @staticmethod
    def _cleanup_temps(resource_dir: str) -> None:
        try:
            names = os.listdir(resource_dir)
        except OSError:
            return
        for name in names:
            if not (name.startswith(".build-") or name.startswith(".manifest-")):
                continue
            try:
                os.unlink(os.path.join(resource_dir, name))
            except OSError:
                pass

    def _lease_snapshot(
        self,
        resource_dir: str,
        snapshot_path: str,
        version: str,
    ) -> str:
        """Pin a snapshot inode for this process while old versions are pruned.

        A hard link makes unlink-based garbage collection safe even if the live
        source advances after this process obtained a snapshot.  The companion
        shared flock lets a later process distinguish an active lease from a
        crashed builder's orphaned files without trusting PIDs or wall clocks.
        """
        lease_key = (resource_dir, version)
        existing = self._leases.get(lease_key)
        if existing and os.path.exists(existing[0]):
            return existing[0]

        nonce = hashlib.sha256(
            f"{os.getpid()}:{id(self)}:{version}".encode("ascii")
        ).hexdigest()[:12]
        lease_db = os.path.join(resource_dir, f".lease-{nonce}-{version}.db")
        lease_lock = lease_db + ".lock"
        lock_fd = os.open(lease_lock, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_SH)
            try:
                os.link(snapshot_path, lease_db)
            except FileExistsError:
                pass
        except Exception:
            os.close(lock_fd)
            try:
                os.unlink(lease_db)
            except FileNotFoundError:
                pass
            raise
        self._leases[lease_key] = (lease_db, lease_lock, lock_fd)
        return lease_db

    @staticmethod
    def _cleanup_dead_leases(resource_dir: str) -> None:
        try:
            names = os.listdir(resource_dir)
        except OSError:
            return
        for name in names:
            if not (name.startswith(".lease-") and name.endswith(".db.lock")):
                continue
            lock_path = os.path.join(resource_dir, name)
            try:
                fd = os.open(lock_path, os.O_RDWR)
            except OSError:
                continue
            try:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    continue
                lease_db = lock_path[:-5]
                for path in (lease_db, lock_path):
                    try:
                        os.unlink(path)
                    except FileNotFoundError:
                        pass
            finally:
                os.close(fd)

    def _gc_resource(
        self,
        resource_dir: str,
        current_db: str,
        current_manifest: str,
    ) -> None:
        """Keep one published version; active readers retain inode leases."""
        self._cleanup_dead_leases(resource_dir)
        keep = {os.path.basename(current_db), os.path.basename(current_manifest)}
        try:
            names = os.listdir(resource_dir)
        except OSError:
            return
        for name in names:
            if name in keep or name.startswith("."):
                continue
            if not (name.endswith(".db") or name.endswith(".json")):
                continue
            try:
                os.unlink(os.path.join(resource_dir, name))
            except OSError:
                pass

    @staticmethod
    def _write_json_atomic(path: str, value: dict, prefix: str = ".manifest-") -> None:
        directory = os.path.dirname(path)
        fd, temp_path = tempfile.mkstemp(prefix=prefix, suffix=".tmp", dir=directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(value, handle, sort_keys=True, separators=(",", ":"))
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_path, path)
            _fsync_directory(directory)
        finally:
            try:
                os.unlink(temp_path)
            except FileNotFoundError:
                pass

    def get_snapshot(self, rel_path: str, enc_key_hex: str) -> str:
        """Return the exact snapshot for the current DB+WAL version.

        If the live source moves while it is being read, the partial output is
        discarded and the operation is retried once.  A second mutation fails
        closed instead of returning the previous snapshot.
        """
        resource_id = self.resource_id(rel_path)
        total_started = time.monotonic()

        for attempt in range(2):
            signature = self._source_signature(rel_path, enc_key_hex)
            version = _canonical_digest(signature)[:24]
            resource_dir, db_path, manifest_path = self._snapshot_paths(
                rel_path, signature
            )
            memory_key = (resource_id, version)
            if self._memory.get(memory_key) == db_path and self._valid_snapshot(
                db_path, manifest_path, signature
            ):
                try:
                    lease_path = self._lease_snapshot(resource_dir, db_path, version)
                except FileNotFoundError:
                    self._memory.pop(memory_key, None)
                else:
                    if self._source_signature(rel_path, enc_key_hex) != signature:
                        continue
                    self._emit({
                        "status": "memory_hit",
                        "resource_id": resource_id,
                        "source_version": version,
                        "duration_ms": round((time.monotonic() - total_started) * 1000, 3),
                    })
                    return lease_path
            if self._valid_snapshot(db_path, manifest_path, signature):
                self._memory[memory_key] = db_path
                try:
                    lease_path = self._lease_snapshot(resource_dir, db_path, version)
                except FileNotFoundError:
                    self._memory.pop(memory_key, None)
                else:
                    if self._source_signature(rel_path, enc_key_hex) != signature:
                        continue
                    lock_path = os.path.join(self.root_dir, f"{resource_id}.lock")
                    with _exclusive_lock(lock_path):
                        if self._source_signature(rel_path, enc_key_hex) == signature:
                            self._gc_resource(resource_dir, db_path, manifest_path)
                    self._emit({
                        "status": "disk_hit",
                        "resource_id": resource_id,
                        "source_version": version,
                        "duration_ms": round((time.monotonic() - total_started) * 1000, 3),
                    })
                    return lease_path

            os.makedirs(resource_dir, mode=0o700, exist_ok=True)
            lock_path = os.path.join(self.root_dir, f"{resource_id}.lock")
            lock_started = time.monotonic()
            with _exclusive_lock(lock_path):
                lock_ms = (time.monotonic() - lock_started) * 1000
                # The source may have advanced while this process waited.
                locked_signature = self._source_signature(rel_path, enc_key_hex)
                if locked_signature != signature:
                    continue
                resource_dir, db_path, manifest_path = self._snapshot_paths(
                    rel_path, signature
                )
                if self._valid_snapshot(db_path, manifest_path, signature):
                    if self._source_signature(rel_path, enc_key_hex) != signature:
                        continue
                    self._memory[memory_key] = db_path
                    lease_path = self._lease_snapshot(resource_dir, db_path, version)
                    self._gc_resource(resource_dir, db_path, manifest_path)
                    self._emit({
                        "status": "locked_hit",
                        "resource_id": resource_id,
                        "source_version": version,
                        "duration_ms": round((time.monotonic() - total_started) * 1000, 3),
                        "segments_ms": {"lock_wait": round(lock_ms, 3)},
                    })
                    return lease_path

                self._cleanup_temps(resource_dir)
                fd, temp_db = tempfile.mkstemp(
                    prefix=f".build-{os.getpid()}-",
                    suffix=".tmp",
                    dir=resource_dir,
                )
                os.close(fd)
                segments = {"lock_wait": round(lock_ms, 3)}
                try:
                    decrypt_started = time.monotonic()
                    pages = self._database_decryptor(
                        os.path.join(self.db_dir, rel_path),
                        temp_db,
                        enc_key_hex,
                    )
                    segments["decrypt"] = round(
                        (time.monotonic() - decrypt_started) * 1000, 3
                    )
                    if not pages:
                        raise SnapshotCacheError("database decryption returned no pages")

                    wal_frames = 0
                    wal_path = os.path.join(self.db_dir, rel_path) + "-wal"
                    if signature["wal"]["exists"]:
                        wal_started = time.monotonic()
                        wal_frames = self._wal_patcher(
                            wal_path,
                            temp_db,
                            enc_key_hex,
                        )
                        segments["wal_patch"] = round(
                            (time.monotonic() - wal_started) * 1000, 3
                        )

                    validate_started = time.monotonic()
                    self._validate_built_snapshot(temp_db)
                    segments["validate"] = round(
                        (time.monotonic() - validate_started) * 1000, 3
                    )

                    after = self._source_signature(rel_path, enc_key_hex)
                    if after != signature:
                        raise SourceChangedError(
                            "source database changed during snapshot build"
                        )

                    with open(temp_db, "rb") as handle:
                        os.fsync(handle.fileno())
                    os.chmod(temp_db, 0o400)
                    os.replace(temp_db, db_path)
                    stat = os.stat(db_path)
                    manifest = {
                        "schema": CACHE_SCHEMA,
                        "source_digest": _canonical_digest(signature),
                        "snapshot_size": stat.st_size,
                        "snapshot_mtime_ns": stat.st_mtime_ns,
                        "pages": int(pages),
                        "wal_frames": int(wal_frames or 0),
                    }
                    self._write_json_atomic(manifest_path, manifest)
                    self._memory[memory_key] = db_path
                    lease_path = self._lease_snapshot(resource_dir, db_path, version)
                    self._gc_resource(resource_dir, db_path, manifest_path)
                    self._emit({
                        "status": "built",
                        "resource_id": resource_id,
                        "source_version": version,
                        "duration_ms": round((time.monotonic() - total_started) * 1000, 3),
                        "segments_ms": segments,
                        "pages": int(pages),
                        "wal_frames": int(wal_frames or 0),
                    })
                    return lease_path
                except SourceChangedError:
                    self._emit({
                        "status": "source_changed",
                        "resource_id": resource_id,
                        "source_version": version,
                        "attempt": attempt + 1,
                        "duration_ms": round((time.monotonic() - total_started) * 1000, 3),
                        "segments_ms": segments,
                    })
                    if attempt == 1:
                        raise
                finally:
                    try:
                        os.unlink(temp_db)
                    except FileNotFoundError:
                        pass

        raise SourceChangedError("source database did not stabilize")

    def clear_memory(self) -> None:
        """Forget process-local objects; immutable disk snapshots remain reusable."""
        self._memory.clear()

    def close(self) -> None:
        """Release this process's hard-link leases; safe to call repeatedly."""
        self.release_leases()

    def release_leases(self) -> None:
        """Unpin snapshots while keeping this cache instance reusable."""
        leases, self._leases = self._leases, {}
        for lease_db, lease_lock, lock_fd in leases.values():
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            except OSError:
                pass
            try:
                os.close(lock_fd)
            except OSError:
                pass
            for path in (lease_db, lease_lock):
                try:
                    os.unlink(path)
                except FileNotFoundError:
                    pass

    def _message_topology(self, rel_paths: list[str]) -> tuple[str, dict[str, str]]:
        resources = {}
        topology = []
        for rel_path in sorted(rel_paths):
            source = os.path.join(self.db_dir, rel_path)
            signature = _stat_signature(source)
            if not signature["exists"]:
                continue
            resource_id = self.resource_id(rel_path)
            resources[resource_id] = rel_path
            # Message/WAL content changes do not move an existing table.  A new
            # shard or source-file replacement does, so topology keys on the
            # resource set and file identity rather than mtime/size.
            topology.append({
                "resource_id": resource_id,
                "device": signature["device"],
                "inode": signature["inode"],
            })
        return _canonical_digest(topology), resources

    @property
    def _mapping_path(self) -> str:
        return os.path.join(self.root_dir, "message-shards.json")

    def get_message_shards(
        self,
        username: str,
        rel_paths: list[str],
    ) -> list[str] | None:
        topology, resources = self._message_topology(rel_paths)
        chat_id = hashlib.sha256(username.encode("utf-8")).hexdigest()
        try:
            with open(self._mapping_path, encoding="utf-8") as handle:
                value = json.load(handle)
        except (OSError, json.JSONDecodeError):
            return None
        if value.get("schema") != MAPPING_SCHEMA:
            return None
        if value.get("topology") != topology:
            return None
        entry = value.get("entries", {}).get(chat_id)
        if not isinstance(entry, list):
            return None
        result = []
        for resource_id in entry:
            rel_path = resources.get(resource_id)
            if rel_path is None:
                return None
            result.append(rel_path)
        return result

    def put_message_shards(
        self,
        username: str,
        rel_paths: list[str],
        matched_rel_paths: list[str],
    ) -> None:
        topology, resources = self._message_topology(rel_paths)
        matched_ids = [
            self.resource_id(rel_path)
            for rel_path in matched_rel_paths
            if self.resource_id(rel_path) in resources
        ]
        # An empty result is not stable: WeChat can create a new chat table in
        # an existing shard without changing the shard's inode topology.
        if not matched_ids:
            self.forget_message_shards(username)
            return
        chat_id = hashlib.sha256(username.encode("utf-8")).hexdigest()
        lock_path = os.path.join(self.root_dir, "message-shards.lock")
        with _exclusive_lock(lock_path):
            try:
                with open(self._mapping_path, encoding="utf-8") as handle:
                    value = json.load(handle)
            except (OSError, json.JSONDecodeError):
                value = {}
            if value.get("schema") != MAPPING_SCHEMA or value.get("topology") != topology:
                value = {
                    "schema": MAPPING_SCHEMA,
                    "topology": topology,
                    "entries": {},
                }
            value.setdefault("entries", {})[chat_id] = matched_ids
            self._write_json_atomic(
                self._mapping_path,
                value,
                prefix=".mapping-",
            )

    def forget_message_shards(self, username: str) -> None:
        chat_id = hashlib.sha256(username.encode("utf-8")).hexdigest()
        lock_path = os.path.join(self.root_dir, "message-shards.lock")
        with _exclusive_lock(lock_path):
            try:
                with open(self._mapping_path, encoding="utf-8") as handle:
                    value = json.load(handle)
            except (OSError, json.JSONDecodeError):
                return
            entries = value.get("entries")
            if isinstance(entries, dict) and entries.pop(chat_id, None) is not None:
                self._write_json_atomic(
                    self._mapping_path,
                    value,
                    prefix=".mapping-",
                )
