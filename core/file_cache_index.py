"""Persistent metadata/hash index for WeChat's downloaded file cache.

The directory walk remains deliberate: directory mtimes cannot prove that a
nested file's bytes did not change.  What is made incremental is the expensive
part—the content hash.  A hash is reused only while the file's identity, size,
mtime, and ctime all still match, and cross-process updates are serialized and
published atomically.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import stat as stat_module
import tempfile
from pathlib import Path


INDEX_SCHEMA = 1


def _file_signature(stat) -> dict:
    return {
        "device": stat.st_dev,
        "inode": stat.st_ino,
        "size": stat.st_size,
        "mtime_ns": stat.st_mtime_ns,
        "ctime_ns": stat.st_ctime_ns,
    }


class PersistentFileCacheIndex:
    """Resolve file appmsg metadata without re-hashing unchanged cache files."""

    def __init__(self, file_root: str, index_dir: str):
        self.file_root = os.path.realpath(file_root)
        root_id = hashlib.sha256(self.file_root.encode("utf-8")).hexdigest()[:16]
        self.index_dir = os.path.realpath(index_dir)
        self.index_path = os.path.join(self.index_dir, f"files-{root_id}.json")
        self.lock_path = self.index_path + ".lock"
        self._refreshed = False
        self._value = None
        os.makedirs(self.index_dir, mode=0o700, exist_ok=True)

    def _load(self) -> dict:
        try:
            with open(self.index_path, encoding="utf-8") as handle:
                value = json.load(handle)
        except (OSError, json.JSONDecodeError):
            return {"schema": INDEX_SCHEMA, "files": {}}
        if value.get("schema") != INDEX_SCHEMA or not isinstance(value.get("files"), dict):
            return {"schema": INDEX_SCHEMA, "files": {}}
        return value

    def _write(self, value: dict) -> None:
        fd, temp_path = tempfile.mkstemp(
            prefix=".files-index-",
            suffix=".tmp",
            dir=self.index_dir,
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(value, handle, sort_keys=True, separators=(",", ":"))
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_path, self.index_path)
            try:
                directory_fd = os.open(self.index_dir, os.O_RDONLY)
            except OSError:
                directory_fd = None
            if directory_fd is not None:
                try:
                    os.fsync(directory_fd)
                except OSError:
                    pass
                finally:
                    os.close(directory_fd)
        finally:
            try:
                os.unlink(temp_path)
            except FileNotFoundError:
                pass

    def _refresh_locked(self, previous: dict) -> dict:
        old_files = previous.get("files", {})
        files = {}
        if os.path.isdir(self.file_root):
            for root, _dirs, names in os.walk(self.file_root):
                for name in names:
                    path = os.path.join(root, name)
                    try:
                        stat = os.stat(path, follow_symlinks=False)
                    except OSError:
                        continue
                    if not stat_module.S_ISREG(stat.st_mode):
                        continue
                    rel_path = os.path.relpath(path, self.file_root)
                    signature = _file_signature(stat)
                    old = old_files.get(rel_path)
                    if isinstance(old, dict) and old.get("signature") == signature:
                        digest = old.get("md5", "")
                    else:
                        digest = ""
                    files[rel_path] = {"signature": signature, "md5": digest}
        value = {"schema": INDEX_SCHEMA, "files": files}
        self._write(value)
        return value

    @staticmethod
    def _hash_stable(path: str, expected_signature: dict) -> str:
        digest = hashlib.md5()
        try:
            before = _file_signature(os.stat(path, follow_symlinks=False))
            if before != expected_signature:
                return ""
            with open(path, "rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
            after = _file_signature(os.stat(path, follow_symlinks=False))
        except OSError:
            return ""
        return digest.hexdigest() if before == after == expected_signature else ""

    def _locked(self):
        fd = os.open(self.lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        handle = os.fdopen(fd, "a+")
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        return handle

    def refresh(self) -> dict:
        """Refresh file metadata once per instance and return the local index."""
        if self._refreshed and self._value is not None:
            return self._value
        with self._locked():
            self._value = self._refresh_locked(self._load())
        self._refreshed = True
        return self._value

    @staticmethod
    def _signature_still_matches(path: str, signature: dict) -> bool:
        try:
            stat = os.stat(path, follow_symlinks=False)
        except OSError:
            return False
        return stat_module.S_ISREG(stat.st_mode) and _file_signature(stat) == signature

    def find(self, metadata: dict, create_time: float) -> str | None:
        """Return a stable matching file, or None rather than guess."""
        size = int(metadata.get("size") or 0)
        if size <= 0:
            return None
        expected_md5 = str(metadata.get("md5") or "").lower()
        expected_ext = str(metadata.get("fileext") or "").lstrip(".").lower()

        # Hash/index updates stay under one cross-process lock so two short-lived
        # collector processes do not hash the same unchanged candidate twice.
        with self._locked():
            if self._refreshed and self._value is not None:
                value = self._value
            else:
                value = self._refresh_locked(self._load())
                self._value = value
                self._refreshed = True
            candidates = []
            for rel_path, record in value["files"].items():
                signature = record.get("signature", {})
                if signature.get("size") != size:
                    continue
                path = os.path.join(self.file_root, rel_path)
                delta = abs(signature.get("mtime_ns", 0) / 1_000_000_000 - create_time)
                candidates.append((delta, rel_path, path, record))
            candidates.sort(key=lambda item: (item[0], item[1]))

            dirty = False
            if expected_md5:
                for _delta, _rel_path, path, record in candidates:
                    if not self._signature_still_matches(path, record["signature"]):
                        continue
                    digest = record.get("md5", "")
                    if not digest:
                        digest = self._hash_stable(path, record["signature"])
                        if not digest:
                            continue
                        record["md5"] = digest
                        dirty = True
                    if digest == expected_md5:
                        if dirty:
                            self._write(value)
                        self._value = value
                        self._refreshed = True
                        return path
                if dirty:
                    self._write(value)
                return None

            for delta, rel_path, path, _record in candidates:
                if delta > 60:
                    continue
                actual_ext = Path(rel_path).suffix.lstrip(".").lower()
                if expected_ext and actual_ext != expected_ext:
                    continue
                if not self._signature_still_matches(path, _record["signature"]):
                    continue
                self._value = value
                self._refreshed = True
                return path
            return None
