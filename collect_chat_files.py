#!/usr/bin/env python3
"""Copy one chat's already-downloaded WeChat files into a stable inbox.

The collector owns its cursor and pending list. It never reads or writes the
digest/archive cursors. Missing cache files remain pending and are retried on
later runs; completed copies and manifest entries are idempotent.
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
from datetime import datetime
from zoneinfo import ZoneInfo

from core.config import load_config
from core.key_extractor import get_cached_keys
from core.wechat_db import WeChatDB


SYD = ZoneInfo("Australia/Sydney")
BASE_DIR = os.path.expanduser("~/.wechat-summary")
DEFAULT_STATE_FILE = os.path.join(BASE_DIR, "chat-file-state.json")
DEFAULT_MANIFEST_DIR = os.path.join(BASE_DIR, "file-manifests")
DEFAULT_DEST_ROOT = os.path.expanduser("~/Documents/WeChat Files")


def _safe_name(value, fallback="unnamed"):
    """Return a basename safe for a user-visible destination directory."""
    value = (value or "").replace("\\", "/").split("/")[-1]
    value = re.sub(r"[\x00-\x1f\x7f]", "", value).strip()
    if value in ("", ".", ".."):
        value = fallback

    stem, ext = os.path.splitext(value)
    if len(value) > 180:
        keep = max(1, 180 - len(ext))
        value = stem[:keep].rstrip() + ext
    return value


def _event_id(chat, record):
    payload = "\0".join(
        (
            chat,
            str(record.get("timestamp", "")),
            record.get("md5", ""),
            record.get("title", ""),
        )
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _file_md5(path):
    digest = hashlib.md5()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_json(path, fallback):
    try:
        with open(path, encoding="utf-8") as handle:
            value = json.load(handle)
        return value
    except (OSError, json.JSONDecodeError):
        return fallback


def _save_json_atomic(path, value):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd, temp_path = tempfile.mkstemp(
        prefix=os.path.basename(path) + ".",
        suffix=".tmp",
        dir=os.path.dirname(path),
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)


def _manifest_path(manifest_dir, timestamp):
    day = datetime.fromtimestamp(timestamp, SYD).strftime("%Y-%m-%d")
    return os.path.join(manifest_dir, f"{day}.jsonl")


def _manifest_ids(path):
    ids = set()
    try:
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if entry.get("event_id"):
                    ids.add(entry["event_id"])
    except OSError:
        pass
    return ids


def _append_manifest(path, entry):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, ensure_ascii=False, sort_keys=True))
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())


def _write_daily_summary(manifest_path):
    """Write a small deduplicated JSON input for the day's final digest."""
    entries = []
    try:
        with open(manifest_path, encoding="utf-8") as handle:
            for line in handle:
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if entry.get("title"):
                    entries.append(entry)
    except OSError:
        return None

    unique = {}
    for entry in entries:
        key = entry.get("md5") or (
            f"{entry.get('title', '')}\0{entry.get('size', 0)}"
        )
        unique.setdefault(key, entry)

    day = os.path.basename(manifest_path).removesuffix(".jsonl")
    summary_path = os.path.join(
        os.path.dirname(manifest_path),
        f"{day}.summary.json",
    )
    summary = {
        "schema_version": 1,
        "date": day,
        "unique_file_count": len(unique),
        "files": [
            {
                "title": entry["title"],
                "stored_name": entry.get("stored_name", entry["title"]),
                "size": entry.get("size", 0),
                "sender": entry.get("sender", ""),
                "message_time": entry.get("message_time", ""),
            }
            for entry in unique.values()
        ],
    }
    _save_json_atomic(summary_path, summary)
    return summary_path


def _destination_path(destination, record):
    """Choose a non-destructive path, reusing an identical existing file."""
    title = _safe_name(record.get("title"), fallback="wechat-file")
    candidate = os.path.join(destination, title)
    expected_md5 = record.get("md5") or ""

    if not os.path.exists(candidate):
        return candidate, False
    if expected_md5 and _file_md5(candidate) == expected_md5:
        return candidate, True

    stem, ext = os.path.splitext(title)
    stamp = datetime.fromtimestamp(record["timestamp"], SYD).strftime(
        "%Y-%m-%d %H%M"
    )
    candidate = os.path.join(destination, f"{stem} ({stamp}){ext}")
    counter = 2
    while os.path.exists(candidate):
        if expected_md5 and _file_md5(candidate) == expected_md5:
            return candidate, True
        candidate = os.path.join(
            destination, f"{stem} ({stamp}, {counter}){ext}"
        )
        counter += 1
    return candidate, False


def _copy_verified(source, destination, record):
    os.makedirs(os.path.dirname(destination), exist_ok=True)
    fd, temp_path = tempfile.mkstemp(
        prefix=".wechat-file-",
        suffix=".tmp",
        dir=os.path.dirname(destination),
    )
    os.close(fd)
    try:
        shutil.copy2(source, temp_path)
        expected_size = record.get("size") or 0
        if expected_size and os.path.getsize(temp_path) != expected_size:
            raise OSError("copied file size does not match appmsg metadata")
        expected_md5 = record.get("md5") or ""
        if expected_md5 and _file_md5(temp_path) != expected_md5:
            raise OSError("copied file md5 does not match appmsg metadata")
        os.replace(temp_path, destination)
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)


def _pending_record(record):
    return {
        "sender": record.get("sender", ""),
        "title": record.get("title", ""),
        "size": record.get("size", 0),
        "md5": record.get("md5", ""),
        "fileext": record.get("fileext", ""),
        "timestamp": record.get("timestamp", 0),
    }


def _initial_cursor():
    now = datetime.now(SYD)
    return now.replace(hour=0, minute=0, second=0, microsecond=0).timestamp()


def collect(args):
    cfg = load_config()
    keys = get_cached_keys()
    if not keys:
        raise RuntimeError("no cached WeChat database keys")

    db = WeChatDB(cfg["db_dir"], keys)
    username = db.resolve_username(args.chat)
    if not username:
        raise RuntimeError(f"chat not found: {args.chat}")

    state = _load_json(
        args.state_file,
        {"schema_version": 1, "chats": {}},
    )
    chats = state.setdefault("chats", {})
    chat_state = chats.setdefault(
        args.chat,
        {"last_ts": _initial_cursor(), "pending": []},
    )
    since_ts = float(chat_state.get("last_ts") or _initial_cursor())

    records, watermark = db.get_file_messages(
        username,
        since_ts=since_ts,
        limit=args.limit,
        include_scan_watermark=True,
    )
    pending = list(chat_state.get("pending") or [])
    candidates = pending + [_pending_record(record) for record in records]

    destination = os.path.join(args.dest_root, _safe_name(args.chat, "chat"))
    manifests = {}
    next_pending = []
    copied = 0
    recorded = 0
    already_recorded = 0

    for record in candidates:
        event_id = _event_id(args.chat, record)
        manifest_path = _manifest_path(args.manifest_dir, record["timestamp"])
        if manifest_path not in manifests:
            manifests[manifest_path] = _manifest_ids(manifest_path)
        if event_id in manifests[manifest_path]:
            already_recorded += 1
            continue

        source = db.find_cached_file(record, record["timestamp"])
        if not source:
            next_pending.append(_pending_record(record))
            continue

        if args.dry_run:
            recorded += 1
            continue

        destination_path, identical = _destination_path(destination, record)
        if not identical:
            _copy_verified(source, destination_path, record)
            copied += 1

        entry = {
            "schema_version": 1,
            "event_id": event_id,
            "chat": args.chat,
            "message_ts": record["timestamp"],
            "message_time": datetime.fromtimestamp(
                record["timestamp"], SYD
            ).isoformat(),
            "sender": record.get("sender", ""),
            "title": record["title"],
            "stored_name": os.path.basename(destination_path),
            "size": record.get("size", 0),
            "md5": record.get("md5", ""),
            "collected_at": datetime.now(SYD).isoformat(),
        }
        _append_manifest(manifest_path, entry)
        manifests[manifest_path].add(event_id)
        recorded += 1

    if not args.dry_run:
        for manifest_path in manifests:
            if os.path.exists(manifest_path):
                _write_daily_summary(manifest_path)
        chat_state["last_ts"] = max(since_ts, watermark)
        chat_state["updated"] = datetime.now(SYD).isoformat()
        chat_state["pending"] = next_pending
        _save_json_atomic(args.state_file, state)

    return {
        "chat": args.chat,
        "scanned_file_messages": len(records),
        "recorded": recorded,
        "copied": copied,
        "already_recorded": already_recorded,
        "pending": len(next_pending),
        "dry_run": args.dry_run,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--chat", default="可爱小克")
    parser.add_argument(
        "--dest-root",
        default=os.environ.get(
            "WECHAT_GROUP_FILES_DIR",
            DEFAULT_DEST_ROOT,
        ),
    )
    parser.add_argument(
        "--state-file",
        default=os.environ.get(
            "WECHAT_GROUP_FILES_STATE",
            DEFAULT_STATE_FILE,
        ),
    )
    parser.add_argument(
        "--manifest-dir",
        default=os.environ.get(
            "WECHAT_GROUP_FILES_MANIFEST_DIR",
            DEFAULT_MANIFEST_DIR,
        ),
    )
    parser.add_argument("--limit", type=int, default=10000)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    try:
        result = collect(args)
    except Exception as exc:
        print(f"collect-chat-files: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
