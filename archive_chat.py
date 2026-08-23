#!/Users/alta/mac-wechat-summary/.venv/bin/python3
"""Archive raw WeChat chat history slices for the digest follow-up feature.

Called by ~/wechat-digest.sh right before the digest claude -p run.
Dumps all messages newer than its OWN cursor (~/.wechat-summary/archive-cursor.json,
completely separate from digest-cursors.json — never touches that file) into a
time-window slice file under ~/.wechat-summary/archive/<chat>/.

Slices are append-only: this script only ever creates new files, never deletes.
Only message text/sender/time go into slices — no tokens, no keys.

stdout (last line) on success: the slice label, e.g.
    07-11 13:06~15:04 · 可爱小克
Empty stdout = no new messages (or dry-run found nothing).

All timestamp formatting is explicitly Australia/Sydney. Never naive now().
"""

import argparse
import json
import os
import sys
import tempfile
from datetime import datetime
from zoneinfo import ZoneInfo

SYD = ZoneInfo("Australia/Sydney")
BASE = os.path.expanduser("~/.wechat-summary")
CURSOR_FILE = os.environ.get(
    "WECHAT_ARCHIVE_CURSOR_FILE", os.path.join(BASE, "archive-cursor.json")
)
DIGEST_CURSOR_FILE = os.environ.get(
    "WECHAT_DIGEST_CURSOR_FILE", os.path.join(BASE, "digest-cursors.json")
)  # READ ONLY, never written
ARCHIVE_DIR = os.environ.get("WECHAT_ARCHIVE_DIR", os.path.join(BASE, "archive"))

sys.path.insert(0, os.path.expanduser("~/mac-wechat-summary"))


def _write_json_atomic(path: str, value: dict) -> None:
    parent = os.path.dirname(path) or "."
    os.makedirs(parent, exist_ok=True)
    fd, temp_path = tempfile.mkstemp(
        prefix=f".{os.path.basename(path)}.", dir=parent
    )
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=False, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)


def _write_text_atomic(path: str, body: str, mode: int = 0o644) -> None:
    """Replace a text file only after its complete contents are durable."""
    parent = os.path.dirname(path) or "."
    os.makedirs(parent, exist_ok=True)
    fd, temp_path = tempfile.mkstemp(
        prefix=f".{os.path.basename(path)}.", dir=parent
    )
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)


def _read_recovery_descriptor(path: str) -> dict:
    with open(path, encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError("recovery descriptor must be a JSON object")
    from_ts = value.get("from_ts")
    through_ts = value.get("through_ts")
    if not isinstance(from_ts, (int, float)) or from_ts < 0:
        raise ValueError("recovery descriptor has invalid from_ts")
    if not isinstance(through_ts, (int, float)) or through_ts < from_ts:
        raise ValueError("recovery descriptor has invalid through_ts")
    return value


def load_cursor(chat: str) -> float:
    """Own cursor; on first run, seed from digest cursor (read-only) for continuity."""
    if os.path.exists(CURSOR_FILE):
        with open(CURSOR_FILE) as f:
            data = json.load(f)
        if chat in data:
            return float(data[chat]["last_ts"])
    # First run for this chat: align with the digest cursor so the first slice
    # starts exactly where the next digest will start. Clamp to now — the
    # headless digest job has written future timestamps before (tz confusion),
    # and trusting one would make the first slice silently skip messages.
    now_ts = datetime.now(SYD).timestamp()
    if os.path.exists(DIGEST_CURSOR_FILE):
        try:
            with open(DIGEST_CURSOR_FILE) as f:
                d = json.load(f)
            if chat in d and "last_ts" in d[chat]:
                ts = float(d[chat]["last_ts"])
                if ts > now_ts:
                    print(f"archive-chat: digest cursor for {chat} is in the future "
                          f"({fmt(ts, '%Y-%m-%d %H:%M')} Sydney); seeding from now instead",
                          file=sys.stderr)
                    return now_ts
                return ts
        except Exception:
            pass
    return 0.0


def _has_own_cursor(chat: str) -> bool:
    if not os.path.exists(CURSOR_FILE):
        return False
    try:
        with open(CURSOR_FILE) as f:
            return chat in json.load(f)
    except Exception:
        return False


def save_cursor(chat: str, ts: float) -> None:
    data = {}
    if os.path.exists(CURSOR_FILE):
        with open(CURSOR_FILE) as f:
            data = json.load(f)
    data[chat] = {"last_ts": ts, "updated": datetime.now(SYD).isoformat()}
    tmp = CURSOR_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, CURSOR_FILE)


def fmt(ts: float, pattern: str) -> str:
    return datetime.fromtimestamp(ts, SYD).strftime(pattern)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--chat", default="可爱小克")
    ap.add_argument("--limit", type=int, default=10000,
                    help="maximum rows consumed per oldest-first chunk; "
                         "the archive loop keeps chunking until the window "
                         "is fully consumed, so this never truncates")
    ap.add_argument("--dry-run", action="store_true",
                    help="fetch + report label, but write nothing (no slice, no cursor)")
    ap.add_argument(
        "--descriptor-file",
        help="durably record exact recovery bounds before reading the database",
    )
    ap.add_argument(
        "--recover-descriptor",
        help="rebuild exactly the bounded slice described by a prior run",
    )
    ap.add_argument("--run-id", default="manual")
    args = ap.parse_args()

    descriptor = None
    if args.recover_descriptor:
        try:
            descriptor = _read_recovery_descriptor(args.recover_descriptor)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"archive-chat: invalid recovery descriptor: {exc}", file=sys.stderr)
            return 2
        if descriptor.get("chat") != args.chat:
            print("archive-chat: recovery descriptor chat mismatch", file=sys.stderr)
            return 2
        since_ts = float(descriptor["from_ts"])
        through_ts = float(descriptor["through_ts"])
    else:
        since_ts = load_cursor(args.chat)
        through_ts = datetime.now(SYD).timestamp()
        descriptor = {
            "schema_version": 1,
            "run_id": args.run_id,
            "chat": args.chat,
            "from_ts": since_ts,
            "through_ts": through_ts,
            "status": "pending",
            "created_at": datetime.now(SYD).isoformat(),
        }
        if args.descriptor_file:
            descriptor["descriptor_path"] = os.path.abspath(args.descriptor_file)
        if args.descriptor_file and not args.dry_run:
            _write_json_atomic(args.descriptor_file, descriptor)

    from core.config import load_config
    from core.key_extractor import get_cached_keys
    from core.wechat_db import WeChatDB

    cfg = load_config()
    keys = get_cached_keys()
    if not keys:
        print("archive-chat: no db keys", file=sys.stderr)
        return 1
    db = WeChatDB(cfg["db_dir"], keys)
    username = db.resolve_username(args.chat)
    if not username:
        print(f"archive-chat: chat not found: {args.chat}", file=sys.stderr)
        return 1

    messages = []
    for chunk in db.iter_messages_ascending(
        username,
        since_ts=since_ts,
        until_ts=through_ts,
        batch_size=max(args.limit, 1),
    ):
        messages.extend(chunk)
    # iter_messages_ascending() uses strict '>', matching digest cursor
    # semantics. Filter out system messages same as the MCP read_messages does.
    messages = [m for m in messages if m["type"] not in (10000, 10002)]
    if not messages:
        if args.dry_run:
            print(f"[dry-run] no new messages after {fmt(since_ts, '%Y-%m-%d %H:%M') if since_ts else 'epoch'}",
                  file=sys.stderr)
        elif args.recover_descriptor:
            save_cursor(args.chat, max(load_cursor(args.chat), through_ts))
        elif not _has_own_cursor(args.chat):
            # Persist the seed so the archive advances from a fixed point
            # instead of re-deriving (and possibly re-clamping) every run.
            save_cursor(args.chat, since_ts)
            print(f"archive-chat: initialized cursor at {fmt(since_ts, '%Y-%m-%d %H:%M')}",
                  file=sys.stderr)
        descriptor.update(
            {
                "status": "empty",
                "slice_id": None,
                "slice_window": None,
                "slice_label": None,
                "slice_path": None,
                "completed_at": datetime.now(SYD).isoformat(),
            }
        )
        target = args.descriptor_file or args.recover_descriptor
        if target and not args.dry_run:
            _write_json_atomic(target, descriptor)
        return 0

    start_ts = messages[0]["timestamp"]
    end_ts = messages[-1]["timestamp"]
    # Window label. Same-day: 07-11 13:06~15:04; cross-day: 07-11 23:30~07-12 01:10
    start_lbl = fmt(start_ts, "%m-%d %H:%M")
    if fmt(start_ts, "%Y-%m-%d") == fmt(end_ts, "%Y-%m-%d"):
        end_lbl = fmt(end_ts, "%H:%M")
    else:
        end_lbl = fmt(end_ts, "%m-%d %H:%M")
    window = f"{start_lbl}~{end_lbl}"
    label = f"{window} · {args.chat}"
    fname = f"{fmt(start_ts, '%Y-%m-%d_%H%M')}-{fmt(end_ts, '%H%M') if fmt(start_ts, '%Y%m%d') == fmt(end_ts, '%Y%m%d') else fmt(end_ts, '%m%d%H%M')}.md"

    if args.dry_run:
        print(f"[dry-run] {len(messages)} messages, would write "
              f"{os.path.join(ARCHIVE_DIR, args.chat, fname)}", file=sys.stderr)
        print(label)
        return 0

    chat_dir = os.path.join(ARCHIVE_DIR, args.chat)
    os.makedirs(chat_dir, exist_ok=True)
    path = os.path.join(chat_dir, fname)
    if os.path.exists(path):  # append-only guarantee: never overwrite
        path = os.path.join(chat_dir, fname.replace(".md", f"-{fmt(datetime.now(SYD).timestamp(), '%H%M%S')}.md"))

    lines = [
        "---",
        f"chat: {args.chat}",
        f"window: {window}",
        f"start_ts: {int(start_ts)}",
        f"end_ts: {int(end_ts)}",
        f"messages: {len(messages)}",
        "tz: Australia/Sydney",
        f"archived: {datetime.now(SYD).isoformat()}",
        "---",
        "",
    ]
    for m in messages:
        t = fmt(m["timestamp"], "%m-%d %H:%M")
        sender = m["sender"] or "?"
        lines.append(f"[{t}] {sender}: {m['text']}")
    # Write atomically with fsync + os.replace so a concurrent reader can
    # never observe a partially written canonical slice.
    body = "\n".join(lines) + "\n"
    _write_text_atomic(path, body)

    save_cursor(args.chat, end_ts)
    descriptor.update(
        {
            "status": "success",
            "slice_id": os.path.basename(path).removesuffix(".md"),
            "slice_window": window,
            "slice_label": label,
            "slice_path": os.path.relpath(path, BASE),
            "start_ts": start_ts,
            "end_ts": end_ts,
            "messages": len(messages),
            "completed_at": datetime.now(SYD).isoformat(),
        }
    )
    target = args.descriptor_file or args.recover_descriptor
    if target:
        descriptor["descriptor_path"] = os.path.abspath(target)
        _write_json_atomic(target, descriptor)
    print(f"archived {len(messages)} msgs -> {path}", file=sys.stderr)
    print(label)
    return 0


if __name__ == "__main__":
    sys.exit(main())
