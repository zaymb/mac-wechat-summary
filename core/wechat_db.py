"""
WeChat database queries - contacts, group chats, and message reading.
Based on the query logic from the wechat-decrypt project's mcp_server.py.
"""
import html
import hashlib
import heapq
import json
import os
import re
import sqlite3
import tempfile
from collections import defaultdict
from datetime import datetime
from pathlib import Path

import zstandard as zstd

try:
    from pysqlcipher3 import dbapi2 as _sqlcipher
    _HAS_SQLCIPHER = True
except ImportError:
    _HAS_SQLCIPHER = False

from .snapshot_cache import DecryptedSnapshotCache, SnapshotCacheError

_zstd_dctx = zstd.ZstdDecompressor()

_RE_APPMSG_TYPE = re.compile(r"<type>\s*(\d+)\s*</type>", re.DOTALL)

# WCDB's message sort key is a millisecond-scale sequence. A 50,000-row sample
# from the live database showed ``sort_seq >= create_time * 1000`` for every
# row (the observed suffix ranged from 0 to 6001). Queries keep create_time as
# the exact predicate; this coarse lower bound exists only to enter the
# SORTSEQ index near the durable cursor instead of scanning the whole shard.
_SORT_SEQ_PER_SECOND = 1000


def _sort_seq_lower_bound(timestamp):
    return max(0, int(float(timestamp) * _SORT_SEQ_PER_SECOND))


def _extract_xml_text(text, tag):
    """Extract and decode one simple XML element from an appmsg payload."""
    match = re.search(
        rf"<{re.escape(tag)}(?:\s[^>]*)?>(.*?)</{re.escape(tag)}>",
        text,
        re.DOTALL | re.IGNORECASE,
    )
    if not match:
        return ""
    value = match.group(1).strip()
    if value.startswith("<![CDATA[") and value.endswith("]]>"):
        value = value[9:-3]
    return html.unescape(value.strip())


def _extract_http_url(text):
    """Return a shareable http(s) URL from an appmsg, never file CDN tokens."""
    value = _extract_xml_text(text, "url")
    if re.match(r"^https?://", value, re.IGNORECASE):
        return value
    return ""


def _parse_file_appmsg(text):
    """Parse the stable metadata needed to locate a cached WeChat file."""
    type_match = _RE_APPMSG_TYPE.search(text or "")
    if not type_match or type_match.group(1) != "6":
        return None

    title = _extract_xml_text(text, "title")
    if not title:
        return None

    size_text = _extract_xml_text(text, "totallen")
    try:
        size = int(size_text)
    except (TypeError, ValueError):
        size = 0

    md5 = _extract_xml_text(text, "md5").lower()
    if not re.fullmatch(r"[0-9a-f]{32}", md5):
        md5 = ""

    return {
        "title": title,
        "size": size,
        "md5": md5,
        "fileext": _extract_xml_text(text, "fileext").lstrip("."),
    }


def _decode_message_content(content, compression_type):
    """Decode a WCDB message_content value, including zstd-compressed rows."""
    if compression_type == 4 and isinstance(content, bytes):
        try:
            return _zstd_dctx.decompress(content).decode("utf-8", errors="replace")
        except Exception:
            return None
    if isinstance(content, bytes):
        try:
            return content.decode("utf-8", errors="replace")
        except Exception:
            return None
    return content


def _clean_msg_text(text):
    """Clean WeChat message text, handle XML-formatted special messages.

    Converts pat-pat, quoted replies, images, stickers, etc. from XML to readable text.
    Plain text messages are returned as-is.

    Returns:
        str | None: Cleaned text, or None if the message should be skipped.
    """
    if not text:
        return None

    stripped = text.strip()

    # Plain text: return directly if not starting with <
    if not stripped.startswith("<"):
        return text

    # ── System messages (sysmsg) → skip ──
    if "<sysmsg" in stripped:
        return None

    # ── appmsg: quoted replies, links, files, pat ──
    if "<appmsg" in stripped:
        title = _extract_xml_text(stripped, "title")
        if title:
            type_match = _RE_APPMSG_TYPE.search(stripped)
            appmsg_type = type_match.group(1) if type_match else ""
            # Pat-pat: title contains "拍了拍"
            if "拍了拍" in title:
                return None
            # Quoted reply (type=57): extract title as reply content
            if appmsg_type == "57":
                return f"[回复] {title}"
            # File (type=6)
            if appmsg_type == "6":
                return f"[文件] {title}"
            # Link/article (type=5 or other)
            url = _extract_http_url(stripped)
            if url:
                return f"[链接] {title} — {url}"
            return f"[链接] {title}"
        return None

    # ── Image ──
    if "<img " in stripped or "<img>" in stripped:
        return "[图片]"

    # ── Sticker ──
    if "<emoji " in stripped or "<emoji>" in stripped:
        return "[表情]"

    # ── Voice ──
    if "<voicemsg " in stripped:
        return "[语音]"

    # ── Video ──
    if "<videomsg " in stripped:
        return "[视频]"

    # ── Other unrecognizable XML → skip ──
    if stripped.startswith("<?xml") or stripped.startswith("<msg"):
        return None

    # Other text: return as-is
    return text


class WeChatDB:
    """WeChat database query interface."""

    CACHE_DIR = os.path.join(tempfile.gettempdir(), "wechat_summary_cache")

    def __init__(self, db_dir, keys, cache_dir=None, diagnostic_sink=None):
        """
        Args:
            db_dir: WeChat db_storage directory path.
            keys: {rel_path: {"enc_key": hex}, ...} encryption key dictionary.
        """
        self.db_dir = db_dir
        self.keys = keys
        self._snapshot_cache = DecryptedSnapshotCache(
            db_dir,
            cache_dir=cache_dir or self.CACHE_DIR,
            diagnostic_sink=diagnostic_sink,
        )
        self._contacts = None  # {username: display_name}
        self._contacts_full = None  # [{username, nick_name, remark}]
        self._nick_to_remark = {}  # {nick_name: remark} reverse mapping for nickname→alias lookup
        self._emoticon_map = None  # {md5: {cdn_url, aes_key, thumb_url}}
        self._file_cache_by_size = None
        self._file_md5_cache = {}

    def invalidate_cache(self):
        """Clear process-local views; versioned disk snapshots stay reusable."""
        self._snapshot_cache.clear_memory()
        self._snapshot_cache.release_leases()
        self._contacts = None
        self._contacts_full = None
        self._nick_to_remark = {}
        self._emoticon_map = None

    def _get_key(self, rel_path):
        """Get database encryption key."""
        normalized = rel_path.replace("\\", "/")
        for candidate in (rel_path, normalized, normalized.replace("/", "\\")):
            if candidate in self.keys:
                return self.keys[candidate]["enc_key"]
        return None

    @staticmethod
    def _is_plain_sqlite(path):
        """Check if file is an unencrypted SQLite database."""
        try:
            with open(path, "rb") as f:
                return f.read(15) == b"SQLite format 3"
        except OSError:
            return False

    def _get_decrypted_db(self, rel_path):
        """Get decrypted database path (with caching).

        If the database is plaintext SQLite (unencrypted), returns the original path directly.
        """
        db_path = os.path.join(self.db_dir, rel_path)
        if not os.path.exists(db_path):
            return None

        # ── If plaintext SQLite, return original path directly ──
        if self._is_plain_sqlite(db_path):
            return db_path

        # ── Decryption needed ──
        enc_key = self._get_key(rel_path)
        if not enc_key:
            return None

        try:
            return self._snapshot_cache.get_snapshot(rel_path, enc_key)
        except (OSError, SnapshotCacheError) as exc:
            resource_id = self._snapshot_cache.resource_id(rel_path)
            print(
                f"[wechat-cache] snapshot unavailable resource={resource_id} "
                f"error={type(exc).__name__}",
                file=__import__("sys").stderr,
            )
            return None

    def _open_encrypted_conn(self, rel_path):
        """Open an encrypted DB directly via pysqlcipher3 (no full-file decrypt).

        Falls back to the old decrypt-to-file path when pysqlcipher3 is unavailable.
        Returns a sqlite3-compatible connection or None.
        """
        db_path = (
            rel_path
            if os.path.isabs(rel_path)
            else os.path.join(self.db_dir, rel_path)
        )
        if not os.path.exists(db_path):
            return None
        if self._is_plain_sqlite(db_path):
            return sqlite3.connect(db_path)
        if not _HAS_SQLCIPHER:
            decrypted = self._get_decrypted_db(rel_path)
            return sqlite3.connect(decrypted) if decrypted else None
        enc_key = self._get_key(rel_path)
        if not enc_key:
            return None
        conn = _sqlcipher.connect(db_path)
        conn.execute(f"PRAGMA key = \"x'{enc_key}'\"")
        conn.execute("PRAGMA cipher_compatibility = 4")
        conn.execute("PRAGMA cipher_page_size = 4096")
        return conn

    def _open_snapshot_conn(self, rel_path):
        """Open one immutable decrypted view of a live encrypted database.

        Direct SQLCipher reads are the fast path, but WeChat's live WAL can
        occasionally make a shard report ``database disk image is malformed``
        mid-scan.  The snapshot cache decrypts the matching DB+WAL version and
        publishes it only after the source stayed stable for the full build.
        """
        source = (
            rel_path
            if os.path.isabs(rel_path)
            else os.path.join(self.db_dir, rel_path)
        )
        snapshot = self._get_decrypted_db(rel_path)
        if not snapshot:
            return None
        if self._is_plain_sqlite(source):
            return sqlite3.connect(snapshot)
        uri = Path(snapshot).resolve().as_uri() + "?mode=ro&immutable=1"
        return sqlite3.connect(uri, uri=True)

    def _load_contacts(self):
        """Load contacts."""
        if self._contacts is not None:
            return

        path = self._get_decrypted_db(os.path.join("contact", "contact.db"))
        if not path:
            self._contacts = {}
            self._contacts_full = []
            self._nick_to_remark = {}
            return

        names = {}
        full = []
        nick_to_remark = {}  # nickname → alias (reverse mapping for looking up alias by nickname in group messages)
        conn = sqlite3.connect(path)
        try:
            for r in conn.execute("SELECT username, nick_name, remark FROM contact"):
                uname, nick, remark = r
                display = remark if remark else nick if nick else uname
                names[uname] = display
                full.append({"username": uname, "nick_name": nick or "", "remark": remark or ""})
                # If alias exists, build nickname→alias reverse mapping
                if remark and nick:
                    nick_to_remark[nick] = remark
        except Exception as e:
            print(f"[wechat_db] warning: 加载联系人失败: {e}", file=__import__('sys').stderr)
        finally:
            conn.close()

        self._contacts = names
        self._contacts_full = full
        self._nick_to_remark = nick_to_remark

    def _load_emoticon_db(self):
        """Lazy-load emoticon.db to build md5→CDN URL mapping for stickers."""
        if self._emoticon_map is not None:
            return
        self._emoticon_map = {}
        path = self._get_decrypted_db(os.path.join("emoticon", "emoticon.db"))
        if not path:
            return
        try:
            conn = sqlite3.connect(path)
            rows = conn.execute(
                "SELECT md5, cdn_url, aes_key, thumb_url"
                " FROM kNonStoreEmoticonTable"
            ).fetchall()
            for md5, cdn, aes, thumb in rows:
                if md5 and cdn:
                    self._emoticon_map[md5] = {
                        "cdn_url": cdn.replace("&amp;", "&"),
                        "aes_key": aes or "",
                        "thumb_url": (thumb or "").replace("&amp;", "&"),
                    }
            conn.close()
        except Exception:
            pass

    def get_groups(self, include_unnamed=False):
        """Get all group chats list.

        Args:
            include_unnamed: Whether to include unnamed groups (those displaying raw IDs).

        Returns:
            list[dict]: [{"username": "xxx@chatroom", "name": "group name"}, ...]
        """
        self._load_contacts()
        groups = []
        unnamed_idx = 0
        for c in self._contacts_full:
            if "@chatroom" in c["username"]:
                name = c["remark"] or c["nick_name"] or c["username"]
                if name == c["username"]:
                    if include_unnamed:
                        unnamed_idx += 1
                        groups.append({"username": c["username"],
                                       "name": f"无名称群{unnamed_idx}"})
                    else:
                        # Check for messages; if found, keep and assign number
                        msgs = self.get_messages(c["username"], limit=1)
                        if msgs:
                            unnamed_idx += 1
                            groups.append({"username": c["username"],
                                           "name": f"无名称群{unnamed_idx}"})
                else:
                    groups.append({"username": c["username"], "name": name})
        return groups

    def get_recent_sessions(self, limit=200):
        """Get recent sessions (groups and private chats)."""
        path = self._get_decrypted_db(os.path.join("session", "session.db"))
        if not path:
            return []

        self._load_contacts()
        conn = sqlite3.connect(path)
        try:
            rows = conn.execute("""
                SELECT username, unread_count, summary, last_timestamp
                FROM SessionTable
                WHERE last_timestamp > 0
                ORDER BY last_timestamp DESC
                LIMIT ?
            """, (limit,)).fetchall()
        except Exception:
            return []
        finally:
            conn.close()

        sessions = []
        unnamed_idx = 0
        for username, unread, summary, ts in rows:
            display = self._contacts.get(username, username)
            is_group = "@chatroom" in username

            # Unnamed group: has SessionTable record indicating activity, show with number
            if is_group and display == username:
                unnamed_idx += 1
                display = f"无名称群{unnamed_idx}"

            if isinstance(summary, bytes):
                try:
                    summary = _zstd_dctx.decompress(summary).decode("utf-8", errors="replace")
                except Exception:
                    summary = ""
            if isinstance(summary, str) and ":\n" in summary:
                summary = summary.split(":\n", 1)[1]

            sessions.append({
                "username": username,
                "name": display,
                "is_group": is_group,
                "unread": unread or 0,
                "summary": summary or "",
                "timestamp": ts,
                "time_str": datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M"),
            })

        return sessions

    def _find_msg_table(self, username):
        """Find all databases containing a user's message table.

        When pysqlcipher3 is available, opens encrypted DBs directly (no full
        decrypt). Falls back to the old snapshot-cache path otherwise.

        Returns:
            (list[str], str): (rel_keys, table_name), returns ([], None) if not found.
            The rel_keys are database-relative paths suitable for _open_encrypted_conn.
        """
        table_hash = hashlib.md5(username.encode()).hexdigest()
        table_name = f"Msg_{table_hash}"

        msg_keys = sorted([
            k for k in self.keys
            if re.search(r"message[/\\](?:biz_)?message_\d+\.db$", k.replace("\\", "/"))
        ])

        mapped_keys = self._snapshot_cache.get_message_shards(username, msg_keys)
        if mapped_keys is not None:
            mapping_valid = True
            for rel_key in mapped_keys:
                conn = self._open_encrypted_conn(rel_key)
                if not conn:
                    mapping_valid = False
                    break
                try:
                    exists = conn.execute(
                        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                        (table_name,),
                    ).fetchone()
                except Exception:
                    exists = None
                finally:
                    conn.close()
                if not exists:
                    mapping_valid = False
                    break
            if mapping_valid:
                return mapped_keys, table_name
            self._snapshot_cache.forget_message_shards(username)

        found_keys = []
        for rel_key in msg_keys:
            conn = self._open_encrypted_conn(rel_key)
            if not conn:
                continue
            try:
                exists = conn.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                    (table_name,),
                ).fetchone()
                if exists:
                    found_keys.append(rel_key)
            except Exception:
                pass
            finally:
                conn.close()

        self._snapshot_cache.put_message_shards(
            username,
            msg_keys,
            found_keys,
        )

        if found_keys:
            return found_keys, table_name
        return [], None

    def count_messages_since(self, username, since_ts):
        """Quick count of new messages since since_ts.

        Returns:
            int: Number of new messages, -1 on query failure.
        """
        rel_keys, table_name = self._find_msg_table(username)
        if not rel_keys:
            return -1

        total = 0
        for rel_key in rel_keys:
            conn = self._open_encrypted_conn(rel_key)
            if not conn:
                continue
            try:
                row = conn.execute(
                    f"""
                    SELECT COUNT(*) FROM [{table_name}]
                    WHERE sort_seq >= ? AND create_time > ?
                    """,
                    (_sort_seq_lower_bound(since_ts), since_ts),
                ).fetchone()
                total += row[0] if row else 0
            except Exception:
                pass
            finally:
                conn.close()
        return total

    def get_messages(self, username, since_ts=0, until_ts=None, limit=500):
        """Get group/private chat messages.

        Args:
            username: Username or group chat ID (xxx@chatroom).
            since_ts: Start timestamp (only get messages after this time).
            until_ts: Optional inclusive upper timestamp for bounded recovery.
            limit: Maximum number of messages.

        Returns:
            list[dict]: [{"sender": "name", "text": "content", "timestamp": ts, "type": int}, ...]
        """
        self._load_contacts()
        is_group = "@chatroom" in username

        rel_keys, table_name = self._find_msg_table(username)
        if not rel_keys:
            return []

        all_rows = []
        for rel_key in rel_keys:
            conn = self._open_encrypted_conn(rel_key)
            if not conn:
                continue
            try:
                if since_ts > 0 and until_ts is not None:
                    rows = conn.execute(f"""
                        SELECT local_type, create_time, message_content,
                               WCDB_CT_message_content, status
                        FROM [{table_name}]
                        WHERE sort_seq >= ?
                          AND create_time > ? AND create_time <= ?
                        ORDER BY sort_seq DESC
                        LIMIT ?
                    """, (
                        _sort_seq_lower_bound(since_ts),
                        since_ts,
                        until_ts,
                        limit * 2,
                    )).fetchall()
                elif since_ts > 0:
                    rows = conn.execute(f"""
                        SELECT local_type, create_time, message_content,
                               WCDB_CT_message_content, status
                        FROM [{table_name}]
                        WHERE sort_seq >= ? AND create_time > ?
                        ORDER BY sort_seq DESC
                        LIMIT ?
                    """, (
                        _sort_seq_lower_bound(since_ts),
                        since_ts,
                        limit * 2,
                    )).fetchall()
                elif until_ts is not None:
                    rows = conn.execute(f"""
                        SELECT local_type, create_time, message_content,
                               WCDB_CT_message_content, status
                        FROM [{table_name}]
                        WHERE create_time <= ?
                        ORDER BY sort_seq DESC
                        LIMIT ?
                    """, (until_ts, limit)).fetchall()
                else:
                    rows = conn.execute(f"""
                        SELECT local_type, create_time, message_content,
                               WCDB_CT_message_content, status
                        FROM [{table_name}]
                        ORDER BY sort_seq DESC
                        LIMIT ?
                    """, (limit,)).fetchall()
                all_rows.extend(rows)
            except Exception:
                pass
            finally:
                conn.close()

        if not all_rows:
            return []

        # Sort by time, take the latest limit entries
        all_rows.sort(key=lambda r: r[1])  # r[1] = create_time
        rows = all_rows[-limit:]

        return self._messages_from_rows(rows, username, "chatroom" in username)

    def _iter_msg_rows_ascending_shard(self, table_name, rel_key, after_ts,
                                       until_ts, batch_size):
        """Stream one message shard by the indexed (sort_seq, rowid) key."""
        conn = self._open_encrypted_conn(rel_key)
        if not conn:
            raise RuntimeError(f"cannot open message shard: {rel_key}")
        using_snapshot = False
        exact_after_ts = float(after_ts)
        cursor_sort_seq = None
        cursor_rowid = None
        try:
            while True:
                if cursor_rowid is None:
                    where = "sort_seq >= ? AND create_time > ?"
                    params = [
                        _sort_seq_lower_bound(exact_after_ts),
                        exact_after_ts,
                    ]
                else:
                    where = (
                        "(sort_seq, rowid) > (?, ?) "
                        "AND create_time > ?"
                    )
                    params = [
                        cursor_sort_seq,
                        cursor_rowid,
                        exact_after_ts,
                    ]
                if until_ts is not None:
                    where += " AND create_time <= ?"
                    params.append(until_ts)
                params.append(batch_size)
                query = f"""
                    SELECT sort_seq, rowid, local_type, create_time, message_content,
                           WCDB_CT_message_content, status
                    FROM [{table_name}]
                    WHERE {where}
                    ORDER BY sort_seq ASC, rowid ASC
                    LIMIT ?
                """
                try:
                    rows = conn.execute(query, params).fetchall()
                except Exception:
                    if using_snapshot:
                        raise
                    conn.close()
                    conn = self._open_snapshot_conn(rel_key)
                    if not conn:
                        raise
                    using_snapshot = True
                    rows = conn.execute(query, params).fetchall()
                if not rows:
                    return
                for row in rows:
                    yield row
                if len(rows) < batch_size:
                    return
                cursor_sort_seq = rows[-1][0]
                cursor_rowid = rows[-1][1]
        finally:
            conn.close()

    def iter_messages_ascending(self, username, since_ts=0.0, until_ts=None,
                                batch_size=1000):
        """Yield oldest-first lists of messages in bounded batches.

        Unlike get_messages(), which keeps only the newest ``limit`` rows and
        silently drops anything older, this walks forward from ``since_ts``
        so a caller with its own durable cursor can consume arbitrarily large
        backlogs without gaps and without ever jumping past unwritten
        messages. Each yielded batch contains at most ~batch_size entries;
        rows sharing the boundary timestamp are always kept together in one
        batch so pagination can never skip them.
        """
        self._load_contacts()
        is_group = "@chatroom" in username

        rel_keys, table_name = self._find_msg_table(username)
        if not rel_keys:
            return

        if batch_size < 1:
            raise ValueError("batch_size must be positive")
        streams = [
            self._iter_msg_rows_ascending_shard(
                table_name, rel_key, since_ts, until_ts, batch_size
            )
            for rel_key in rel_keys
        ]
        merged_rows = heapq.merge(*streams, key=lambda row: (row[0], row[1]))
        while True:
            batch = []
            try:
                for _ in range(batch_size):
                    batch.append(next(merged_rows)[2:])
            except StopIteration:
                pass
            if not batch:
                return
            messages = self._messages_from_rows(batch, username, is_group)
            if messages:
                yield messages
            if len(batch) < batch_size:
                return

    def _messages_from_rows(self, rows, username, is_group):
        """Convert raw DB rows into message dicts (shared by readers)."""
        # In private chat, label counterpart's messages with display name
        contact_name = ""
        if not is_group:
            contact_name = self._contacts.get(username, username)

        messages = []
        for local_type, create_time, content, ct, status in rows:
            # zstd decompression
            if ct and ct == 4 and isinstance(content, bytes):
                try:
                    content = _zstd_dctx.decompress(content).decode("utf-8", errors="replace")
                except Exception:
                    content = None
            elif isinstance(content, bytes):
                try:
                    content = content.decode("utf-8", errors="replace")
                except Exception:
                    content = None

            if content is None:
                continue

            sender = ""
            raw_sender_id = ""
            text = content
            if is_group and ":\n" in content:
                raw_sender_id, text = content.split(":\n", 1)
                # Prefer wxid lookup (alias > nickname); fall back to nickname→alias reverse lookup
                sender = self._contacts.get(raw_sender_id)
                if not sender:
                    sender = self._nick_to_remark.get(raw_sender_id, raw_sender_id)
            elif not is_group:
                # Private chat: status=2 = sent by me, status=3 = received
                sender = "我" if status == 2 else contact_name

            # In group chat, own messages lack wxid:\n prefix, sender will be empty
            if is_group and not sender:
                sender = "您"

            # Clean XML special messages
            cleaned = _clean_msg_text(text)
            if cleaned is None:
                continue
            text = cleaned

            messages.append({
                "sender": sender,
                "raw_sender_id": raw_sender_id,
                "text": text,
                "timestamp": create_time,
                "time_str": datetime.fromtimestamp(create_time).strftime("%Y-%m-%d %H:%M"),
                "type": local_type,
            })

        return messages

    def _build_file_cache_index(self):
        """Index WeChat's already-downloaded generic file cache by byte size."""
        if self._file_cache_by_size is not None:
            return self._file_cache_by_size

        by_size = defaultdict(list)
        file_root = os.path.join(os.path.dirname(self.db_dir), "msg", "file")
        if os.path.isdir(file_root):
            for root, _dirs, names in os.walk(file_root):
                for name in names:
                    path = os.path.join(root, name)
                    try:
                        if os.path.isfile(path):
                            by_size[os.path.getsize(path)].append(path)
                    except OSError:
                        continue
        self._file_cache_by_size = by_size
        return by_size

    def _cached_file_md5(self, path):
        try:
            stat = os.stat(path)
        except OSError:
            return ""
        cache_key = (path, stat.st_size, stat.st_mtime_ns)
        if cache_key in self._file_md5_cache:
            return self._file_md5_cache[cache_key]

        digest = hashlib.md5()
        try:
            with open(path, "rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
        except OSError:
            return ""
        value = digest.hexdigest()
        self._file_md5_cache[cache_key] = value
        return value

    def _find_cached_file(self, metadata, create_time):
        """Match appmsg metadata to a file in WeChat's local cache."""
        size = metadata.get("size") or 0
        if size <= 0:
            return None

        candidates = list(self._build_file_cache_index().get(size, ()))
        if not candidates:
            return None
        candidates.sort(
            key=lambda path: abs(os.path.getmtime(path) - create_time)
            if os.path.exists(path)
            else float("inf")
        )

        expected_md5 = metadata.get("md5") or ""
        if expected_md5:
            for path in candidates:
                if self._cached_file_md5(path) == expected_md5:
                    return path
            return None

        # Older appmsg rows can omit md5. In that case, require a very close
        # timestamp and matching extension rather than guessing by size alone.
        expected_ext = metadata.get("fileext") or ""
        for path in candidates:
            try:
                if abs(os.path.getmtime(path) - create_time) > 60:
                    continue
            except OSError:
                continue
            actual_ext = os.path.splitext(path)[1].lstrip(".")
            if expected_ext and actual_ext.lower() != expected_ext.lower():
                continue
            return path
        return None

    def find_cached_file(self, metadata, create_time):
        """Public cache lookup used by the idempotent file collector."""
        return self._find_cached_file(metadata, create_time)

    def get_file_messages(
        self,
        username,
        since_ts=0,
        limit=10000,
        include_scan_watermark=False,
    ):
        """Read file-share messages and resolve already-downloaded cache paths.

        Rows are consumed oldest-first so callers can keep an independent,
        lossless cursor even when a chat has more than ``limit`` new messages.
        ``include_scan_watermark`` returns ``(files, latest_scanned_ts)``;
        the watermark advances across non-file messages too.
        """
        self._load_contacts()
        is_group = "@chatroom" in username
        rel_keys, table_name = self._find_msg_table(username)
        if not rel_keys:
            result = ([], since_ts) if include_scan_watermark else []
            return result

        all_rows = []
        for rel_key in rel_keys:
            conn = self._open_encrypted_conn(rel_key)
            if not conn:
                continue
            try:
                rows = conn.execute(
                    f"""
                    SELECT local_type, create_time, message_content,
                           WCDB_CT_message_content, status
                    FROM [{table_name}]
                    WHERE sort_seq >= ? AND create_time > ?
                    ORDER BY sort_seq ASC
                    LIMIT ?
                    """,
                    (_sort_seq_lower_bound(since_ts), since_ts, limit),
                ).fetchall()
                all_rows.extend(rows)
            except Exception:
                pass
            finally:
                conn.close()

        all_rows.sort(key=lambda row: row[1])
        rows = all_rows[:limit]
        watermark = rows[-1][1] if rows else since_ts

        contact_name = ""
        if not is_group:
            contact_name = self._contacts.get(username, username)

        messages = []
        for local_type, create_time, content, compression_type, status in rows:
            content = _decode_message_content(content, compression_type)
            if not content:
                continue

            sender = ""
            raw_sender_id = ""
            text = content
            if is_group and ":\n" in content:
                raw_sender_id, text = content.split(":\n", 1)
                sender = self._contacts.get(raw_sender_id)
                if not sender:
                    sender = self._nick_to_remark.get(raw_sender_id, raw_sender_id)
            elif not is_group:
                sender = "我" if status == 2 else contact_name
            if is_group and not sender:
                sender = "您"

            metadata = _parse_file_appmsg(text)
            if not metadata:
                continue

            messages.append({
                "sender": sender,
                "raw_sender_id": raw_sender_id,
                "title": metadata["title"],
                "size": metadata["size"],
                "md5": metadata["md5"],
                "fileext": metadata["fileext"],
                "timestamp": create_time,
                "time_str": datetime.fromtimestamp(create_time).strftime(
                    "%Y-%m-%d %H:%M"
                ),
                "type": local_type,
                "cache_path": self._find_cached_file(metadata, create_time),
            })

        if include_scan_watermark:
            return messages, watermark
        return messages

    def _get_fts_db(self):
        """Get decrypted FTS full-text search database path."""
        return self._get_decrypted_db("message/message_fts.db")

    def _build_fts_lookup(self, fts_conn):
        """Build FTS helper mapping tables.

        Returns:
            (name2id, id2name, id2sender_name)
            - name2id: {username: session_id}
            - id2name: {session_id: username}
            - id2sender_name: {sender_id: display_name}
        """
        self._load_contacts()
        name2id = {}
        id2name = {}
        id2sender_name = {}

        for row in fts_conn.execute("SELECT rowid, username FROM name2id"):
            rid, uname = row
            name2id[uname] = rid
            id2name[rid] = uname
            # Parse sender display name
            display = self._contacts.get(uname, uname)
            id2sender_name[rid] = display

        return name2id, id2name, id2sender_name

    def search_messages(self, keywords, usernames, start_ts, end_ts, limit_per_group=2000):
        """Cross-chat message search (AND boolean search + sliding window).

        Prefers FTS full-text search database (covers all historical messages).
        Falls back to direct database scan if FTS is unavailable.
        Only reads decrypted cache copies, never touches original WeChat databases.

        Args:
            keywords: list[str] - Keyword list (already split by spaces).
            usernames: list[str] - List of group chat usernames to search.
            start_ts: int/float - Start timestamp.
            end_ts: int/float - End timestamp.
            limit_per_group: int - Max messages to retrieve per group.

        Returns:
            dict: {username: [{"sender", "text", "timestamp", "time_str", "group_name"}]}
        """
        # Try FTS search (covers all historical data)
        fts_path = self._get_fts_db()
        if fts_path:
            print("[search] 使用 FTS 全文索引搜索（覆盖全部历史数据）")
            return self._search_via_fts(fts_path, keywords, usernames, start_ts, end_ts, limit_per_group)

        # FTS unavailable, fall back to direct database search
        print("[search] FTS 不可用，回退到直接数据库搜索")
        return self._search_via_db(keywords, usernames, start_ts, end_ts, limit_per_group)

    def _search_via_fts(self, fts_path, keywords, usernames, start_ts, end_ts, limit_per_group=2000):
        """Search messages via FTS full-text search database.

        The FTS database contains full-text indexes of all messages, independent of
        message database decryption keys, covering all historical messages (back to 2022).
        """
        self._load_contacts()
        results = {}

        fts_conn = sqlite3.connect(fts_path, timeout=5)
        try:
            name2id, id2name, id2sender_name = self._build_fts_lookup(fts_conn)
        except Exception as e:
            print(f"[search] FTS 映射表构建失败: {e}", file=__import__('sys').stderr)
            fts_conn.close()
            return results

        try:
            return self._search_fts_inner(
                fts_conn, name2id, id2name, id2sender_name,
                keywords, usernames, start_ts, end_ts, limit_per_group,
            )
        finally:
            fts_conn.close()

    def _search_fts_inner(self, fts_conn, name2id, id2name, id2sender_name,
                          keywords, usernames, start_ts, end_ts, limit_per_group):
        results = {}

        # Preprocess keywords
        keywords_lower = [kw.lower() for kw in keywords]

        # Build set of session_ids to search
        target_sessions = {}  # session_id → username
        for uname in usernames:
            sid = name2id.get(uname)
            if sid is not None:
                target_sessions[sid] = uname
            else:
                group_name = self._contacts.get(uname, uname)
                print(f"[search]   ⚠ {group_name}: 不在 FTS 索引中")

        print(f"[search] 正在搜索 {len(target_sessions)} 个群聊...")

        # FTS has 4 content shard tables (message_fts_v4_0_content ~ _3_content)
        # Schema: id, c0(acontent), c1(message_local_id), c2(sort_seq),
        #         c3(local_type), c4(session_id), c5(sender_id), c6(create_time)
        FTS_TABLES = [f"message_fts_v4_{i}_content" for i in range(4)]

        for idx, (sid, uname) in enumerate(target_sessions.items()):
            group_name = self._contacts.get(uname, uname)
            print(f"[search]   ({idx+1}/{len(target_sessions)}) 搜索 {group_name}...")

            # Collect messages from all FTS shards
            all_msgs = []
            total_rows = 0
            for tbl in FTS_TABLES:
                try:
                    rows = fts_conn.execute(f"""
                        SELECT c0, c5, c6 FROM [{tbl}]
                        WHERE c4 = ? AND c6 >= ? AND c6 <= ?
                        ORDER BY c6 ASC
                        LIMIT ?
                    """, (sid, int(start_ts), int(end_ts), limit_per_group)).fetchall()
                except Exception:
                    continue

                total_rows += len(rows)
                for text, sender_id, create_time in rows:
                    if not text or not create_time:
                        continue
                    # FTS content is already cleaned text, no XML processing needed
                    sender = id2sender_name.get(sender_id, str(sender_id))
                    all_msgs.append({
                        "sender": sender,
                        "text": text,
                        "text_lower": text.lower(),
                        "timestamp": create_time,
                        "time_str": datetime.fromtimestamp(create_time).strftime("%Y-%m-%d %H:%M"),
                        "group_name": group_name,
                    })

            # Sort by time (messages from different shards need merge sort)
            all_msgs.sort(key=lambda m: m["timestamp"])

            # Limit max messages per group
            if len(all_msgs) > limit_per_group:
                all_msgs = all_msgs[:limit_per_group]

            if not all_msgs:
                if total_rows > 0:
                    print(f"[search]   · {group_name}: 该时间段无文本消息")
                else:
                    print(f"[search]   · {group_name}: 该时间段无消息")
                continue

            print(f"[search]     {total_rows} 条记录 → {len(all_msgs)} 条文本")

            # Sliding window search (1 msg above + below = 3 msg window)
            CONTEXT = 1
            matched_indices = set()
            for i in range(len(all_msgs)):
                win_start = max(0, i - CONTEXT)
                win_end = min(len(all_msgs), i + CONTEXT + 1)
                combined = " ".join(all_msgs[j]["text_lower"] for j in range(win_start, win_end))
                if all(kw in combined for kw in keywords_lower):
                    for j in range(win_start, win_end):
                        matched_indices.add(j)

            matched = []
            for mi in sorted(matched_indices):
                msg = all_msgs[mi]
                matched.append({
                    "sender": msg["sender"],
                    "text": msg["text"],
                    "timestamp": msg["timestamp"],
                    "time_str": msg["time_str"],
                    "group_name": msg["group_name"],
                })

            if matched:
                results[uname] = matched
                print(f"[search]   ✓ {group_name}: {len(matched)} 条命中（共扫描 {total_rows} 条）")
            else:
                print(f"[search]   · {group_name}: 扫描 {len(all_msgs)} 条，无命中")

        total_hits = sum(len(msgs) for msgs in results.values())
        print(f"[search] ✅ 搜索完成，共命中 {total_hits} 条消息，涉及 {len(results)} 个群")
        return results

    def _search_via_db(self, keywords, usernames, start_ts, end_ts, limit_per_group=2000):
        """Direct database scan search (fallback when FTS unavailable)."""
        self._load_contacts()
        results = {}

        # Pre-build username → (db_path, table_name) mapping
        table_cache = {}
        total = len(usernames)
        print(f"[search] 正在定位 {total} 个群聊的消息表...")
        for i, username in enumerate(usernames):
            rel_keys, table_name = self._find_msg_table(username)
            if rel_keys:
                table_cache[username] = (rel_keys, table_name)
        print(f"[search] 定位完成，{len(table_cache)}/{total} 个群有消息表")

        keywords_lower = [kw.lower() for kw in keywords]

        for i, username in enumerate(table_cache):
            is_group = "@chatroom" in username
            group_name = self._contacts.get(username, username)
            rel_keys, table_name = table_cache[username]

            print(f"[search]   ({i+1}/{len(table_cache)}) 搜索 {group_name}...")

            rows = []
            for rel_key in rel_keys:
                conn = self._open_encrypted_conn(rel_key)
                if not conn:
                    continue
                try:
                    r = conn.execute(f"""
                        SELECT local_type, create_time, message_content,
                               WCDB_CT_message_content
                        FROM [{table_name}]
                        WHERE create_time >= ? AND create_time <= ?
                        ORDER BY create_time ASC
                    """, (int(start_ts), int(end_ts))).fetchall()
                    rows.extend(r)
                except Exception as e:
                    print(f"[search]   ⚠ {group_name} 查询失败: {e}")
                finally:
                    conn.close()

            # Sort by time after multi-DB merge (context window depends on order)
            rows.sort(key=lambda r: r[1])

            if not rows:
                continue

            all_msgs = []
            for local_type, create_time, content, ct in rows:
                if ct and ct == 4 and isinstance(content, bytes):
                    try:
                        content = _zstd_dctx.decompress(content).decode("utf-8", errors="replace")
                    except Exception:
                        continue
                elif isinstance(content, bytes):
                    try:
                        content = content.decode("utf-8", errors="replace")
                    except Exception:
                        continue

                if content is None:
                    continue

                sender = ""
                text = content
                if is_group and ":\n" in content:
                    sender, text = content.split(":\n", 1)
                    sender = self._contacts.get(sender, sender)

                text = _clean_msg_text(text)
                if text is None:
                    continue

                all_msgs.append({
                    "sender": sender,
                    "text": text,
                    "text_lower": text.lower(),
                    "timestamp": create_time,
                    "time_str": datetime.fromtimestamp(create_time).strftime("%Y-%m-%d %H:%M"),
                    "group_name": group_name,
                })

            print(f"[search]     {len(rows)} 条记录 → {len(all_msgs)} 条文本")

            CONTEXT = 1
            matched_indices = set()
            for i in range(len(all_msgs)):
                win_start = max(0, i - CONTEXT)
                win_end = min(len(all_msgs), i + CONTEXT + 1)
                combined = " ".join(all_msgs[j]["text_lower"] for j in range(win_start, win_end))
                if all(kw in combined for kw in keywords_lower):
                    for j in range(win_start, win_end):
                        matched_indices.add(j)

            matched = []
            for idx in sorted(matched_indices):
                msg = all_msgs[idx]
                matched.append({
                    "sender": msg["sender"],
                    "text": msg["text"],
                    "timestamp": msg["timestamp"],
                    "time_str": msg["time_str"],
                    "group_name": msg["group_name"],
                })

            if matched:
                results[username] = matched
                print(f"[search]   ✓ {group_name}: {len(matched)} 条命中（共扫描 {len(rows)} 条）")
            elif rows:
                print(f"[search]   · {group_name}: 扫描 {len(rows)} 条，无命中")
            else:
                print(f"[search]   · {group_name}: 该时间段无文本消息")

        total_hits = sum(len(msgs) for msgs in results.values())
        print(f"[search] ✅ 搜索完成，共命中 {total_hits} 条消息，涉及 {len(results)} 个群")
        return results

    def get_fts_coverage(self, usernames):
        """Get data coverage range per chat in FTS.

        Args:
            usernames: list[str] - List of chat usernames.

        Returns:
            dict: {username: {"earliest": timestamp, "latest": timestamp, "count": int}}
                  If FTS is unavailable or chat has no data, the username is absent from results.
        """
        fts_path = self._get_fts_db()
        if not fts_path:
            return {}

        fts_conn = sqlite3.connect(fts_path, timeout=5)
        try:
            name2id = dict(fts_conn.execute("SELECT username, rowid FROM name2id").fetchall())
        except Exception:
            fts_conn.close()
            return {}

        try:
            coverage = {}
            FTS_TABLES = [f"message_fts_v4_{i}_content" for i in range(4)]

            for uname in usernames:
                sid = name2id.get(uname)
                if sid is None:
                    continue
                earliest = None
                latest = None
                total = 0
                for tbl in FTS_TABLES:
                    try:
                        row = fts_conn.execute(
                            f"SELECT MIN(c6), MAX(c6), COUNT(*) FROM [{tbl}] WHERE c4 = ?",
                            (sid,),
                        ).fetchone()
                        if row[2] > 0:
                            total += row[2]
                            if row[0] and (earliest is None or row[0] < earliest):
                                earliest = row[0]
                            if row[1] and (latest is None or row[1] > latest):
                                latest = row[1]
                    except Exception:
                        continue
                if total > 0:
                    coverage[uname] = {"earliest": earliest, "latest": latest, "count": total}

            return coverage
        finally:
            fts_conn.close()

    def resolve_username(self, name):
        """Resolve group name / alias / nickname to username."""
        self._load_contacts()
        if name in self._contacts or "@chatroom" in name:
            return name
        name_lower = name.lower()
        # Exact match
        for uname, display in self._contacts.items():
            if name_lower == display.lower():
                return uname
        # Fuzzy match
        for uname, display in self._contacts.items():
            if name_lower in display.lower():
                return uname
        return None

    # ── Image message utilities ─────────────────────────────────────

    @staticmethod
    def _extract_file_hash_from_protobuf(data):
        """Extract 32-char hex file hash from packed_info_data protobuf.

        Manually parses protobuf wire format (including nested sub-messages),
        looking for 32-byte ASCII hex strings or 16-byte raw hashes.

        Returns:
            str | None: 32-char hex hash, or None.
        """
        if not data or len(data) < 10:
            return None

        def _scan(buf, depth=0):
            """Recursively scan protobuf fields."""
            if depth > 3:
                return []
            pos = 0
            found = []
            while pos < len(buf):
                try:
                    tag_byte = buf[pos]
                    wire_type = tag_byte & 0x07
                    pos += 1
                    if tag_byte & 0x80:
                        while pos < len(buf) and buf[pos] & 0x80:
                            pos += 1
                        pos += 1

                    if wire_type == 0:  # varint
                        while pos < len(buf) and buf[pos] & 0x80:
                            pos += 1
                        pos += 1
                    elif wire_type == 1:
                        pos += 8
                    elif wire_type == 5:
                        pos += 4
                    elif wire_type == 2:  # length-delimited
                        length = 0
                        shift = 0
                        while pos < len(buf):
                            b = buf[pos]
                            length |= (b & 0x7F) << shift
                            pos += 1
                            if not (b & 0x80):
                                break
                            shift += 7
                        if pos + length > len(buf):
                            break
                        field_data = buf[pos:pos + length]
                        pos += length

                        if length == 32:
                            try:
                                ascii_str = field_data.decode("ascii")
                                bytes.fromhex(ascii_str)
                                found.append(ascii_str)
                                continue
                            except (UnicodeDecodeError, ValueError):
                                pass
                        if length == 16 and not all(b == 0 for b in field_data):
                            found.append(field_data.hex())
                            continue
                        # Recursively parse sub-messages
                        if length > 10:
                            found.extend(_scan(field_data, depth + 1))
                    else:
                        break
                except (IndexError, ValueError):
                    break
            return found

        candidates = _scan(data)
        return candidates[0] if candidates else None

    def _get_attach_base_dir(self):
        """Derive msg/attach image attachment directory from db_dir.

        db_dir = .../xwechat_files/{wxid}/db_storage
        attach = .../xwechat_files/{wxid}/msg/attach
        """
        wxid_dir = os.path.dirname(self.db_dir)
        attach_dir = os.path.join(wxid_dir, "msg", "attach")
        return attach_dir if os.path.isdir(attach_dir) else None

    def _find_image_file(self, username, create_time, file_hash=None, prefer_thumbnail=True):
        """Locate image file on disk.

        Primary strategy: look up by file_hash in attach/{md5(username)}/{YYYY-MM}/Img/{hash}_M.dat
        Fallback: match by file modification time (closest file within +/-60 seconds).

        Args:
            username: Chat username.
            create_time: Message timestamp.
            file_hash: 32-char hex hash extracted from packed_info_data.
            prefer_thumbnail: Whether to prefer returning thumbnails.

        Returns:
            str | None: Absolute path to image file.
        """
        attach_base = self._get_attach_base_dir()
        if not attach_base:
            return None

        user_hash = hashlib.md5(username.encode()).hexdigest()
        user_dir = os.path.join(attach_base, user_hash)
        if not os.path.isdir(user_dir):
            return None

        dt = datetime.fromtimestamp(create_time)
        month_str = dt.strftime("%Y-%m")
        img_dir = os.path.join(user_dir, month_str, "Img")

        # ── Primary strategy: locate by hash ──
        if file_hash:
            months_to_try = [month_str]
            # Month boundary: also check adjacent months
            if dt.day <= 2:
                prev = dt.replace(day=1)
                prev = prev.replace(
                    year=prev.year - 1, month=12
                ) if prev.month == 1 else prev.replace(month=prev.month - 1)
                months_to_try.append(prev.strftime("%Y-%m"))
            elif dt.day >= 28:
                nxt = dt.replace(day=1)
                nxt = nxt.replace(
                    year=nxt.year + 1, month=1
                ) if nxt.month == 12 else nxt.replace(month=nxt.month + 1)
                months_to_try.append(nxt.strftime("%Y-%m"))

            # New format (2026+): _t.dat=thumbnail, .dat=medium, _h.dat=original
            # Old format (~2025): _t_M.dat=thumbnail, _M.dat=original
            thumb_suffixes = ("_t_M.dat", "_t.dat")
            full_suffixes = ("_h.dat", "_M.dat", ".dat")

            for m in months_to_try:
                d = os.path.join(user_dir, m, "Img")
                if not os.path.isdir(d):
                    continue
                if prefer_thumbnail:
                    for sfx in thumb_suffixes:
                        p = os.path.join(d, file_hash + sfx)
                        if os.path.isfile(p):
                            return p
                for sfx in full_suffixes:
                    p = os.path.join(d, file_hash + sfx)
                    if os.path.isfile(p):
                        return p
                if not prefer_thumbnail:
                    for sfx in thumb_suffixes:
                        p = os.path.join(d, file_hash + sfx)
                        if os.path.isfile(p):
                            return p

        # ── Fallback: match by modification time ──
        if not os.path.isdir(img_dir):
            return None

        if prefer_thumbnail:
            target_suffixes = ("_t_M.dat", "_t.dat")
        else:
            target_suffixes = ("_h.dat", "_M.dat", ".dat")
        best_path = None
        best_delta = float("inf")

        for fname in os.listdir(img_dir):
            if not any(fname.endswith(sfx) for sfx in target_suffixes):
                continue
            # Exclude files with underscore prefixes that don't match the target suffix
            fpath = os.path.join(img_dir, fname)
            try:
                delta = abs(os.path.getmtime(fpath) - create_time)
                if delta < best_delta:
                    best_delta = delta
                    best_path = fpath
            except OSError:
                continue

        return best_path if best_path and best_delta < 60 else None

    def get_image_messages(self, username, since_ts=0, limit=10):
        """Get image messages with file paths from a chat.

        Similar to get_messages(), but only queries local_type=3 (images),
        and additionally extracts packed_info_data to locate image files on disk.

        Returns:
            list[dict]: Each contains sender, time_str, timestamp,
                        thumb_path, image_path, file_hash.
        """
        self._load_contacts()
        is_group = "@chatroom" in username

        rel_keys, table_name = self._find_msg_table(username)
        if not rel_keys:
            return []

        rows = []
        for rel_key in rel_keys:
            conn = self._open_encrypted_conn(rel_key)
            if not conn:
                continue
            try:
                if since_ts > 0:
                    r = conn.execute(f"""
                        SELECT local_type, create_time, message_content,
                               WCDB_CT_message_content, status, packed_info_data
                        FROM [{table_name}]
                        WHERE local_type = 3 AND create_time > ?
                        ORDER BY create_time DESC
                        LIMIT ?
                    """, (since_ts, limit * 2)).fetchall()
                else:
                    r = conn.execute(f"""
                        SELECT local_type, create_time, message_content,
                               WCDB_CT_message_content, status, packed_info_data
                        FROM [{table_name}]
                        WHERE local_type = 3
                        ORDER BY create_time DESC
                        LIMIT ?
                    """, (limit * 2,)).fetchall()
                rows.extend(r)
            except Exception:
                pass
            finally:
                conn.close()

        if not rows:
            return []

        # Sort + truncate after multi-DB merge
        if since_ts > 0:
            rows.sort(key=lambda r: r[1])
        else:
            rows.sort(key=lambda r: r[1], reverse=True)
        rows = rows[:limit]
        if since_ts <= 0:
            rows = list(reversed(rows))

        contact_name = ""
        if not is_group:
            contact_name = self._contacts.get(username, username)

        messages = []
        for local_type, create_time, content, ct, status, packed_info in rows:
            # Decompress content
            if ct and ct == 4 and isinstance(content, bytes):
                try:
                    content = _zstd_dctx.decompress(content).decode("utf-8", errors="replace")
                except Exception:
                    content = ""
            elif isinstance(content, bytes):
                try:
                    content = content.decode("utf-8", errors="replace")
                except Exception:
                    content = ""

            # Extract sender
            sender = ""
            text = content or ""
            if is_group and ":\n" in text:
                raw_id, text = text.split(":\n", 1)
                sender = self._contacts.get(raw_id)
                if not sender:
                    sender = self._nick_to_remark.get(raw_id, raw_id)
            elif not is_group:
                sender = "我" if status == 2 else contact_name
            if is_group and not sender:
                sender = "您"

            # Extract file hash
            file_hash = None
            if packed_info and isinstance(packed_info, bytes):
                file_hash = self._extract_file_hash_from_protobuf(packed_info)

            # Locate file
            thumb_path = self._find_image_file(
                username, create_time, file_hash, prefer_thumbnail=True
            )
            image_path = self._find_image_file(
                username, create_time, file_hash, prefer_thumbnail=False
            )

            messages.append({
                "sender": sender,
                "timestamp": create_time,
                "time_str": datetime.fromtimestamp(create_time).strftime("%Y-%m-%d %H:%M"),
                "file_hash": file_hash,
                "thumb_path": thumb_path,
                "image_path": image_path,
            })

        return messages

    def get_emoji_messages(self, username, since_ts=0, limit=10):
        """Get sticker/animated emoji messages from a chat.

        Queries local_type=47 messages, parses XML to extract cdnurl, md5, etc.

        Returns:
            list[dict]: Each contains sender, time_str, timestamp,
                        md5, cdnurl, aeskey, width, height.
        """
        import re

        self._load_contacts()
        is_group = "@chatroom" in username

        rel_keys, table_name = self._find_msg_table(username)
        if not rel_keys:
            return []

        rows = []
        for rel_key in rel_keys:
            conn = self._open_encrypted_conn(rel_key)
            if not conn:
                continue
            try:
                if since_ts > 0:
                    r = conn.execute(f"""
                        SELECT local_type, create_time, message_content,
                               WCDB_CT_message_content, status
                        FROM [{table_name}]
                        WHERE local_type = 47 AND create_time > ?
                        ORDER BY create_time DESC
                        LIMIT ?
                    """, (since_ts, limit * 2)).fetchall()
                else:
                    r = conn.execute(f"""
                        SELECT local_type, create_time, message_content,
                               WCDB_CT_message_content, status
                        FROM [{table_name}]
                        WHERE local_type = 47
                        ORDER BY create_time DESC
                        LIMIT ?
                    """, (limit * 2,)).fetchall()
                rows.extend(r)
            except Exception:
                pass
            finally:
                conn.close()

        if not rows:
            return []

        # Sort + truncate after multi-DB merge
        if since_ts > 0:
            rows.sort(key=lambda r: r[1])
        else:
            rows.sort(key=lambda r: r[1], reverse=True)
        rows = rows[:limit]
        if since_ts <= 0:
            rows = list(reversed(rows))

        contact_name = ""
        if not is_group:
            contact_name = self._contacts.get(username, username)

        messages = []
        for local_type, create_time, content, ct, status in rows:
            # Decompress content
            if ct and ct == 4 and isinstance(content, bytes):
                try:
                    content = _zstd_dctx.decompress(content).decode(
                        "utf-8", errors="replace"
                    )
                except Exception:
                    content = ""
            elif isinstance(content, bytes):
                try:
                    content = content.decode("utf-8", errors="replace")
                except Exception:
                    content = ""

            if not content:
                continue

            # Parse emoji XML
            md5_match = re.search(r'md5\s*=\s*"([a-fA-F0-9]{32})"', content)
            cdn_match = re.search(r'cdnurl\s*=\s*"([^"]+)"', content)
            aes_match = re.search(r'aeskey\s*=\s*"([^"]*)"', content)
            w_match = re.search(r'width\s*=\s*"(\d+)"', content)
            h_match = re.search(r'height\s*=\s*"(\d+)"', content)
            from_match = re.search(
                r'fromusername\s*=\s*"([^"]+)"', content
            )

            if not md5_match:
                continue

            emoji_md5 = md5_match.group(1)
            cdnurl = cdn_match.group(1).replace("&amp;", "&") if cdn_match else ""
            aeskey = aes_match.group(1) if aes_match else ""
            width = int(w_match.group(1)) if w_match else 0
            height = int(h_match.group(1)) if h_match else 0

            # Extract sender
            sender = ""
            if is_group:
                # In group chat emoji XML, fromusername is the sender
                if from_match:
                    raw_id = from_match.group(1)
                    sender = self._contacts.get(raw_id)
                    if not sender:
                        sender = self._nick_to_remark.get(raw_id, raw_id)
            else:
                sender = "我" if status == 2 else contact_name

            messages.append({
                "sender": sender,
                "timestamp": create_time,
                "time_str": datetime.fromtimestamp(create_time).strftime(
                    "%m-%d %H:%M"
                ),
                "md5": emoji_md5,
                "cdnurl": cdnurl,
                "aeskey": aeskey,
                "width": width,
                "height": height,
                "msg_type": "emoji",
            })

        # Backfill CDN URLs from emoticon.db for stickers missing cdnurl
        self._load_emoticon_db()
        for msg in messages:
            if not msg.get("cdnurl") and msg["md5"] in self._emoticon_map:
                info = self._emoticon_map[msg["md5"]]
                msg["cdnurl"] = info["cdn_url"]
                if not msg.get("aeskey"):
                    msg["aeskey"] = info["aes_key"]

        return messages

    def format_messages_for_ai(self, messages, show_group_nickname=False):
        """Format message list into text suitable for AI summary.

        Args:
            messages: List of messages.
            show_group_nickname: Whether to show group nickname (raw sender ID + known name).
        """
        lines = []
        for msg in messages:
            if msg["type"] in (10000, 10002):
                continue  # Skip system messages and recalls
            sender = msg.get("sender", "")
            if sender:
                lines.append(f"[{msg['time_str']}] {sender}: {msg['text']}")
            else:
                lines.append(f"[{msg['time_str']}] {msg['text']}")
        return "\n".join(lines)
