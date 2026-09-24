import hashlib
import hmac
import json
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from core import key_extractor
from core import lldb_key_capture
from core.decryptor import PAGE_SZ, RESERVE_SZ, SALT_SZ


def _run_scan(tmp_path, staged_keys):
    live = tmp_path / "all_keys.json"
    original = {"message/message_1.db": {"enc_key": "a" * 64}}
    live.write_text(json.dumps(original), encoding="utf-8")

    def fake_run(_args, **kwargs):
        Path(kwargs["cwd"], "all_keys.json").write_text(
            json.dumps(staged_keys), encoding="utf-8"
        )
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    with (
        mock.patch.object(key_extractor, "DATA_DIR", str(tmp_path)),
        mock.patch.object(key_extractor, "KEYS_FILE", str(live)),
        mock.patch.object(key_extractor, "EXTRACT_LOG", str(tmp_path / "extract.log")),
        mock.patch.object(key_extractor, "compile_scanner", return_value=True),
        mock.patch.object(key_extractor, "get_wechat_pid", return_value=123),
        mock.patch.object(
            key_extractor,
            "load_config",
            return_value={"db_dir": str(tmp_path)},
        ),
        mock.patch.object(key_extractor.subprocess, "run", side_effect=fake_run),
        mock.patch.object(key_extractor, "_rematch_keys_from_log", return_value={}),
        mock.patch.object(
            key_extractor,
            "_validated_staged_keys",
            side_effect=lambda keys, _db_dir: keys,
        ),
    ):
        result = key_extractor.extract_keys()

    return result, json.loads(live.read_text(encoding="utf-8"))


def test_empty_scan_preserves_last_known_good_keys(tmp_path):
    result, live = _run_scan(tmp_path, {})

    assert result is None
    assert live == {"message/message_1.db": {"enc_key": "a" * 64}}


def test_non_empty_scan_atomically_replaces_key_cache(tmp_path):
    new = {"message/message_2.db": {"enc_key": "b" * 64}}
    result, live = _run_scan(tmp_path, new)

    assert result == new
    assert live == new


def test_staged_key_requires_page1_authentication(tmp_path):
    db_dir = tmp_path / "db_storage"
    db_path = db_dir / "message" / "message_2.db"
    db_path.parent.mkdir(parents=True)
    db_path.write_bytes(b"x" * 4096)
    staged = {"message/message_2.db": {"enc_key": "ab" * 32}}

    with mock.patch.object(key_extractor, "verify_page1", return_value=False):
        assert key_extractor._validated_staged_keys(staged, str(db_dir)) == {}

    with mock.patch.object(key_extractor, "verify_page1", return_value=True):
        assert key_extractor._validated_staged_keys(staged, str(db_dir)) == staged


def test_candidate_rejects_decrypted_header_without_page_authentication():
    key = bytes(range(32))
    page1 = bytes(range(256)) * (PAGE_SZ // 256)

    with mock.patch.object(key_extractor, "verify_page1", return_value=False):
        assert not key_extractor._candidate_validates_page1(key, page1)


def test_staged_key_cannot_escape_database_root(tmp_path):
    db_dir = tmp_path / "db_storage"
    db_dir.mkdir()
    outside = tmp_path / "outside.db"
    outside.write_bytes(b"x" * 4096)
    staged = {"../outside.db": {"enc_key": "ab" * 32}}

    with mock.patch.object(key_extractor, "verify_page1", return_value=True):
        assert key_extractor._validated_staged_keys(staged, str(db_dir)) == {}


def test_extract_log_is_private(tmp_path):
    log_path = tmp_path / "extract.log"
    with mock.patch.object(key_extractor, "EXTRACT_LOG", str(log_path)):
        key_extractor._write_extract_log("safe diagnostics\n")

    assert log_path.read_text(encoding="utf-8") == "safe diagnostics\n"
    assert log_path.stat().st_mode & 0o777 == 0o600


def test_db_salt_manifest_is_private_and_skips_plaintext_sqlite(tmp_path):
    db_dir = tmp_path / "db_storage"
    encrypted = db_dir / "message" / "message_2.db"
    plaintext = db_dir / "contact" / "contact.db"
    backup = db_dir / "message" / "message_2.db.factory" / "old" / "message_2.db"
    encrypted.parent.mkdir(parents=True)
    plaintext.parent.mkdir(parents=True)
    backup.parent.mkdir(parents=True)
    encrypted.write_bytes(bytes(range(16)) + b"x" * 32)
    plaintext.write_bytes(b"SQLite format 3\0" + b"x" * 32)
    backup.write_bytes(b"z" * 48)

    manifest = Path(key_extractor._stage_db_salt_manifest(str(db_dir), str(tmp_path)))

    assert manifest.read_text(encoding="utf-8") == (
        "000102030405060708090a0b0c0d0e0f\tmessage/message_2.db\n"
    )
    assert manifest.stat().st_mode & 0o777 == 0o600


def test_lldb_capture_authenticates_sqlcipher_page1():
    key = bytes(range(32))
    salt = bytes(range(16))
    page = bytearray(PAGE_SZ)
    page[:SALT_SZ] = salt
    page[SALT_SZ : PAGE_SZ - RESERVE_SZ + SALT_SZ] = b"x" * (
        PAGE_SZ - RESERVE_SZ
    )
    mac_salt = bytes(value ^ 0x3A for value in salt)
    mac_key = hashlib.pbkdf2_hmac("sha512", key, mac_salt, 2, 32)
    page[PAGE_SZ - 64 :] = hmac.new(
        mac_key,
        page[SALT_SZ : PAGE_SZ - RESERVE_SZ + SALT_SZ]
        + (1).to_bytes(4, "little"),
        hashlib.sha512,
    ).digest()

    assert lldb_key_capture.verify_page1(key, bytes(page))
    assert not lldb_key_capture.verify_page1(b"z" * 32, bytes(page))


def test_lldb_capture_inventory_skips_plaintext_sqlite(tmp_path):
    db_dir = tmp_path / "db_storage"
    encrypted = db_dir / "message" / "message_1.db"
    plaintext = db_dir / "contact" / "contact.db"
    backup = db_dir / "message" / "message_1.db.factory" / "old" / "message_1.db"
    encrypted.parent.mkdir(parents=True)
    plaintext.parent.mkdir(parents=True)
    backup.parent.mkdir(parents=True)
    encrypted.write_bytes(bytes(range(16)) + b"x" * (PAGE_SZ - 16))
    plaintext.write_bytes(b"SQLite format 3\0" + b"x" * (PAGE_SZ - 16))
    backup.write_bytes(b"z" * PAGE_SZ)

    rows = lldb_key_capture.load_encrypted_pages(db_dir)

    assert [(relative, len(page)) for relative, page in rows] == [
        ("message/message_1.db", PAGE_SZ)
    ]


def test_lldb_capture_key_file_is_private(tmp_path):
    target = tmp_path / "keys.json"
    lldb_key_capture.write_private_json(target, {"db": {"enc_key": "ab" * 32}})

    assert json.loads(target.read_text(encoding="utf-8"))["db"]["enc_key"] == "ab" * 32
    assert target.stat().st_mode & 0o777 == 0o600
