import hashlib
import hmac
import json
import os
from pathlib import Path
import platform
import subprocess

import pytest

from bootstrap_wechat_keys import DEBUG_ENTITLEMENTS, developer_mode_enabled
from bootstrap_wechat_keys import run_lldb_capture
from core.lldb_key_capture import PAGE_SIZE, RESERVE_SIZE, SALT_SIZE


RUN_INTEGRATION = os.environ.get("RUN_LLDB_CAPTURE_INTEGRATION") == "1"


@pytest.mark.skipif(
    not RUN_INTEGRATION or platform.system() != "Darwin" or platform.machine() != "arm64",
    reason="set RUN_LLDB_CAPTURE_INTEGRATION=1 on Apple Silicon macOS",
)
def test_lldb_cli_captures_and_authenticates_pbkdf_key(tmp_path):
    if not developer_mode_enabled():
        pytest.skip("macOS developer mode is disabled")
    fixture_source = Path(__file__).parent / "fixtures" / "pbkdf_capture_fixture.c"
    fixture_binary = tmp_path / "pbkdf_capture_fixture"
    subprocess.run(
        [
            "/usr/bin/cc",
            "-O0",
            "-g",
            "-o",
            str(fixture_binary),
            str(fixture_source),
        ],
        check=True,
    )
    subprocess.run(
        [
            "/usr/bin/codesign",
            "--force",
            "--sign",
            "-",
            "--entitlements",
            str(DEBUG_ENTITLEMENTS),
            str(fixture_binary),
        ],
        check=True,
    )

    password = bytes(range(32))
    salt = bytes(range(16))
    key = hashlib.pbkdf2_hmac("sha512", password, salt, 256000, 32)
    page = bytearray(PAGE_SIZE)
    page[:SALT_SIZE] = salt
    page[SALT_SIZE : PAGE_SIZE - RESERVE_SIZE + SALT_SIZE] = b"x" * (
        PAGE_SIZE - RESERVE_SIZE
    )
    mac_salt = bytes(value ^ 0x3A for value in salt)
    mac_key = hashlib.pbkdf2_hmac("sha512", key, mac_salt, 2, 32)
    page[PAGE_SIZE - 64 :] = hmac.new(
        mac_key,
        page[SALT_SIZE : PAGE_SIZE - RESERVE_SIZE + SALT_SIZE]
        + (1).to_bytes(4, "little"),
        hashlib.sha512,
    ).digest()
    db_root = tmp_path / "db_storage"
    db_path = db_root / "message" / "fixture.db"
    db_path.parent.mkdir(parents=True)
    db_path.write_bytes(page)
    output = tmp_path / "captured.json"

    result = run_lldb_capture(fixture_binary, db_root, output, 30)

    assert result == 0
    assert json.loads(output.read_text(encoding="utf-8")) == {
        "message/fixture.db": {"enc_key": key.hex()}
    }
    assert output.stat().st_mode & 0o777 == 0o600
