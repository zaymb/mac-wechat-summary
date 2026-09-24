#!/usr/bin/env python3
"""LLDB breakpoint callback for verified WeChat SQLCipher key capture.

This module is intentionally stdlib-only because LLDB embeds Apple's Python.
LLDB imports it after selecting one explicit executable.  The callback reads
PBKDF2 arguments only when their salts match selected local databases and
never prints key bytes.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path


PAGE_SIZE = 4096
RESERVE_SIZE = 80
SALT_SIZE = 16
KEY_SIZE = 32
HMAC_SIZE = 64
PBKDF2_SHA512_PRF = 5
KEY_ITERATIONS = 256000
HMAC_ITERATIONS = 2
DB_ROOT_ENV = "WECHAT_KEY_CAPTURE_DB_ROOT"
OUTPUT_ENV = "WECHAT_KEY_CAPTURE_OUTPUT"
_CAPTURE_STATE = None


def emit(event, **fields):
    """Emit metadata-only progress suitable for an operator or log."""
    print(json.dumps({"event": event, **fields}, sort_keys=True), flush=True)


def verify_page1(key, page):
    """Authenticate a SQLCipher 4 page-one candidate."""
    if len(key) != KEY_SIZE or len(page) != PAGE_SIZE:
        return False
    salt = page[:SALT_SIZE]
    mac_salt = bytes(value ^ 0x3A for value in salt)
    mac_key = hashlib.pbkdf2_hmac(
        "sha512", key, mac_salt, HMAC_ITERATIONS, KEY_SIZE
    )
    payload = page[SALT_SIZE : PAGE_SIZE - RESERVE_SIZE + SALT_SIZE]
    expected = hmac.new(
        mac_key,
        payload + (1).to_bytes(4, "little"),
        hashlib.sha512,
    ).digest()
    stored = page[PAGE_SIZE - HMAC_SIZE :]
    return hmac.compare_digest(expected, stored)


def load_encrypted_pages(db_root):
    """Load page one for encrypted databases under a single resolved root."""
    root = Path(db_root).resolve(strict=True)
    rows = []
    for candidate in sorted(root.rglob("*.db")):
        try:
            path = candidate.resolve(strict=True)
            relative = path.relative_to(root)
            if any(part.endswith(".factory") for part in relative.parts):
                continue
            with path.open("rb") as handle:
                page = handle.read(PAGE_SIZE)
        except (OSError, ValueError):
            continue
        if len(page) != PAGE_SIZE or page.startswith(b"SQLite format 3\x00"):
            continue
        rows.append((relative.as_posix(), page))
    return rows


def write_private_json(path, value):
    """Atomically replace a private JSON file."""
    target = Path(path)
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(target.parent, 0o700)
    temporary = target.with_name(target.name + ".new")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _new_capture_state():
    db_root = os.environ.get(DB_ROOT_ENV)
    output_path = os.environ.get(OUTPUT_ENV)
    if not db_root or not output_path:
        raise RuntimeError("LLDB key-capture environment is incomplete")
    rows = load_encrypted_pages(db_root)
    if not rows:
        raise RuntimeError("no encrypted database pages available for validation")
    salts = {page[:SALT_SIZE] for _relative, page in rows}
    return {
        "rows": rows,
        "salts": salts,
        "hmac_salts": {
            bytes(value ^ 0x3A for value in salt): salt for salt in salts
        },
        "found": {},
        "counts": {"pbkdf_calls": 0, "matched_salt_calls": 0},
        "output_path": output_path,
        "completed": False,
    }


def _read_memory(process, address, size):
    import lldb

    error = lldb.SBError()
    data = process.ReadMemory(address, size, error)
    if error.Success() and len(data) == size:
        return bytes(data)
    return b""


def handle_pbkdf(frame, _breakpoint_location, _internal_dict):
    """Inspect one matching CommonCrypto PBKDF2 call and auto-continue."""
    state = _CAPTURE_STATE
    state["counts"]["pbkdf_calls"] += 1

    def register(number):
        return frame.FindRegister(f"x{number}").GetValueAsUnsigned()

    password_ptr, password_len, salt_ptr, salt_len, prf, rounds = (
        register(index) for index in range(1, 7)
    )
    if not (
        salt_len == SALT_SIZE
        and 0 < password_len <= 256
        and prf == PBKDF2_SHA512_PRF
        and rounds in (HMAC_ITERATIONS, KEY_ITERATIONS)
    ):
        return False

    process = frame.GetThread().GetProcess()
    salt_argument = _read_memory(process, salt_ptr, SALT_SIZE)
    salt = (
        salt_argument
        if rounds == KEY_ITERATIONS
        else state["hmac_salts"].get(salt_argument)
    )
    if salt not in state["salts"]:
        return False
    state["counts"]["matched_salt_calls"] += 1
    secret = _read_memory(process, password_ptr, password_len)
    if len(secret) != password_len:
        return False
    key = (
        hashlib.pbkdf2_hmac("sha512", secret, salt, KEY_ITERATIONS, KEY_SIZE)
        if rounds == KEY_ITERATIONS
        else secret
    )
    if len(key) != KEY_SIZE:
        return False

    changed = False
    for relative, page in state["rows"]:
        if (
            relative not in state["found"]
            and page[:SALT_SIZE] == salt
            and verify_page1(key, page)
        ):
            state["found"][relative] = {"enc_key": key.hex()}
            changed = True
    if changed:
        write_private_json(state["output_path"], state["found"])
        emit(
            "verified_key_progress",
            verified_databases=len(state["found"]),
            total_databases=len(state["rows"]),
            **state["counts"],
        )
    if len(state["found"]) == len(state["rows"]):
        state["completed"] = True
        emit("all_database_keys_verified", database_count=len(state["found"]))
        return True
    return False


def report_final():
    """Emit metadata after the target exits or capture intentionally stops."""
    state = _CAPTURE_STATE
    emit(
        "capture_finished",
        completed=state["completed"],
        verified_databases=len(state["found"]),
        total_databases=len(state["rows"]),
        **state["counts"],
    )


def __lldb_init_module(debugger, _internal_dict):
    """Install the callback into LLDB's already selected explicit target."""
    global _CAPTURE_STATE
    _CAPTURE_STATE = _new_capture_state()
    target = debugger.GetSelectedTarget()
    if not target.IsValid():
        raise RuntimeError("LLDB has no selected target")
    if not target.GetTriple().startswith("arm64"):
        raise RuntimeError("key capture supports native Apple Silicon only")
    breakpoint = target.BreakpointCreateByName("CCKeyDerivationPBKDF")
    if not breakpoint.IsValid():
        raise RuntimeError("LLDB could not create the PBKDF2 breakpoint")
    callback = f"{__name__}.handle_pbkdf"
    callback_error = breakpoint.SetScriptCallbackFunction(callback)
    if callback_error is not None and callback_error.Fail():
        raise RuntimeError("LLDB could not install the PBKDF2 callback")
    emit(
        "capture_breakpoint_ready",
        database_count=len(_CAPTURE_STATE["rows"]),
        breakpoint_locations=breakpoint.GetNumLocations(),
    )
