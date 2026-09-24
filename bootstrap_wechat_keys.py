#!/usr/bin/env python3
"""Recover WeChat database keys using a temporary, privately signed app copy.

The installed WeChat app is never modified.  The operator first quits the
official app, this script copies it into a mode-0700 temporary directory,
ad-hoc signs only that copy, launches the copy under LLDB, installs only keys
that pass SQLCipher page-one authentication, and reopens the original app.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import tempfile
import time

from core.config import DATA_DIR, load_config
from core.key_extractor import (
    _save_keys_atomically,
    _validated_staged_keys,
    get_cached_keys,
    get_wechat_pid,
)


DEFAULT_APP = Path("/Applications/WeChat.app")
CAPTURE_SCRIPT = Path(__file__).resolve().parent / "core" / "lldb_key_capture.py"
DEBUG_ENTITLEMENTS = (
    Path(__file__).resolve().parent / "resources" / "debug-copy-entitlements.plist"
)


def emit(event, **fields):
    print(json.dumps({"event": event, **fields}, sort_keys=True), flush=True)


def run_checked(arguments):
    result = subprocess.run(
        arguments,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode:
        raise RuntimeError(f"command failed: {Path(arguments[0]).name}")
    return result.stdout + result.stderr


def signature_description(app):
    return run_checked(["/usr/bin/codesign", "-dvv", str(app)])


def developer_mode_enabled():
    result = subprocess.run(
        ["/usr/sbin/DevToolsSecurity", "-status"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    return result.returncode == 0 and "enabled" in result.stdout.lower()


def unregister_copy(app):
    executable = Path(
        "/System/Library/Frameworks/CoreServices.framework/Frameworks/"
        "LaunchServices.framework/Support/lsregister"
    )
    if executable.exists():
        subprocess.run(
            [str(executable), "-u", str(app)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )


def temporary_copy_pids(app):
    prefix = str(Path(app).resolve()) + os.sep
    result = subprocess.run(
        ["/bin/ps", "-axo", "pid=,command="],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    pids = []
    for line in result.stdout.splitlines():
        fields = line.strip().split(maxsplit=1)
        if len(fields) != 2 or not fields[0].isdigit():
            continue
        if fields[1].startswith(prefix):
            pids.append(int(fields[0]))
    return pids


def terminate_temporary_copy(app):
    """Stop only processes whose executable lives inside our private copy."""
    for pid in temporary_copy_pids(app):
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if not temporary_copy_pids(app):
            return
        time.sleep(0.1)
    for pid in temporary_copy_pids(app):
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def launch_original(app):
    executable = app / "Contents" / "MacOS" / "WeChat"
    if executable.exists() and get_wechat_pid() is None:
        process = subprocess.Popen(
            [str(executable)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        time.sleep(1)
        emit(
            "original_wechat_launch_requested",
            pid=process.pid,
            exited=process.poll() is not None,
        )


def install_staged_keys(staged_path, db_root):
    with open(staged_path, encoding="utf-8") as handle:
        staged = json.load(handle)
    staged = _validated_staged_keys(staged, str(db_root))
    if not staged:
        raise RuntimeError("capture produced no authenticated database keys")
    merged = dict(get_cached_keys() or {})
    merged.update(staged)
    merged = _validated_staged_keys(merged, str(db_root))
    if not merged:
        raise RuntimeError("no authenticated keys remain after cache validation")
    _save_keys_atomically(merged)
    return len(staged), len(merged)


def run_lldb_capture(executable, db_root, staged_keys, timeout):
    """Run LLDB's CLI with a scripted breakpoint callback.

    The CLI owns exactly one child process.  On timeout, signals target only
    that process group; the installed app and unrelated WeChat processes are
    never selected by name.
    """
    if not developer_mode_enabled():
        raise RuntimeError("macOS developer mode is disabled")
    environment = dict(
        os.environ,
        WECHAT_KEY_CAPTURE_DB_ROOT=str(db_root),
        WECHAT_KEY_CAPTURE_OUTPUT=str(staged_keys),
    )
    command = [
        "/usr/bin/lldb",
        "--no-lldbinit",
        "--batch",
        "-o",
        "settings set target.preload-symbols false",
        "-o",
        "settings set target.output-path /dev/null",
        "-o",
        "settings set target.error-path /dev/null",
        "-o",
        f"command script import {CAPTURE_SCRIPT}",
        "-o",
        "run",
        "-o",
        "script lldb_key_capture.report_final()",
        "-o",
        "process kill",
        "--",
        str(executable),
    ]
    process = subprocess.Popen(command, env=environment, start_new_session=True)
    try:
        return process.wait(timeout=max(timeout, 10))
    except subprocess.TimeoutExpired:
        emit("capture_timeout", seconds=max(timeout, 10))
        os.killpg(process.pid, signal.SIGINT)
        try:
            return process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                return process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                return process.wait(timeout=5)


def bootstrap(app, db_root, timeout):
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise RuntimeError("bootstrap supports native Apple Silicon macOS only")
    if os.geteuid() == 0:
        raise RuntimeError("do not run bootstrap as root")
    if get_wechat_pid() is not None:
        raise RuntimeError("quit the official WeChat app before key recovery")
    if not Path("/usr/bin/lldb").exists():
        raise RuntimeError("LLDB is unavailable")

    app = Path(app).resolve(strict=True)
    db_root = Path(db_root).resolve(strict=True)
    if not list(db_root.rglob("*.db")):
        raise RuntimeError("configured WeChat database directory is empty")
    original_signature = signature_description(app)
    run_checked(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(app)])

    os.makedirs(DATA_DIR, mode=0o700, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".wechat-key-bootstrap-", dir=DATA_DIR) as work:
        os.chmod(work, 0o700)
        temporary_app = Path(work) / "WeChat-debug.app"
        staged_keys = Path(work) / "captured-keys.json"
        try:
            run_checked(["/usr/bin/ditto", str(app), str(temporary_app)])
            run_checked(
                [
                    "/usr/bin/codesign",
                    "--force",
                    "--deep",
                    "--sign",
                    "-",
                    str(temporary_app),
                ]
            )
            run_checked(
                [
                    "/usr/bin/codesign",
                    "--force",
                    "--sign",
                    "-",
                    "--entitlements",
                    str(DEBUG_ENTITLEMENTS),
                    str(temporary_app),
                ]
            )
            run_checked(
                [
                    "/usr/bin/codesign",
                    "--verify",
                    "--deep",
                    "--strict",
                    str(temporary_app),
                ]
            )
            emit(
                "temporary_copy_ready",
                instruction="Use the temporary WeChat window to enter this account if prompted.",
            )
            result = run_lldb_capture(
                temporary_app / "Contents" / "MacOS" / "WeChat",
                db_root,
                staged_keys,
                timeout,
            )
            if not staged_keys.exists():
                raise RuntimeError(f"key capture failed with status {result}")
            captured, cached = install_staged_keys(staged_keys, db_root)
            emit(
                "keys_installed",
                captured_databases=captured,
                cached_databases=cached,
            )
        finally:
            terminate_temporary_copy(temporary_app)
            unregister_copy(temporary_app)
            if signature_description(app) != original_signature:
                raise RuntimeError("the original WeChat signature changed unexpectedly")
            launch_original(app)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", type=Path, default=DEFAULT_APP)
    parser.add_argument("--db-root", type=Path)
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--acknowledge-debug-copy", action="store_true")
    args = parser.parse_args()
    if not args.acknowledge_debug_copy:
        parser.error("key recovery requires --acknowledge-debug-copy")
    configured_db_root = load_config().get("db_dir", "")
    if args.db_root is None and not configured_db_root:
        raise RuntimeError("WeChat database directory is not configured")
    db_root = args.db_root or Path(configured_db_root)
    bootstrap(args.app, db_root, args.timeout)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        emit("bootstrap_error", error=str(exc))
        raise SystemExit(2)
