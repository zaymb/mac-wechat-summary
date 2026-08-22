#!/usr/bin/env python3
"""Durable, edge-triggered alerts for timed-out digest stages.

The scheduler owns process timeouts.  This helper only records the observed
outcome and delivers an alert through an injected notifier.  It deliberately
does not read chat content, credentials, or the digest output.
"""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


SCHEMA_VERSION = 1
HEALTHY_STATUSES = frozenset({"success", "empty", "silent"})
VALID_STATUSES = frozenset({"timeout", *HEALTHY_STATUSES})
_SAFE_ID = re.compile(r"^[A-Za-z0-9_.:+-]{1,128}$")
_SAFE_STAGE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


class AlertError(RuntimeError):
    """Raised when a receipt cannot be recorded without guessing."""


def _validate_inputs(run_id, stage, status, occurred_at, timeout_seconds):
    if not _SAFE_ID.fullmatch(run_id):
        raise AlertError("run_id must be a short, non-sensitive identifier")
    if not _SAFE_STAGE.fullmatch(stage):
        raise AlertError("stage must use lowercase letters, digits, '-' or '_'")
    if status not in VALID_STATUSES:
        raise AlertError(f"unsupported status: {status}")
    try:
        dt.datetime.fromisoformat(occurred_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AlertError("occurred_at must be an ISO-8601 timestamp") from exc
    if status == "timeout":
        if timeout_seconds is None or timeout_seconds <= 0:
            raise AlertError(
                "timeout_seconds must be the positive timeout observed by the caller"
            )
    elif timeout_seconds is not None:
        raise AlertError("timeout_seconds is only valid for timeout events")


def _event_id(run_id, stage, status):
    material = f"wechat-digest-alert-v{SCHEMA_VERSION}\0{run_id}\0{stage}\0{status}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _write_state_atomic(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=False, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temp_name)


def _read_ledger(path):
    if not path.exists():
        return []
    rows = []
    try:
        with path.open(encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, 1):
                if not line.strip():
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise AlertError(
                        f"alert ledger contains invalid JSON at line {line_number}"
                    ) from exc
                if not isinstance(row, dict):
                    raise AlertError(
                        f"alert ledger contains a non-object at line {line_number}"
                    )
                rows.append(row)
    except OSError as exc:
        raise AlertError("alert ledger is unreadable") from exc
    return rows


def _append_ledger(path, row):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
    try:
        os.fchmod(fd, 0o600)
        payload = json.dumps(
            row, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ) + "\n"
        os.write(fd, payload.encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)


def _project_state(rows):
    """Rebuild the disposable per-stage projection from durable receipts."""
    state = {"schema_version": SCHEMA_VERSION, "stages": {}}
    event_stage = {}
    active_events = {}

    for row in rows:
        record_type = row.get("record_type")
        if record_type == "pipeline_status":
            event_id = row.get("event_id")
            stage = row.get("stage")
            status = row.get("status")
            if (
                not isinstance(event_id, str)
                or not isinstance(stage, str)
                or status not in VALID_STATUSES
            ):
                raise AlertError("alert ledger contains an invalid pipeline receipt")
            stage_state = state["stages"].setdefault(
                stage,
                {
                    "active_timeout": False,
                    "streak": 0,
                    "alert_delivered": False,
                },
            )
            event_stage[event_id] = stage
            if status == "timeout":
                if stage_state["active_timeout"]:
                    stage_state["streak"] += 1
                else:
                    stage_state.update(
                        {
                            "active_timeout": True,
                            "streak": 1,
                            "alert_delivered": False,
                        }
                    )
                    active_events[stage] = set()
                active_events.setdefault(stage, set()).add(event_id)
            else:
                stage_state.update(
                    {
                        "active_timeout": False,
                        "streak": 0,
                        "alert_delivered": False,
                    }
                )
                active_events[stage] = set()
            stage_state["last_event_id"] = event_id
            stage_state["last_status"] = status
            stage_state["last_observed_at"] = row.get("occurred_at")
        elif record_type == "notification_delivery" and row.get("status") == "sent":
            event_id = row.get("event_id")
            stage = event_stage.get(event_id)
            if stage and event_id in active_events.get(stage, set()):
                state["stages"][stage]["alert_delivered"] = True

    return state, active_events


@contextlib.contextmanager
def _exclusive_lock(state_path):
    lock_path = state_path.with_name(f"{state_path.name}.lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        os.fchmod(fd, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _notification_message(event):
    return (
        "WeChat digest timeout: "
        f"stage={event['stage']}, run={event['run_id']}, "
        f"limit={event['timeout_seconds']}s. "
        "A durable failure receipt was recorded for the resident agents."
    )


def _deliver(notifier, chat_id, event, attempted_at):
    if not notifier:
        return {
            "schema_version": SCHEMA_VERSION,
            "record_type": "notification_delivery",
            "event_id": event["event_id"],
            "attempted_at": attempted_at,
            "status": "failed",
            "reason": "notifier_unconfigured",
        }
    notifier_path = Path(notifier)
    if not notifier_path.is_file() or not os.access(notifier_path, os.X_OK):
        return {
            "schema_version": SCHEMA_VERSION,
            "record_type": "notification_delivery",
            "event_id": event["event_id"],
            "attempted_at": attempted_at,
            "status": "failed",
            "reason": "notifier_unavailable",
        }

    env = os.environ.copy()
    if chat_id:
        env["WECHAT_DIGEST_CHAT_ID"] = chat_id
    alert_id = f"wechat-timeout-{event['event_id'][:24]}"
    try:
        result = subprocess.run(
            [str(notifier_path), "--slice-id", alert_id],
            input=_notification_message(event) + "\n",
            text=True,
            capture_output=True,
            check=False,
            env=env,
        )
    except OSError:
        return {
            "schema_version": SCHEMA_VERSION,
            "record_type": "notification_delivery",
            "event_id": event["event_id"],
            "attempted_at": attempted_at,
            "status": "failed",
            "reason": "notifier_exec_error",
        }

    status = "sent" if result.returncode == 0 else "failed"
    receipt = {
        "schema_version": SCHEMA_VERSION,
        "record_type": "notification_delivery",
        "event_id": event["event_id"],
        "attempted_at": attempted_at,
        "status": status,
        "notifier_exit_code": result.returncode,
    }
    if status == "failed":
        receipt["reason"] = "notifier_rejected"
    return receipt


def process_event(
    *,
    ledger_path,
    state_path,
    run_id,
    stage,
    status,
    occurred_at,
    timeout_seconds=None,
    notifier=None,
    chat_id=None,
):
    """Record one scheduler observation and edge-trigger a timeout alert.

    Every distinct timeout is durable.  Notifications are emitted once per
    uninterrupted timeout streak for a stage.  A healthy outcome resets that
    stage.  If delivery fails, the same event (or the next timeout round) may
    retry without duplicating the pipeline-status receipt.
    """
    ledger_path = Path(ledger_path)
    state_path = Path(state_path)
    _validate_inputs(run_id, stage, status, occurred_at, timeout_seconds)
    event_id = _event_id(run_id, stage, status)

    with _exclusive_lock(state_path):
        rows = _read_ledger(ledger_path)
        state, active_events = _project_state(rows)
        existing = next(
            (
                row
                for row in rows
                if row.get("record_type") == "pipeline_status"
                and row.get("event_id") == event_id
            ),
            None,
        )
        stage_state = state["stages"].setdefault(
            stage,
            {"active_timeout": False, "streak": 0, "alert_delivered": False},
        )

        if existing:
            retryable = (
                status == "timeout"
                and stage_state.get("active_timeout")
                and event_id in active_events.get(stage, set())
                and not stage_state.get("alert_delivered")
            )
            if not retryable:
                return {
                    "event_id": event_id,
                    "recorded": False,
                    "notification": "duplicate_suppressed",
                }
            delivery = _deliver(notifier, chat_id, existing, occurred_at)
            _append_ledger(ledger_path, delivery)
            stage_state["alert_delivered"] = delivery["status"] == "sent"
            _write_state_atomic(state_path, state)
            return {
                "event_id": event_id,
                "recorded": False,
                "notification": delivery["status"],
                "retry": True,
            }

        if status == "timeout":
            continuing = bool(stage_state.get("active_timeout"))
            streak = int(stage_state.get("streak") or 0) + 1 if continuing else 1
            should_notify = not continuing or not stage_state.get("alert_delivered")
            stage_state.update(
                {"active_timeout": True, "streak": streak}
            )
            disposition = "planned" if should_notify else "suppressed"
            suppress_reason = None if should_notify else "active_timeout_streak"
        else:
            streak = 0
            should_notify = False
            disposition = "not_applicable"
            suppress_reason = None
            stage_state.update(
                {
                    "active_timeout": False,
                    "streak": 0,
                    "alert_delivered": False,
                }
            )

        event = {
            "schema_version": SCHEMA_VERSION,
            "record_type": "pipeline_status",
            "event_id": event_id,
            "run_id": run_id,
            "stage": stage,
            "status": status,
            "occurred_at": occurred_at,
            "timeout_seconds": timeout_seconds,
            "timeout_streak": streak,
            "notification_disposition": disposition,
        }
        if suppress_reason:
            event["notification_suppression_reason"] = suppress_reason
        _append_ledger(ledger_path, event)

        notification = disposition
        if should_notify:
            delivery = _deliver(notifier, chat_id, event, occurred_at)
            _append_ledger(ledger_path, delivery)
            stage_state["alert_delivered"] = delivery["status"] == "sent"
            notification = delivery["status"]

        stage_state["last_event_id"] = event_id
        stage_state["last_status"] = status
        stage_state["last_observed_at"] = occurred_at
        _write_state_atomic(state_path, state)
        return {
            "event_id": event_id,
            "recorded": True,
            "notification": notification,
            "timeout_streak": streak,
        }


def _now_iso():
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Record a WeChat digest stage outcome and alert on timeout"
    )
    parser.add_argument("--ledger", required=True)
    parser.add_argument("--state", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--stage", required=True)
    parser.add_argument("--status", required=True, choices=sorted(VALID_STATUSES))
    parser.add_argument("--occurred-at", default=_now_iso())
    parser.add_argument("--timeout-seconds", type=int)
    parser.add_argument(
        "--notifier",
        default=os.environ.get("WECHAT_DIGEST_ALERT_NOTIFIER"),
        help="executable accepting --slice-id and notification text on stdin",
    )
    parser.add_argument(
        "--chat-id", default=os.environ.get("WECHAT_DIGEST_ALERT_CHAT_ID")
    )
    args = parser.parse_args(argv)

    try:
        result = process_event(
            ledger_path=args.ledger,
            state_path=args.state,
            run_id=args.run_id,
            stage=args.stage,
            status=args.status,
            occurred_at=args.occurred_at,
            timeout_seconds=args.timeout_seconds,
            notifier=args.notifier,
            chat_id=args.chat_id,
        )
    except AlertError as exc:
        print(f"digest-timeout-alert: {exc}", file=sys.stderr)
        return 2

    print(json.dumps(result, sort_keys=True))
    return 1 if result.get("notification") == "failed" else 0


if __name__ == "__main__":
    raise SystemExit(main())
