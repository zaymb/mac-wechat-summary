#!/usr/bin/env python3
"""Check whether WeChat has written a real database artifact recently."""

from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path


DATA_SUFFIXES = (".db", ".db-wal", ".material", ".mmkv", ".crc")


def newest_data_write(db_dir: Path) -> tuple[float, str] | None:
    """Return the newest data-artifact mtime and basename below ``db_dir``."""
    newest: tuple[float, str] | None = None
    for root, _dirs, files in os.walk(db_dir):
        for name in files:
            if not name.endswith(DATA_SUFFIXES):
                continue
            path = Path(root, name)
            try:
                candidate = (path.stat().st_mtime, name)
            except OSError:
                continue
            if newest is None or candidate[0] > newest[0]:
                newest = candidate
    return newest


def inspect_freshness(
    db_dir: Path, max_age_minutes: float, *, now: float | None = None
) -> dict:
    if max_age_minutes <= 0:
        raise ValueError("max age must be positive")
    if not db_dir.is_dir():
        raise FileNotFoundError(db_dir)
    newest = newest_data_write(db_dir)
    if newest is None:
        raise RuntimeError("no WeChat database artifacts found")
    mtime, basename = newest
    age_seconds = max(0.0, (time.time() if now is None else now) - mtime)
    return {
        "fresh": age_seconds <= max_age_minutes * 60,
        "age_seconds": round(age_seconds, 3),
        "newest_file": basename,
        "newest_mtime": mtime,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db-dir", required=True, type=Path)
    parser.add_argument("--max-age-minutes", required=True, type=float)
    args = parser.parse_args(argv)
    try:
        result = inspect_freshness(args.db_dir, args.max_age_minutes)
    except (OSError, RuntimeError, ValueError) as exc:
        print(json.dumps({"fresh": False, "error": type(exc).__name__}))
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["fresh"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
