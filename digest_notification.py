#!/usr/bin/env python3
"""Deterministically append a daily WeChat file rollup to a TG digest."""

import argparse
import json
import re
import sys


TELEGRAM_TEXT_LIMIT = 4096
FILE_SECTION_HEADER = "📎 文件分享"
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def _telegram_units(text):
    """Return Telegram's UTF-16 code-unit count for a text message."""
    return len(text.encode("utf-16-le")) // 2


def _truncate_units(text, limit):
    if limit <= 0:
        return ""
    if _telegram_units(text) <= limit:
        return text

    ellipsis = "…"
    budget = max(0, limit - _telegram_units(ellipsis))
    out = []
    used = 0
    for char in text:
        width = 2 if ord(char) > 0xFFFF else 1
        if used + width > budget:
            break
        out.append(char)
        used += width
    return "".join(out).rstrip() + (ellipsis if limit > 0 else "")


def _clean_titles(summary):
    if not isinstance(summary, dict):
        raise ValueError("file summary must be a JSON object")
    files = summary.get("files", [])
    if not isinstance(files, list):
        raise ValueError("file summary files must be a list")

    titles = []
    seen = set()
    for entry in files:
        if not isinstance(entry, dict):
            continue
        title = entry.get("title")
        if not isinstance(title, str):
            continue
        title = " ".join(_CONTROL.sub(" ", title).split())
        if not title or title in seen:
            continue
        seen.add(title)
        titles.append(title)
    return titles


def build_file_section(summary, limit=TELEGRAM_TEXT_LIMIT):
    titles = _clean_titles(summary)
    if not titles:
        return ""

    lines = [FILE_SECTION_HEADER]
    for index, title in enumerate(titles):
        candidate = "\n".join([*lines, f"- {title}"])
        if _telegram_units(candidate) <= limit:
            lines.append(f"- {title}")
            continue
        remaining = len(titles) - index
        suffix = f"- …另有 {remaining} 个文件"
        if _telegram_units("\n".join([*lines, suffix])) <= limit:
            lines.append(suffix)
        break
    return "\n".join(lines)


def append_file_section(text, summary, limit=TELEGRAM_TEXT_LIMIT):
    section = build_file_section(summary, limit=limit)
    if not section:
        return text

    separator = "\n\n" if text.strip() else ""
    reserved = _telegram_units(separator + section)
    base = _truncate_units(text.rstrip(), max(0, limit - reserved))
    result = base + (separator if base else "") + section
    if _telegram_units(result) > limit:
        raise ValueError("formatted Telegram digest exceeds the text limit")
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--file-summary", required=True)
    args = parser.parse_args()

    try:
        with open(args.file_summary, encoding="utf-8") as handle:
            summary = json.load(handle)
        print(append_file_section(sys.stdin.read(), summary), end="")
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"digest-notification: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
