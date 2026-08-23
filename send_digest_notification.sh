#!/bin/bash
set -euo pipefail
umask 077

SLICE_ID=""
FILE_SUMMARY="${WECHAT_DIGEST_FILE_SUMMARY:-}"
FILE_SUMMARY_EXPLICIT=0
TOKEN_FILE="${WECHAT_DIGEST_TOKEN_FILE:-$HOME/.wechat-summary/digest-bot-token}"
LEDGER="${WECHAT_DIGEST_NOTIFICATION_LEDGER:-$HOME/.wechat-summary/digest-notifications.jsonl}"
CHAT_ID="${WECHAT_DIGEST_CHAT_ID:-8690704851}"
CURL_BIN="${WECHAT_DIGEST_CURL_BIN:-curl}"
PYTHON_BIN="${WECHAT_DIGEST_PYTHON_BIN:-python3}"
FORMATTER="${WECHAT_DIGEST_FORMATTER:-$(dirname "$0")/digest_notification.py}"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --slice-id)
      SLICE_ID="${2:-}"
      shift 2
      ;;
    --file-summary)
      FILE_SUMMARY="${2:-}"
      FILE_SUMMARY_EXPLICIT=1
      shift 2
      ;;
    *)
      printf 'unknown argument: %s\n' "$1" >&2
      exit 2
      ;;
  esac
done

if [ -z "$SLICE_ID" ]; then
  printf '%s\n' '--slice-id is required' >&2
  exit 2
fi

if [ "$FILE_SUMMARY_EXPLICIT" -eq 0 ] \
  && [ -n "${WECHAT_DIGEST_FILE_SLICE_ID:-}" ] \
  && [ "$SLICE_ID" != "$WECHAT_DIGEST_FILE_SLICE_ID" ]; then
  FILE_SUMMARY=""
fi

if [ ! -r "$TOKEN_FILE" ]; then
  printf 'digest bot token is unreadable\n' >&2
  exit 1
fi

TEXT="$(cat)"
if [ -z "$TEXT" ]; then
  printf 'notification text is empty\n' >&2
  exit 2
fi

FILE_COUNT=0
if [ -n "$FILE_SUMMARY" ]; then
  if [ ! -r "$FILE_SUMMARY" ]; then
    printf 'digest file summary is unreadable\n' >&2
    exit 1
  fi
  TEXT="$(printf '%s' "$TEXT" | "$PYTHON_BIN" "$FORMATTER" \
    --file-summary "$FILE_SUMMARY")"
  FILE_COUNT="$(jq -r '(.files // []) | length' "$FILE_SUMMARY")"
  case "$FILE_COUNT" in
    ''|*[!0-9]*)
      printf 'digest file summary has an invalid file count\n' >&2
      exit 1
      ;;
  esac
fi

TEXT_SHA256="$(printf '%s' "$TEXT" | shasum -a 256 | awk '{print $1}')"

LOCK_DIR="${LEDGER}.lock"
LOCKED=0
for _attempt in $(seq 1 100); do
  if mkdir "$LOCK_DIR" 2>/dev/null; then
    LOCKED=1
    break
  fi
  sleep 0.1
done
if [ "$LOCKED" -ne 1 ]; then
  printf 'could not acquire notification ledger lock\n' >&2
  exit 1
fi
trap 'rmdir "$LOCK_DIR"' EXIT

touch "$LEDGER"
if jq -e --arg slice_id "$SLICE_ID" \
  'select(.slice_id == $slice_id and .status == "sent")' \
  "$LEDGER" >/dev/null 2>&1; then
  printf 'already sent: %s\n' "$SLICE_ID"
  exit 0
fi

TOKEN="$(cat "$TOKEN_FILE")"
RESPONSE="$(
  "$CURL_BIN" -sS --max-time 20 -X POST \
    "https://api.telegram.org/bot${TOKEN}/sendMessage" \
    -d "chat_id=$CHAT_ID" \
    --data-urlencode "text=$TEXT"
)"
if ! jq -e '.ok == true' <<<"$RESPONSE" >/dev/null 2>&1; then
  printf 'Telegram rejected digest notification\n' >&2
  exit 1
fi

MESSAGE_ID="$(jq -r '.result.message_id // empty' <<<"$RESPONSE")"
jq -cn \
  --arg slice_id "$SLICE_ID" \
  --arg sent_at "$(date '+%Y-%m-%d %H:%M:%S %Z')" \
  --arg telegram_message_id "$MESSAGE_ID" \
  --arg text_sha256 "$TEXT_SHA256" \
  --argjson file_count "$FILE_COUNT" \
  '{schema_version:2, slice_id:$slice_id, status:"sent",
    sent_at:$sent_at, telegram_message_id:$telegram_message_id,
    file_count:$file_count, text_sha256:$text_sha256}' \
  >> "$LEDGER"
printf 'sent: %s message_id=%s files=%s\n' \
  "$SLICE_ID" "$MESSAGE_ID" "$FILE_COUNT"
