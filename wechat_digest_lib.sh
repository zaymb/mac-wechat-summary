#!/bin/bash
# Shared helpers for the WeChat digest pipeline. Sourced by wechat_digest.sh;
# safe to source from tests.

# descriptor_is_recoverable PATH
#   Exit 0 only when PATH names a readable descriptor whose status is exactly
#   "success" or "empty". Anything else (missing, unreadable, invalid JSON,
#   pending, unknown status) exits nonzero: a failed recovery must never be
#   treated as settled.
descriptor_is_recoverable() {
  local path="$1"
  [ -n "$path" ] || return 1
  [ -r "$path" ] || return 1
  jq -e '.status == "success" or .status == "empty"' "$path" >/dev/null 2>&1
}

# private_runtime_value ENV_VALUE FILE
# Prefer an injected value. Otherwise read one line from a private runtime
# file. Tracked code never supplies a destination ID of its own.
private_runtime_value() {
  local injected="$1"
  local path="$2"
  local value=""
  if [ -n "$injected" ]; then
    printf '%s' "$injected"
    return 0
  fi
  [ -n "$path" ] && [ -r "$path" ] || return 1
  IFS= read -r value < "$path" || [ -n "$value" ] || return 1
  [ -n "$value" ] || return 1
  printf '%s' "$value"
}

# recovery_context_json RETRY_JSON DESCRIPTOR
# Print enriched scheduler context only after the descriptor proves that the
# exact recovery archive is complete (or mechanically empty).
recovery_context_json() {
  local retry_json="$1"
  local descriptor="$2"
  descriptor_is_recoverable "$descriptor" || return 1
  jq -cn \
    --argjson retry "$retry_json" \
    --slurpfile descriptor "$descriptor" \
    '$retry + {
      recovery_descriptor:$descriptor[0],
      slice_id:$descriptor[0].slice_id,
      slice_window:$descriptor[0].slice_window,
      slice_label:$descriptor[0].slice_label,
      slice_path:$descriptor[0].slice_path
    }'
}
