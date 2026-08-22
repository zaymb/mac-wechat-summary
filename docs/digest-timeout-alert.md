# Digest timeout alert

`digest_timeout_alert.py` records scheduler-observed stage outcomes without
reading chat content or credentials.  It is intentionally separate from the
active machine scheduler: code review and deployment can happen independently.

## Contract

- `timeout` is distinct from the ordinary healthy outcomes `success`, `empty`,
  and `silent`.
- Every distinct timeout round is appended to a mode-0600 JSONL ledger.
- The first timeout in an uninterrupted per-stage streak notifies the shared
  resident channel.  Later rounds remain durable but are notification-suppressed
  until any healthy outcome resets the streak.
- The caller supplies the timeout that actually fired.  This helper has no
  timeout default and does not change the scheduler's existing timeout budget.
- Notification failures are receipted without recording transport output.  An
  identical call can retry delivery without duplicating the pipeline event.

The notifier must accept `--slice-id ID`, read plain text from stdin, own its
transport timeout, and return zero only after a real delivery receipt.  The
existing digest notification helper has this shape.  Point
`WECHAT_DIGEST_ALERT_CHAT_ID` at the existing shared household wake channel;
keep its value in private runtime configuration, not in git.

## Active rollout hook

The active scheduler is currently an untracked machine-local wrapper at
`~/wechat-digest.sh`; there is no canonical tracked copy in this repository.
It calls the helper immediately after the archive and file-collector stages
return.  For a timeout, it passes the same timeout variable already used by
that stage:

```sh
python3 /path/to/mac-wechat-summary/digest_timeout_alert.py \
  --ledger "$HOME/.wechat-summary/digest-alert-events.jsonl" \
  --state "$HOME/.wechat-summary/digest-alert-state.json" \
  --run-id "$RUN_ID" --stage archive --status timeout \
  --timeout-seconds "$ARCHIVE_TIMEOUT_SECONDS" \
  --notifier /path/to/mac-wechat-summary/send_digest_notification.sh
```

The alert helper returning nonzero means notification delivery failed, not that
the scheduler stage acquired a new outcome.  Capture it separately and continue;
never let it overwrite the original stage status or abort the digest:

```sh
alert_status=0
python3 /path/to/mac-wechat-summary/digest_timeout_alert.py ... \
  || alert_status=$?
if [ "$alert_status" -ne 0 ]; then
  printf 'digest timeout alert delivery failed (status=%s)\n' \
    "$alert_status" >&2
fi
```

The durable `notification_delivery` failure receipt is the retry/diagnostic
signal.  This separation is required even when the wrapper is not using
`set -e` today, so a later shell-mode change cannot turn an alert failure into a
digest failure.

Record `success`, `empty`, or `silent` for the same stage on its corresponding
healthy path so recovery resets the edge trigger.  Roll back by removing these
calls; the append-only ledger and state can remain for diagnosis.

Verification must use an injected fake notifier first, then one explicitly
labelled shared-channel test.  A valid live
receipt consists of: one `pipeline_status` row, one successful
`notification_delivery` row, and the sender's external message receipt.  No
additional live notification is needed for ordinary code-only regression tests.
