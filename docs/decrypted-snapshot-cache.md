# Shared decrypted snapshot cache

## Problem and evidence

The digest chain runs archive, file collection, and the main MCP digest as
separate processes. Before this change, each fresh `WeChatDB` process had only
an in-memory cache marker, so the same encrypted source could be fully
decrypted again in every stage.

That repeated work is a proven structural defect. It does **not** by itself
explain why runtime changed suddenly at 19:05; the trigger for that step change
remains unknown. This change therefore does not treat a larger timeout as a
root-cause fix.

## Snapshot identity and publication

`DecryptedSnapshotCache` keys an immutable snapshot by:

- hashed logical resource name;
- database device, inode, size, mtime, and ctime;
- WAL presence and the same WAL metadata;
- a one-way encryption-key fingerprint.

The builder holds a per-resource cross-process `flock`, decrypts to a unique
temporary file, patches the matching WAL, validates the SQLite header, page
geometry, and schema, and then rechecks the source signature. Validation is
bounded to SQLite metadata rather than `PRAGMA quick_check`: the latter scans
the entire database and took tens of minutes on the 650+ MiB message shard even
though decryption itself finished in seconds. Only a stable build is published
with atomic rename and a matching atomic manifest. A source that changes twice
during the two allowed attempts fails closed; an older snapshot is never
substituted.

Fresh processes naturally share the cache because archive, collector, and MCP
all construct `WeChatDB` with the same default cache root. The first stage that
touches a particular DB/WAL version builds it. Later stages hit the published
snapshot without a live-script or orchestration change.

The exact guarantee is **one decrypt per unchanged DB+WAL version across
processes**, not one frozen snapshot for an entire digest run. If the live WAL
changes between archive and collector, freshness wins: the later stage builds a
new version. A strict per-run view would require the external orchestrator to
freeze/pin source versions before stage one and pass that run pin to every
stage. The canonical orchestrator is outside this repository and the live
wrapper is deliberately out of scope, so that contract is a deployment-stage
follow-up rather than a claim made by this commit.

## Retention and readers

Each resource keeps one published version, so a changing 650 MiB source does
not leave one new 650 MiB snapshot per digest run forever. A process receives a
hard-link lease protected by a shared file lock. Garbage collection can unlink
an older published name while an active reader continues to use the leased
inode. A later process removes lease files left by a crashed reader only after
it can acquire the companion lock exclusively. No PID-age guess or retention
timeout is involved.

## Message shard mapping

Successful chat-to-message-shard discoveries are persisted by hashed chat ID.
The target table is still verified on every use. A new or replaced shard
invalidates the topology. Empty results are never persisted because WeChat may
create a new chat table inside an existing shard without changing that shard's
inode.

## Diagnostics

An optional diagnostic sink receives one event per cache operation with:

- status (`built`, `disk_hit`, `locked_hit`, `memory_hit`, or
  `source_changed`);
- hashed resource and source-version identifiers;
- total and segmented durations;
- decrypted page and WAL-frame counts for builds.

Events contain no chat text, encryption key, credential, or raw database path.
Setting `WECHAT_SUMMARY_CACHE_DIAGNOSTICS=1` prints the same safe JSON event to
stderr. It is off by default.

## Downloaded-file index (deferred integration)

`PersistentFileCacheIndex` is a standalone follow-up component. It performs a
correctness-preserving metadata walk, rejects symlinks, and persists MD5 values
only while device/inode/size/mtime/ctime remain unchanged. The walk is not
pruned by directory mtime: that would miss in-place changes to nested files.
Content hashing, the expensive part, is incremental across processes.

It is intentionally **not wired into `collect_chat_files.py` in this commit**.
That collector and its current `WeChatDB` file methods are pre-existing,
uncommitted #66 owner work. Integrating now would mix ownership and make a
clean commit impossible. Once #66 has a tracked baseline, replace its
process-local recursive/hash index with this module and remove its second
lookup of a `cache_path` already returned by `get_file_messages`.

## Deployment

No live service, launchd job, cursor, ledger, or digest wrapper is changed by
this commit. Deployment remains a separate operation:

1. land the code in the repository used by all three stages;
2. run the focused tests in that deployed environment;
3. restart or reload the live MCP/digest processes only under the normal
   service-change authorization;
4. observe safe cache diagnostics for one real cycle and compare stage timing.

The sudden 19:05 slowdown should still be investigated independently (for
example storage/cache pressure, concurrent access, or a source-side change).
