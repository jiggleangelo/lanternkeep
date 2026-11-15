# lanternkeep

Prototype: Check if an old app with users is ready to keep alive or hand over: lanternkeep

**Use it free, no account:** https://app-lanternkeep.manykiln.com/  
**Try the demo (made-up data):** https://try-lanternkeep.manykiln.com/  
**Product page:** https://lanternkeep.manykiln.com/

> Built and maintained by AI agents at [Manykiln](https://manykiln.com), a studio whose products are written, tested and operated by AI agents. This is a working prototype, not a finished product. No payment is taken anywhere: any checkout, waitlist or payment code in this project runs against fakes only, and the hosted demo uses made-up data.

- Status: prototype; run the 14 automated tests yourself with `python3 -m unittest discover`
- Runs on the Python 3.12 standard library; run the usable app with `python3 app.py` (see below)
- Licence: MIT. Free to use, fork and improve.
- Issues and pull requests are not monitored yet.

---

# Steward Desk and Lanternkeep

The original standard-library demonstration remains available with `python3 demo.py`. Its `demo.py`, `steward/` modules and original tests are unchanged.

## Lanternkeep

Lanternkeep produces a deterministic handover-readiness report, self-review checklist, keep-alive budget, stewardship log, read-only share link and JSON export. It uses Python 3.12's standard library. It makes no outbound requests and no AI-model calls. Reports explicitly state that the project was not built or tested by Lanternkeep.

Paste or upload app/root Gradle files, AndroidManifest.xml, Info.plist, dependency coordinates or a Gradle lockfile, and optionally libs.versions.toml. Each document is limited to 200 KB and the request to 1 MB. A nonempty upload takes precedence over its corresponding textarea. Resubmit documents to replace the report; successful submissions do not prefill document textareas.

Full documents are discarded after parsing. Only derived facts, at most 200 matched source lines per request, and at most 500 dependency records are retained. Suspected secret lines are removed before facts or diffs are produced. Redaction is not permission to submit credentials: never submit signing keys, keystores, passwords, API secrets, user databases or other people's personal data. Error pages temporarily return escaped, redacted input for correction with Cache-Control: no-store; failed submissions are not saved.

Ambiguous auth/token assignments remain conservatively redacted. The report identifies affected Gradle file names and line numbers as not assessed, explains that other declarations on those lines were omitted, and asks the user to separate non-secret declarations and resubmit. It does not echo suspected values.

Gradle comments use a linear scanner rather than a whole-document backtracking lexer. A block comment's terminator is searched once. Ordinary tokens and strings respect the 2,000-character line cap, and scanning checks the shared two-second parsing deadline. Overlong lines are omitted from assessment and reported through the existing limit finding.

Numeric root properties are collected before parsing app settings. An app reference such as rootProject.ext.targetSdkVersion resolves to its root definition, and its diff identifies the defining file and line. App literals take precedence; unused root definitions do not establish the app's SDK. Plugin values such as flutter.targetSdkVersion resolve only when an explicit numeric definition is supplied. Otherwise the report identifies the unresolved expression and asks the user to inspect their installed Flutter plugin or supply a tested numeric app setting. No plugin defaults are invented.

Catalog aliases that cannot be resolved produce informational 'not assessed' findings, not high-severity dependency accusations. Repository checks inspect repository declarations. Multiple repository edits are grouped into one finding whose checklist covers every edit. Changed findings lose their previous done status. Permission-to-category suggestions, including the Google Play services AD_ID permission, are explicitly assumptions requiring confirmation of actual collection.

## Budget

Budget amounts use only user-entered figures in a common currency. Fee/split percentage is the user's assumption.

Net annual is twelve times monthly revenue after the entered fee percentage, less monthly costs. Annual upkeep is entered hours times hourly rate plus the annual store fee. Break-even monthly revenue covers both costs and upkeep after fees.

An optional cash-reserve field enables months of runway: reserve divided by monthly net burn, where monthly burn is (annual upkeep minus net annual) / 12. This spreads upkeep evenly over the year and treats entered labour costs as cash expenses. Zero reserve with positive burn gives zero months. Missing reserve means runway is not assessed; it is never silently treated as zero. With no positive net burn there is no finite depletion date at the entered figures; JSON uses null and runway_status=no_net_burn rather than Infinity.

The older 'months of upkeep coverage' metric remains available for compatibility. It is one year's positive net income divided by annual upkeep, multiplied by twelve, and is separately labelled. Existing budgets without reserves remain valid.

## Run

```sh
APP_HOST=127.0.0.1 \
PORT=8080 \
PUBLIC_BASE_URL=http://127.0.0.1:8080 \
APP_HTTPS_TERMINATED=false \
DATA_DIR=/path/to/persistent/lanternkeep-data \
APP_DATA_CAP_MB=200 \
python3 app.py
```

For hosted HTTPS, use the public HTTPS origin and APP_HTTPS_TERMINATED=true. DATA_DIR is the only writable location. GET /healthz returns ok and intentionally bypasses the Host check.

Behind a proxy, set APP_TRUSTED_PROXIES to a comma-separated list of actual proxy IP addresses or CIDRs, for example `127.0.0.1/32` for a local IPv4 proxy. The trusted edge must append the connecting client's address to X-Forwarded-For or overwrite that header with the connecting client's address. Lanternkeep strips trusted hops from the right and ignores forwarded headers from untrusted peers. Do not trust arbitrary Internet ranges. With no trusted proxy configuration, the socket peer remains the client identity. Startup warns that an unconfigured proxy makes its users share the 60/hour client limit.

Creation limits are 60 per client per hour and 600 globally per hour, plus workspace and disk caps. The global limit intentionally protects total storage and can limit creation for all clients; configure and monitor deployment capacity accordingly. Short-lived client identifiers use an ephemeral HMAC key and exist only in memory. They expire on creation or sweeping and reset on restart. No raw or hashed IP identifiers are written to disk.

There are at most 32 request workers. Request headers and body share an absolute ten-second monotonic read deadline from handler setup. Each underlying receive uses only the remaining time, so trickling bytes cannot reset the budget. Timed-out bodies are not saved and their connections close.

Workspace URLs contain the only access key; bookmark them. Workspace tokens are stored only as SHA-256 digests. Read activity updates a zero-byte activity marker, including shared-log reads, so activity survives process restarts without rewriting state.json or consuming payload capacity. Workspaces expire after 90 idle days; never-written workspaces expire after 24 hours. Startup and daily sweeps enforce expiry. Each workspace is capped at 5 MB and total payload storage is bounded by APP_DATA_CAP_MB.

Deletion is reached through a separate confirmation page with export and cancel links. The dashboard has no destructive POST button. The confirmation page submits the existing same-origin-protected deletion endpoint. Deleted directories and share pointers are removed; there is no ever-growing in-memory set of deleted tokens. Waiting operations recheck the state file after acquiring the workspace lock and cannot recreate a deleted workspace.

New review dates and default log dates use UTC. Explicit user-entered log dates are preserved. Existing historical dates are left unchanged because their original timezone cannot be reconstructed.

New share tokens can be redisplayed from the owner dashboard across restarts without rotating them. They are derived from the owner token and a stored random nonce; raw owner and share tokens are not stored. Rotation invalidates the old link. Disabling a share removes its pointer. Shared pages expose only the log and open-finding counts.

On upgrade from legacy schemas, saved documents, parsed facts, findings and review statuses are discarded because old snippets may contain secrets missed by previous redaction. Answers, budgets and logs remain. The dashboard requests a new submission. Legacy IP-hash metadata is removed. Existing legacy share links remain usable, but their original tokens cannot be recovered; rotating once creates a redisplayable link. This migration cannot erase copies in operator-managed backups.

Every POST requires a same-origin Origin, or an absent Origin with a same-origin Referer. Multipart POSTs require Origin. Error logging records exception type and route class, not tokens or submitted data.

## Tests

```sh
python3 -m unittest discover -s tests
```

Existing tests are retained. `tests/test_external_review.py` adds regressions for the unterminated-comment attack in a killable subprocess, comment/string scope and offsets, cross-file SDK resolution and file-labelled diffs, unresolved Flutter values, GMS AD_ID evidence, explicit redaction omissions, cash runway edge cases and UI/export, proxy startup warnings, absolute receive deadlines and slow-body expiry, deletion confirmation, deletion races and memory cleanup, and UTC dates.
