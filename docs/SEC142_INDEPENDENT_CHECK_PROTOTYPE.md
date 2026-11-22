# PCFM SEC-142 — independent status-check candidate (isolated source-only preview)

## Confirmed reason for this branch
Public test PR #3 demonstrated that PR-controlled GitHub Actions could report the existing required job `env003-main-rules` as SUCCESS without executing its security audit. GitHub's source restriction currently pins **GitHub Actions App ID 15368**, which is not an independently controlled admission authority for this job. See [SEC141 test](https://github.com/taku077/github-runner-availability-check/pull/3#issuecomment-7080239502).

## Independent mechanism (design only, NOT deployed)
1. Register **a separate GitHub App**, whose installation and signing keys are controlled outside this PR-controlled repo and outside ChatGPT's tool execution. Keep only minimally required permissions, including Checks:write and read-only PR / metadata access; do not give Contents:write, Workflows:write, or Administration.
2. Verify webhook HMAC-SHA256 over raw request bytes and durable replay IDs. Treat webhook payload as a notification, not sufficient current truth. Re-fetch PR HEAD/base, review states/permissions, file list, and ruleset using an independent authenticated channel. Recheck the HEAD and review after enumeration; reject missing, inconsistent or stale data. Enforce a separately authenticated operator/independent reviewer policy. Neither the repository author account nor a GitHub review login is by itself independent human proof.
3. The independently administered GitHub App may publish a check named `pcfm-independent-admission` on the **exact verified head SHA** only after policy and identity/provenance checks. Fail closed on gaps/errors; do not publish success on merely synthetic/PR-authored evidence. Publish no sensitive event detail to public logs.
4. After owner authorization, installation, independent review and a recoverable test plan, transition repository Ruleset to require **this new check from the separate App installation ID**, without dropping existing branch restrictions. Verify an unapproved disposable PR is actually blocked, and an independently approved disposable PR passes; check unexpected check sources. Never self-approve or let GitHub Actions credentials impersonate the App. Protect the app keys and operator evidence externally.
5. Only then independently review and decide about draft PR #2 deployment to main. Public default-branch dispatch/schedule proof remains separate. Do not merge this prototype merely because its tests are green.

## Prototype scope and limits
The two Python files under `security/sec142/` use the standard library only. They check example HMAC signatures and structural policy candidates; ALL fields passed as dictionaries are **not provider-attested**. Even a synthetic case with an `independent_operator_attestation_verified` flag returns `CANDIDATE_ONLY_NOT_ENFORCED`. A real trusted server must verify evidence/attestation, persistent webhook replay protection and installation credentials outside the PR repository. This branch has **no webhook receiver, network client, app installation, private key, external immutable storage, or check publication**. The CI job is explicitly untrusted and synthetic. Do not use this prototype as a required security check.

Owner type verified from GitHub: **User** (personal repository), not a GitHub organization. GitHub documents required workflow ruleset sourcing for org/enterprise, so do not assume organization-only required workflows are available here.

Acceptance flags: `PROTOTYPE_ONLY`, `WEBHOOK_SIGNATURE_SYNTHETIC`, `INDEPENDENT_APP=NOT_INSTALLED`, `LIVE_GATE=NOT_ACCEPTED`, `PC_INTRUSION=UNDETERMINED`.

## Sources
- https://docs.github.com/en/rest/checks/runs
- https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets
- https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries
- https://docs.github.com/en/webhooks/using-webhooks/best-practices-for-using-webhooks
- https://docs.github.com/en/enterprise-cloud@latest/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets


## SEC-143 — durable delivery replay intake (synthetic only)

Added 'security/sec142/webhook_intake.py' and 'test_webhook_intake.py'.
First authenticate the exact raw webhook body with HMAC-SHA256. Then verify
'X-GitHub-Delivery' as a UUID-style value, event type, repository, installation,
PR number and head SHA. Atomically claim the delivery ID in a persistent SQLite
WAL ledger with a unique key and full synchronous setting. Identical delivery
IDs cannot be claimed twice, including across restarts or concurrent clients.

This is an **untrusted source-code prototype**: no actual webhook server,
no operational secret, no independent App installation, no verified human actor,
no PR API readback, no check creation, no signed operator approval. Receipts
always have status 'WEBHOOK_OBSERVED_ONLY_NOT_AUTHORIZED'. A valid webhook
signature only authenticates that GitHub sent those bytes; it is not user
authorization. A database on a PR-controlled host cannot attest independence.
The ledger itself is not immutable evidence. GitHub redelivery with the
same delivery ID is intentionally ignored/rejected. An identical payload
under a *different* ID is not detected as a replay and must be correlated
separately by a future trusted host. Custody, retention, backup, recovery,
monitoring and replay ID scope remain unaccepted.

Official references:
https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries
https://docs.github.com/en/webhooks/using-webhooks/best-practices-for-using-webhooks


## SEC-144 — offline custody snapshot and restore preflight (synthetic only)

Added 'security/sec142/ledger_snapshot.py' and 'test_ledger_snapshot.py'.
The snapshot helper invokes SQLite's online backup API from a read-only
connection so a WAL-backed ledger can be copied consistently. It refuses
overwriting existing snapshot/manifest paths; checks SQLite integrity and
ordered row evidence digest; writes a snapshot SHA-256 plus a canonical JSON
manifest authenticated by an HMAC key provided to the function. A verify-only
preflight detects changed manifest, wrong key, changed snapshot bytes, missing
database and stale snapshot compared with current live ledger. No action
overwrites the live ledger or publishes GitHub checks.

Boundaries: this source is PR-controlled and synthetic, and the MAC secret
is supplied by the caller; it is NOT an independently protected custodian,
immutable archive, tamper-proof audit record, trusted-key provider, rollback
mechanism, actual PR review, or a real GitHub App deployment. There is no
automatic restore; a verified stale snapshot must NOT replace a newer ledger.
No crash-atomic transaction spans *both* SQLite snapshot and separate manifest.
An interrupted creation may leave partial files that must be quarantined
without modification of original evidence. WAL durability also depends on
underlying filesystem and sync semantics; production needs a separately
secured host and externally protected manifests, backup/restore drill,
secrets, ownership, alerts, limits, retention and external independent audit.

The system still rejects GitHub webhook redeliveries with the same delivery
ID: retry/processing recovery after a crash is NOT implemented or accepted.
No input here gives permission to merge a PR or declare a PC intrusion.

Official references:
https://www.sqlite.org/backup.html
https://www.sqlite.org/wal.html
https://www.sqlite.org/pragma.html
https://docs.github.com/en/webhooks/using-webhooks/best-practices-for-using-webhooks


## SEC-145: durable delivery lifecycle and fenced observation recovery (offline synthetic)

The new files security/sec142/delivery_lifecycle.py and
security/sec142/test_delivery_lifecycle.py demonstrate a SQLite lifecycle
independent of the earlier SEC143 claim-once ledger. SEC143 is kept intact
for historical behavior and tests; do NOT run both ingestion ledgers against
the same live webhook without an independently verified migration.

States are RECEIVED -> PROCESSING -> OBSERVED_COMPLETE, or
PROCESSING -> RECOVERY_HOLD after the lease deadline. An authenticated
redelivery of the same delivery GUID and identical payload returns the
existing state; a payload collision fails closed. Repeated deliveries NEVER
start a new processing attempt automatically. Each worker gets a random,
per-attempt fencing token. The store rejects a stale worker after expiry
or re-arm; the SQLite transition uses BEGIN IMMEDIATE and UNIQUE keys.
Logical time rollback is refused; production requires a trustworthy clock.

A synthetic manual-recovery ticket binds delivery GUID, body SHA-256,
PR HEAD, observed attempt and expiration to an HMAC of a caller-supplied
key. On an expired attempt, the ticket can move RECOVERY_HOLD back to
RECEIVED, but only in an OFFLINE DEMONSTRATION. The key and alleged live
HEAD are supplied by the untrusted caller: this does NOT authenticate a
real operator, account, GitHub check or user instruction. The ticket
cannot auto-start a worker or emit a check. A recovery audit table records
ticket digest/attempt inside the same untrusted DB; it is NOT immutable.

OBSERVED_COMPLETE means internal observation ONLY, not an actual outbound
GitHub API side effect. Exactly-once remote writes are NOT proven. A real
protected deployment would require an independent host and operator,
re-fetch of current GitHub PR and review state, protected signing keys,
durable transaction/outbox, remote check-run reconciliation, backup of
BOTH the old and new state schemas, log retention and crash/fault tests.
In particular, SEC144 snapshot tooling checks the SEC143 seen table,
NOT the new SEC145 lifecycle and recovery_audit tables. Consequently
SEC144 backups DO NOT protect SEC145 state and this remains BLOCKED.

The new tests are synthetic-only and use fake signing keys; no live
GitHub App, credentials, authorized reviewer, check-run publication,
ruleset modification or user-PC investigation occurs in SEC145.

References:
https://docs.github.com/en/webhooks/using-webhooks/best-practices-for-using-webhooks
https://docs.github.com/en/webhooks/using-webhooks/handling-failed-webhook-deliveries
https://sqlite.org/lang_transaction.html


## SEC-146 — combined SEC145 lifecycle backup and offline unknown-result outbox

The SEC146 scope is source-only with 39 additional synthetic unit tests:
- security/sec142/offline_outbox.py and test_offline_outbox.py
- security/sec142/custody_v2.py and test_custody_v2.py

**Local outbox** (SEC146): after a local SEC145 OBSERVED_COMPLETE entry,
the program can create a deterministic PREPARED_LOCAL_ONLY intent bound to
the observed delivery, attempt and PR head SHA in the SAME SQLite database
and transaction domain. This is not an approval to publish any Check Run.
Marking a hypothetical remote attempt as UNKNOWN_REMOTE_RESULT prevents
any automatic retry. A caller-supplied API-like observation can only move
the intent to RECONCILIATION_HOLD, and the result still has
independent_provenance=NOT_ATTESTED and check_written=false.
A caller-controlled successful conclusion is explicitly not accepted.
No network library or GitHub write token is present in this code. GitHub
App authentication, external_id reconciliation, actual provider check-run
readback, and non-replay-safe external API side effects are NOT TESTED.
Exactly-once delivery to GitHub is NOT guaranteed by this demonstration.

**Custody v2** (SEC146): SQLite online backup includes ALL four operational
tables for the SEC145+SEC146 state: lifecycle, recovery_audit, outbox_intents,
and outbox_events. The backup and manifest include separate row counts,
canonical row hashes, snapshot file SHA-256 and caller-key HMAC.
Verification rejects changed bytes, modified manifests, missing tables,
wrong keys and divergence between a snapshot and a still-current ledger.
It is verification-only; never overwrites an original database.
The previous SEC144 snapshot (SEC143 seen table) is intentionally separate,
so a real migration would need inventory, schema pinning, retention and
independent backups of both old and new storage paths.

**Security limits**: Caller-supplied secret/HMAC key and purported remote
check metadata do not attest actual GitHub App identity, independent
operator authority, human reviewer identity, live PR head, external
storage custody or incident recovery. A real trusted App host would be
needed to bind the external_id to an App-owned check on the exact current
PR SHA and reconcile unknown results without blindly sending a second
request. Snapshot and manifest are not a single crash-atomic commit;
a crash can leave partial files for quarantine. A private external HMAC
key, backup custody, access controls, independent attestations, a fault
injection plan and trusted-server check-run publication are absent.
The stored outbox audit is local SQLite data, not an immutable log.
None of these tests grants merge approval or changes the production Ruleset.

Acceptance:
SEC146_SOURCE_ONLY=true
SEC146_EXTERNAL_GITHUB_API_CALLS=0
SEC146_INDEPENDENT_GITHUB_APP=NOT_INSTALLED
SEC146_TRUSTED_MERGE_ENFORCEMENT=NOT_ACCEPTED
SEC146_LIVE_RESTORE=NOT_TESTED

Official references:
https://www.sqlite.org/backup.html
https://www.sqlite.org/wal.html
https://docs.github.com/en/rest/checks/runs
https://docs.github.com/en/webhooks/using-webhooks/best-practices-for-using-webhooks

## SEC-147 — Check Run App source / exact PR HEAD / external ID candidate readback

Added security/sec142/provider_readback.py and test_provider_readback.py.
Source-only comparison rejects mismatched expected future independent GitHub App
app.id (NOT existing GitHub Actions app 15368), head_sha, external_id / outbox
intent ID, Check Run name pcfm-independent-admission, incomplete check listing,
duplicate check runs, changed PR HEAD/base, stale intent, or failed check status.
It also checks a matching get-by-ID record against the git-reference list.

Every input is caller-supplied API-shaped synthetic data. There is no
GitHub REST request, real registered App, independently protected credentials,
verified installation or user identity, and no check publication or Ruleset
change. The expected App ID value is not authenticated. Even a fully matching
synthetic record yields SYNTHETIC_MATCH_UNTRUSTED_NOT_AUTHORIZED with all
authorization, provenance, merge and actual enforcement flags FALSE.

This pure comparison cannot prove that the list response includes every
possible check run, nor prevent a commit from changing after the second
PR readback. GitHub's git-ref check-list API has pagination/1000-suite limits;
absence of a listed result does not prove historic absence. A future secure
host must authenticate GitHub API and App configuration independently, ensure
exact current PR and review state and a complete reconciliation query,
and perform an external denial test before declaring a trusted merge gate.
No true source-origin admission is accepted in SEC-147.

Sources:
https://docs.github.com/en/rest/checks/runs
https://docs.github.com/en/rest/apps/apps
https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets
