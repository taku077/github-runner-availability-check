# PCFM SEC152–153 — Independent-admission acceptance matrix

Status: **DESIGN / OFFLINE SYNTHETIC TESTS ONLY**. This document does not
authorize installing a GitHub App, modifying repository Rulesets, merging a
PR, deploying code to the target Windows PC, or investigating the stopped
private CI. This plan is scoped to the public PCFM CI repository
taku077/github-runner-availability-check.

## A. Verified context at design time

- Public repository: personal owner account (User), ID 1450293513.
- Public main baseline: 1b33f359b1079d0c31fc964083991fd875cda304.
- Draft PR #4, intentionally never merged, contains the SEC142–153 prototypes.
- Read-only GitHub REST PR #4 reviews returned an empty list at SEC152 start.
- Ruleset 27806733: active; zero required approving reviews; required check
  env003-main-rules sourced from GitHub Actions App 15368.
- A user-controlled PR preview can report that Actions check green without
  an independent review audit (SEC141 synthetic negative fixture). This is
  an observed trust-boundary weakness, **not evidence of hostile intrusion**.
- The non-public Windows PC, Defender, EVTX and production PCFM have not been
  touched by these stages. Target-PC intrusion and third-party interference
  remain UNDETERMINED.

## B. Threat and acceptance traceability

| ID | Failure mode / attack hypothesis | Evidence required before acceptance | Current status |
|---|---|---|---|
| A01 | PR author can change required Actions job | Required check from an independently administered **different** App, with source pinned in Ruleset | NOT_DEPLOYED |
| A02 | PR author/pusher pretends to be reviewer | Independent operator policy, distinct approved reviewer and owner-governed identity evidence | NOT_ATTESTED |
| A03 | Review applies to old HEAD | Re-fetch exact HEAD; current-HEAD submitted approval after last push; double-check state | SYNTHETIC_ONLY |
| A04 | Dismissal/comment masks changes request | Complete review timeline and independently confirmed effective review state | SYNTHETIC_ONLY |
| A05 | List API omits results | Complete bounded Link pagination; independent authenticated collection/retry/fail-closed | SYNTHETIC_ONLY |
| A06 | Check Run from wrong App, SHA or external_id | Authenticated GET list/detail; verified App ID and exact intent/HEAD; owner-appointed check source | SYNTHETIC_ONLY |
| A07 | Installation silently gains repo/permission | External policy pinning, app/installation token auth, before/after scope comparison, revocation monitoring | SYNTHETIC_ONLY |
| A08 | GET results spoofed or mixed sessions | Separate trusted TLS/API client with protected credentials and audit logs | NOT_DEPLOYED |
| A09 | HEAD changes after final GET | Provider-side revalidation immediately before any write, safe write conditionality, stale state denial | NOT_TESTED |
| A10 | Misattributed PR review from same human using two logins | Independently verified person-to-account mapping and owner authorization | NOT_ATTESTED |
| A11 | SQLite/manifest altered together | Trusted external append-only storage, independently held key, verified restore/recovery | NOT_ATTESTED |
| A12 | Webhook replay/crash/duplicate external write | Durable claim, transactional outbox, API result reconciliation, actual fault injection | SYNTHETIC_ONLY |
| A13 | Protected branch lost due to unsafe migration | Human-approved reversible Ruleset plan; independent reviewer; rejection/pass tests on disposable PR | NOT_AUTHORIZED |
| A14 | Production PC destabilized by collector | Independent Windows 10/11 UAC-enabled VM plus real workstation opt-in, evidence-preserving preflight | NOT_TESTED |

## C. Explicit go/no-go gates

**Gate 0 – Source-only synthesis (current):** Offline structural checks
SEC142–153 run on disposable public Actions; every return must remain
non-authorizing even for perfect synthetic inputs. Do not merge prototype PR #4.
A green Actions job does not establish source independence.

**Gate 1 – Separate authority:** Obtain an external administrator/reviewer
not controlled by the PR author or the assistant; confirm separate GitHub
account and verified human consent; establish ownership, incident response,
approved recovery playbook and external secure log retention. A GitHub
account name or repo role alone is insufficient evidence of independence.

**Gate 2 – App installation and credentials:** Owner explicitly approves
registration, installation and permissions; App secrets kept outside public
repo, Actions workflows and assistant-managed tools; enforce least-privilege
checks:write + PR/metadata read and exactly the intended repo.
Confirm real GET /app, installation, token scope and expiration via
independently administered authenticated client. No raw bearer tokens in logs.

**Gate 3 – Provider-authenticated evidence:** Obtain the entire PR/review
list and check history, with complete pagination, authenticated timestamps,
exact HEAD/base source, review supersession, trusted role mapping, explicit
independent user approval, durable outbox intent and actual App readback.
Reject missing, inconsistent, superseded, expired or nonunique evidence.

**Gate 4 – Enforcement negative/positive test:** Independently protect the
new check source in the Ruleset (without losing current restrictions),
then run *authorized disposable PRs* to show:
(a) unapproved PR is actually blocked; (b) stale-HEAD approval is blocked;
(c) approved PR with an authorized independent reviewer can pass; and
(d) forged GitHub Actions check name cannot impersonate the App.
Verify both check source and branch-rule evaluation. Save run/job/commit IDs,
clock basis (UTC/JST), auth scope and SHA-256 for raw logs.

**Gate 5 – Safe operation and recovery:** Exercise key rotation, suspended
installation, API rate limits, check re-issuance, webhook duplicates,
host reboot, storage failure, outbox unknown result, retention and manual
rollback under an independently governed operator. Alert on heartbeat
loss and missing checks. Never automatically retry unknown remote effect.

**Gate 6 – Investigated Windows PC:** Preserve original evidence; run only
after separate explicit approval, isolated VM signoff and documented impact,
hash and rollback plan. Production gate remains BLOCKED until then.

## D. Non-negotiable no-go conditions

- Missing distinct reviewer/owner permission, App credentials, trusted time
  source, credential custody or verified restored state.
- Any review/PR/Check API response acquired using only PR-controlled
  GitHub Actions credentials or passed as caller dictionaries.
- Any PR HEAD drift, base drift, unresolved CHANGES_REQUESTED review, stale
  approval, App suspension, unexpected repository or permission, missing
  pages, or ambiguous Check Runs.
- Any attempt to infer independent human identity solely from GitHub
  login names, role metadata, unsigned commits or green CI.
- Any plan requiring investigation of the **stopped private CI failure**.

## E. Source evidence and notes

- GitHub review API:
  https://docs.github.com/en/rest/pulls/reviews
- PR API:
  https://docs.github.com/en/rest/pulls/pulls
- GitHub App installation/token API:
  https://docs.github.com/en/rest/apps/installations
- GitHub Check Runs API:
  https://docs.github.com/en/rest/checks/runs
- GitHub webhook signature and replay:
  https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries
  https://docs.github.com/en/webhooks/using-webhooks/best-practices-for-using-webhooks

Independent-enforcement acceptance remains NOT_ACCEPTED.
Production deployment remains BLOCKED; investigated-PC intrusion remains
UNDETERMINED. No software in this draft is a verified security boundary.
