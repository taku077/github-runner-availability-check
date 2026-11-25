# PCFM SEC154 — public Ruleset/readiness audit (read-only evidence)

Record date: **2026-11-23 JST**. Scope: PCFM's public CI repo, not a vendor repository.
All values are time-bound observations, NOT proof of an intruder, human identity
or future GitHub enforcement. They are sourced from read-only GitHub connector
REST calls; a separately trusted App has NOT authenticated this evidence.

## Live observations

- Repository: taku077/github-runner-availability-check, ID=1450293513;
  owner User ID=344928446, public, default branch main.
  Source: https://api.github.com/repos/taku077/github-runner-availability-check
- Public main: 1b33f359b1079d0c31fc964083991fd875cda304 at lookup.
  Source: https://api.github.com/repos/taku077/github-runner-availability-check/git/ref/heads/main
- Ruleset 27806733 active, default-branch scope, bypass_actors=[].
  The PR rule requires 0 approvals; it has
  dismiss_stale_reviews_on_push=false, require_last_push_approval=false,
  required_review_thread_resolution=false. Required status checks have
  strict_required_status_checks_policy=false. The ONLY required check is
  env003-main-rules from GitHub Actions App ID 15368.
  Source: https://api.github.com/repos/taku077/github-runner-availability-check/rulesets/27806733
- PR #4 was open, Draft, unmerged, with zero submitted reviews
  (GET pulls/4/reviews?per_page=100 -> []). At SEC154 source HEAD
  5663800463554e47c6d2a444037369f671806dbc.
  Sources: https://api.github.com/repos/taku077/github-runner-availability-check/pulls/4
  https://api.github.com/repos/taku077/github-runner-availability-check/pulls/4/reviews?per_page=100
- Check Runs at that exact SHA with filter=all/per_page=100 returned
  1/1: sec142-prototype-tests-not-a-required-gate,
  check ID=137319159834, completed/success, App ID=15368
  (GitHub Actions). This is NOT the independently administered App.
  Source: https://api.github.com/repos/taku077/github-runner-availability-check/commits/5663800463554e47c6d2a444037369f671806dbc/check-runs?per_page=100&filter=all
- Run 45058567528 / job 137319159834 completed SUCCESS;
  original job log: Ran 528 tests / OK (prior 474 + 54).
  It explicitly reports EXTERNAL_GITHUB_APP_DEPLOYED=FALSE.
  Source: https://github.com/taku077/github-runner-availability-check/actions/runs/45058567528

## Gate-readiness audit

| ID | Observed condition | Required property | State |
|---|---|---|---|
| L01 | Required check sourced from Actions ID 15368 | Independently controlled separate App pinned as issuer | BLOCKED |
| L02 | No independent check in required statuses | Require pcfm-independent-admission from that App | BLOCKED |
| L03 | Required human reviews = 0 | Owner-approved independently governed approval policy >=1 | BLOCKED |
| L04 | Last-push approval rule = false | Independent latest-push review requirement | BLOCKED |
| L05 | Stale approval dismissal disabled | Correct stale review handling enforced | BLOCKED |
| L06 | Review thread resolution not required | Effective unresolved-review protections | BLOCKED |
| L07 | Strict status check policy disabled | Independent base/HEAD freshness controls reviewed | BLOCKED |
| L08 | PR #4 Draft, submitted reviews 0 | Non-Draft, authorized disposable PR and separate human review | BLOCKED |
| L09 | Successful Check Run issued by Actions | Independently verified App/SHA/intent-bound check | BLOCKED |
| L10 | No separate host/keys/identity attestation | Independently controlled operator and authenticated provider | NOT_ACQUIRED |
| L11 | No real forbidden/allowed PR rejection test | Negative and positive authorized merge enforcement tests | NOT_TESTED |
| L12 | No live recovery drill | Key revocation, backup, outbox reconciliation and rollback | NOT_TESTED |

SEC154 Python preflight is only an untrusted, offline structural comparison,
with every authorization/enforcement flag false and constant status
READONLY_PREFLIGHT_NOT_ACCEPTED. Even fabricated, perfectly matched metadata
cannot prove a real independent App, human or secure API transport.

## Prerequisites for a separately authorized future change

1. Independently verify owner consent, distinct human reviewer and operator,
   their authorizations and protected, accountable runbook. GitHub login
   names, green Actions jobs and caller-provided data do not prove identity.
2. Register/install a separate App only after explicit approval and external
   key custody. Never send bearer tokens/private keys to public PRs/logs.
3. On explicitly authorized disposable commits, independently prove check
   app.id, name, head_sha, external_id and reviewer/operator intent from
   provider-authenticated API readback.
4. Use a reviewed reversible Ruleset migration with no weakened protection.
   First demonstrate unauthorized PR rejection, stale-review rejection
   and fake Actions-name source mismatch. Confirm approved positive path.
5. Rehearse lost credentials, suspended App, incident recovery, monitor failure,
   API outages, duplicate webhooks and unknown remote outbox results.
6. Reassess production PCFM only under separate evidence-preserving Windows
   VM/real-host authorization and impact plan.

No such change was performed or authorized during SEC154.
INDEPENDENT_ENFORCEMENT=NOT_ACCEPTED; PRODUCTION=BLOCKED;
PC_INTRUSION=UNDETERMINED. Stopped private CI failure investigation is forbidden.

Official documentation:
- https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets
- https://docs.github.com/en/rest/repos/rules
- https://docs.github.com/en/rest/checks/runs
- https://docs.github.com/en/rest/pulls/reviews
