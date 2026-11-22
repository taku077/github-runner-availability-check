# SEC155 — Independent operator, evidence, and recovery acceptance runbook

Document class: DESIGN ONLY / NO DEPLOYMENT AUTHORIZATION
Baseline: 2026-11-23 JST. This describes PCFM's own public CI repository,
not third-party open source projects. No GitHub App, owner intervention,
independent reviewer, security key, protected host, Ruleset change or PC
installation is claimed to exist merely because this document is committed.

## 1. Separation of authority — strict stop conditions

GitHub Rulesets, check-source App IDs and PR reviews help govern repository
merges, but they cannot prove that two GitHub accounts belong to different
human beings or that a PR author did not control a reviewer's credentials.
They also cannot control an AI model's choice of unrelated tool calls.

Required *independent, accountable* roles:
- Owner: expressly authorizes the purpose, allowed repository, permissions,
  maintenance window, rollback, operator identity, and each live experiment.
- Operator: administrates the separately hosted App and its signing key.
  Must not rely on PR-author-controlled Actions, workflows, repositories,
  assistant-managed scripts or a private key stored in GitHub files.
- Reviewer: separately verifies identity, changes, evidence completeness,
  key custody, Ruleset effects and failure/recovery results. An account
  login alone does not prove a separate person. Confirm through an external
  owner-approved channel and retain attestations outside the public repo.
- Evidence custodian: controls retention, immutable provenance, clock
  correction/UTC, SHA-256 and incident response (may share a role only
  after explicit separation-of-duties review, not by default).

**STOP / NO-GO** if any role, authority, consent, recovery plan, trust
anchor or verified account mapping is missing. This project currently
has no verified independent App operator or human reviewer.

## 2. Minimal GitHub App and protected host contract (future only)

Before setup:
1. Owner grants explicit, separate authorization to register/install
   an App against only the named public PCFM CI repository (ID 1450293513).
   Do not silently expand repository scope or enable installation on the
   private development repo.
2. Independently review the exact permission set. Proposed baseline:
   checks:write, pull_requests:read, metadata:read. Review all webhook
   subscriptions and any API-specific additional permissions, do not assume
   the proposed baseline is complete until endpoints are validated.
3. Keep the GitHub App private key in separately administered KMS/HSM/key
   vault, ideally sign-only. Never put its PEM, JWT, bearer token or
   webhook secret in the public repo, Actions secrets controlled by the
   developer, a PR comment, Google Drive progress note or AI chat.
4. Protected host independently authenticates GitHub API calls, pins App
   and installation IDs and repository IDs, handles token one-hour expiry,
   suspension, grant drift, HTTPS failures, token revocation and rotation.
   The source code in Draft PR #4 is untrusted and does not implement this.
5. Independently signed policy pins review rules, permitted check name
   pcfm-independent-admission and App source ID. The PR author must not
   be able to change this policy or the trusted host's identity.

GitHub documents that check-run creation requires a GitHub App with
checks:write. App token expiry is one hour. Neither can be emulated as
an independent control by the GitHub Actions preview.

## 3. External evidence packet before any Ruleset edit

For each owner-authorized disposable test attempt, require an **external
immutable** packet. Never publish secrets or personal identification
documents to a public PR.

Required fields (all must have source, UTC collection time and custody):
- owner authorization reference and scope (external, countersigned);
- operator/reviewer identity and account mapping attested out-of-band;
- issue/case ID; GitHub repository numeric ID, PR number, branch, exact
  base SHA and head SHA, and intended check name;
- independently captured GET repository, Ruleset and installation metadata;
- App ID and installation ID, permission grant and expiry evidence
  (redacted; **no access token material**);
- review sequence including all pages, effective approval on current HEAD,
  last push identity and unresolved change requests;
- full Check Runs and relevant Check Suite readbacks, actual origin
  App ID, external intent ID and check run ID, with complete pagination;
- webhook delivery identifier, signature-validation result, replay ledger
  outcome, source event and attempt number; use raw payload hash only in
  nonpublic external custody;
- before/after Ruleset snapshot and explicit expected branch protection
  effects; authorized negative and positive test results, not just status
  check green;
- collection tool and version, SHA-256 of exact original bytes, timezone
  label, trusted external clock reference, storage reference, retention and
  chain of custody;
- rollback plan and recovery-test evidence, including tested key revocation,
  suspended App behavior, API outage, duplicate deliveries, unknown
  remote outbox effect and operator access loss.

A self-computed SHA-256 digest is a checksum, **not** provenance or
signature; signatures only help when the verifying key and audit store are
outside PR/author/assistant control. GitHub's X-GitHub-Delivery ID is reused
on deliberate webhook redelivery: an independent durable dedup/replay
policy must distinguish authorized redelivery from unsafe duplicate
processing. A successful signed webhook is not itself owner approval.

## 4. Acceptance progression (none currently approved)

Gate 0 / Source-only rehearsal:
- SEC142–155 Python compares *untrusted* fixtures and always returns
  NOT_AUTHORIZED. Public Actions CI confirms regression tests, no more.
- Confirm PR #4 remains Draft and main unchanged.

Gate 1 / Separate people and custody:
- Owner authorizes named independent operator and reviewer out-of-band.
- Confirm separate account access, actual person and conflict handling.
- Record external key-vault and immutable evidence-store ownership.
- Stop on any missing attestation. Current state: NOT_ACQUIRED.

Gate 2 / Credential and installation verification:
- Separate administrator registers/installs App after owner consent.
- Validate minimal repo and permission scopes, installation id,
  webhook secret, token lifecycle, revocation and external policy pin.
- Do not display or save raw keys in ChatGPT, Actions, comments or Drive.
- Current state: NOT_DEPLOYED.

Gate 3 / Owner-authorized disposable PRs:
- Independent host issues a Check Run for a disposable exact HEAD with
  independent intent, then independently reads back check name,
  app.id, head_sha, external_id, status and conclusion.
- Check both stale/refreshed head and redeploy/rotation scenarios.
- This is NOT permission to change Ruleset or merge PR #4.
- Current state: NOT_TESTED.

Gate 4 / Reversible Ruleset migration:
- Record before snapshot/hash and a separately reviewed, owner-approved
  patch. Preserve existing protections and check-source restrictions;
  require the independently issued source, never a PR-defined Actions
  name pretending to be it.
- With a disposable PR, demonstrate that no review, stale review, wrong
  App source, revoked token and missing check each block an actual merge.
  Then verify permitted path with authorized distinct reviewer.
- Record final Ruleset, check-run and PR/HEAD after state. No automated
  bypass, no emergency disable by this assistant.
- Current state: NOT_AUTHORIZED and NOT_TESTED.

Gate 5 / Recovery and monitoring:
- Simulate host outage, lease expiry, key compromise, webhook replay,
  permission escalation, API loss, outbox unknown result and data-store
  loss. Fail closed; don't reissue ambiguous remote Check Runs blindly.
- Prove owner-controlled rollback with external reviewer, preserved
  rule history, custody chain, and known-good Ruleset baseline. Alert
  when independent check host is unreachable or logs are missing.
- Current state: NOT_TESTED.

Gate 6 / Target Windows forensic use:
- Separate prior authorization, evidence inventory/hashes and
  impact assessment on isolated Windows test VM. Real investigated
  PC operations require distinct opt-in and evidence-preserving plan.
- Current state: BLOCKED / PC intrusion UNDETERMINED.

## 5. AI tool-dispatch controls are a different security boundary

The GitHub gate controls repository merge acceptance, not decisions made
by an AI assistant when it selects connector or web actions. The earlier
RCA for forbidden private-CI work reentering the task queue is unresolved.
An external tool gateway / allowlist should deny prohibited private-CI
queries and require purpose-specific owner approval for any exceptional
operation, with independent audit of tool calls. A natural-language prompt
or handoff memo is not a technical enforcement boundary. No such external
gateway is deployed by SEC155. In particular, "continue" must never mean
permission to investigate the stopped private CI's runner/logs/reasons.

## 6. Rollback and stop procedure

Before an owner-approved live change: record Ruleset ID, version/updated
timestamp, full original configuration, protected ref, app integration
source IDs and independent custodian checksum/signature. Confirm
administrator recovery access and an operator-owned emergency channel.
During a negative test, if any unauthorized merge passes, if required
checks disappear, if the App identity changes, or if rollback provenance
is incomplete: STOP. Preserve the evidence, prevent further changes
through an authorized incident procedure, and do not weaken protections
automatically. Owner and separate reviewer must approve each recovery
action. Re-read Ruleset and exact base/HEAD after recovery and run the
blocked-case test again. If still uncertain, remain BLOCKED.

## References (GitHub primary sources)

- https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets
- https://docs.github.com/en/rest/repos/rules
- https://docs.github.com/en/rest/checks/runs
- https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/authenticating-as-a-github-app-installation
- https://docs.github.com/en/apps/creating-github-apps/about-creating-github-apps/best-practices-for-creating-a-github-app
- https://docs.github.com/en/webhooks/using-webhooks/best-practices-for-using-webhooks
- https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries

## SEC155 release disposition

Independent App/operator: NOT_DEPLOYED / NOT_ATTESTED.
Independent rule enforcement: NOT_ACCEPTED.
PCFM production deployment: BLOCKED.
PC intrusion / third-party intervention: UNDETERMINED.
Paused private CI failure investigation: PROHIBITED without specific
separate owner instruction.
