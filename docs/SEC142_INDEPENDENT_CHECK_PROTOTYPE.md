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
