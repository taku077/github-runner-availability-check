# ENV004: December 2, 2026 GitHub Actions event-policy migration

Status: **CODE_MIGRATED_AND_PUBLIC_PR_CI_PASS; NOT_MERGED; DEFAULT_BRANCH_SCHEDULE_NOT_PROVEN**.
Recorded: 2026-11-22 JST. Owner project: PCFM public CI, not the external osquery repository.

## Policy change and decision

GitHub will enforce a default block for `pull_request_target` events in public repositories on **2026-12-02**, unless an applicable Actions event policy explicitly allows them.
Official references:
- https://github.blog/changelog/2026-11-02-pull_request_target-blocked-by-default-december-2/
- https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target
- https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows

ENV004 does not require a privileged PR event to perform its existing read-only checks. **Do not create an allow-policy exception for `pull_request_target` merely to keep ENV004 running.**

## Implemented change

File: `.github/workflows/env004-audit-provenance.yml` on `dev/pcfm-env003-public-main-audit`.
Migration commit: `b4f6595efbc548eefafa0726ed9f521cc4d365f2`.
- Removed the `pull_request_target` trigger and the corresponding obsolete event code.
- Retained `pull_request` for untrusted, read-only **preview** checks.
- Retained `schedule` (23:17 UTC daily) and `workflow_dispatch` as default-branch read-only observer options **after deployment to main**.
- No checkout, secrets, repository writes, elevated token scopes, or event-policy exceptions introduced.
- The PR workflow-change alert remains a warning, not an independently enforced merge denial.
- The Github-actor field is *not* human identity attestation.

## Verified public CI on migration SHA

- ENV004 `45022374882`: success, `pull_request` (migration test)
- ENV003 `45022374865`: success
- ENV005 `45022374871`: success
- ENV007 `45022374824`: success
Public run URLs: https://github.com/taku077/github-runner-availability-check/actions/runs/45022374882 and adjacent runs.

## Deployment boundaries and next-chat continuation

The migration is **on draft PR #1**, with other unfinished changes; `main` does NOT yet contain ENV004. Do **not** treat the scheduled workflow, default-branch enforcement, or post-December-2 production operation as verified. Do not merge unrelated/unaccepted code solely to address this event policy. The user must be informed of the remaining deployment gate.

On continuation:
1. Re-read this file, the current public branch head, draft PR #1, CI runs, main contents and ruleset. Confirm no ENV004 `pull_request_target` trigger.
2. Re-read private PCFM GitHub `docs/HANDOFF_CURRENT.md` and Google Drive `02_調査進捗` for the authoritative project status. Do not investigate stopped private CI failures.
3. Verify after an authorized **isolated, reviewed** deployment that main contains ENV004 and that `schedule` or `workflow_dispatch` actually runs with expected read-only receipt. An open PR success does not prove default-branch execution.
4. Separately address existing security gaps before any strong prevention claim: Ruleset currently requires ENV003 only and zero reviews; ENV004 PR-preview warnings are not independent merge blocking; ENV007 signing is synthetic, not operator identity or ChatGPT tool mediation.
5. Preserve evidence; never claim Windows PC intrusion or native production acceptance from public CI tests.

Result is **December-2-event-compatible source in draft PR**, not completion of production rollout.
