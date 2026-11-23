# RCA172 — live branch-scope gap, not a fake authorization gate

Target: only the PCFM public CI repo, isolated Draft PR #4.
RCA171 obtained public commit facts; RCA172 tests whether the **current GitHub
ruleset applies to PR author-controlled branches**, not whether a given
push was attacker-controlled.

A fixed, unauthenticated GET-only Python standard-library reader fetches the
public repo metadata, all active rulesets (100 max / fail closed on 100),
Ruleset 27806733 detail, and PR #4/#5 metadata. It only makes the narrowly
supported determination if the repo has precisely one active ruleset and it
targets "~DEFAULT_BRANCH" with no exclusions. Other rulesets, changed default
branches, unknown patterns, missing pages or changed schema are NOT_VERIFIED,
rather than silently declaring a branch unprotected.

Expected live observation as of 2026-11-24:
- default main within the single ruleset; review required 0;
- branch dev/sec142-external-gate-prototype not within that main-only scope;
- branch dev/pcfm-ops160-offline-evtx-reader not within that main-only scope.

This result says **these branches are not protected by this specific ruleset**.
It does not attest that writes have been blocked or that a user, AI, or third
party authored any observed commit. The connected ChatGPT GitHub interface
currently reports push/admin visibility on both PCFM repos; this is a separate
authenticated connector observation and is *not* imported into uncredentialed CI.

Run: python3 security/sec142/rca172_ruleset_scope.py --live
The existing PR CI's read-only job runs unit tests and an optional public GET.
Failure of the live probe is clearly marked NOT_VERIFIED, not a policy success.
No GitHub App installation changes, ruleset updates, PR merges, access changes,
private CI, target PC work or repeating approval prompts.

**Required for actual prevention:** a PCFM-only independent authenticated
writer, all other PCFM write paths removed from the model-accessible connection,
reliable read-only replacement before removal, genuine write DENY observed at
the provider with no network send, separate external custody and attribution
records. Until then NATIVE_NON_BYPASS=NOT_IMPLEMENTED.

Sources:
- https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets
- https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets
- https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app
- https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html
