# PCFM-SEC-159 — Fail-closed PR author/reviewer account provenance (source-only)

Date: 2026-11-23 JST. Scope: public PCFM CI repository
`taku077/github-runner-availability-check`, isolated Draft PR #4 only.
No changes to private CI, PR merge, main Ruleset, GitHub App credentials,
Windows machine, Defender or collected evidence.

## Observed defect and bounded fix

SEC154/155 `ruleset_preflight.py` excluded self-approval only if
`pull_request.user.id` was present. If this field was absent/false/invalid,
a synthetic approval by the same actor could be counted as a distinct
reviewer, even though independent identity was unverified. Also, a
reviewer with an explicitly Bot/non-User account type could enter the
structural approval candidate set.

SEC159 requires positive integer PR author ID and API-shaped `type=User`;
missing/invalid author fails closed with PR_AUTHOR_ID_NOT_VERIFIED and
zero approval candidates. Each review actor must also have positive
integer ID and `type=User`, otherwise REVIEW_ACTOR_TYPE_NOT_VERIFIED
and REVIEW_HISTORY_AMBIGUOUS block structural approval counting.
The fixture and nine adversarial regressions were updated. GitHub's
REST PR review example exposes user.id and user.type, but these labels
do **not** attest a human, a separate person, control of the account,
or complete/unmodified provider audit data.

## Read-only live snapshot at development start

- Main: `1b33f359b1079d0c31fc964083991fd875cda304`.
- Draft PR #4: `b01a27fbd8d0abedef685f4b3276eb9da1392505`;
  review list: zero entries (GET pulls/4/reviews?per_page=100).
- Public PR HEAD check-runs: total_count=1; sole name
  `sec142-prototype-tests-not-a-required-gate`, App ID 15368
  (GitHub Actions), conclusion success.
- Ruleset 27806733: active, required_approving_review_count=0;
  required check only `env003-main-rules` from App ID 15368.
- Published prior PR CI 45132499956: successful 729 synthetic tests.
  New SEC159 exact-HEAD CI must be measured separately.

## Hard stop remains

This is read-only policy **simulation** in PR-controlled code.
A `User` label and different numeric account IDs cannot show human
independence. The prior model-input-origin RCA and live native ChatGPT
tool-dispatch interception remain unverified. No separately hosted
independent GitHub App, external immutable evidence store, owner
authorization for Ruleset changes, or actual merge-rejection test.
`INDEPENDENT_ENFORCEMENT=NOT_ACCEPTED`,
`PRODUCTION=BLOCKED`, `PC_INTRUSION=UNDETERMINED`.
Private CI failure diagnostics remain PAUSED.

Primary references:
- https://docs.github.com/en/rest/pulls/reviews
- https://docs.github.com/en/rest/repos/rules
- https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html
