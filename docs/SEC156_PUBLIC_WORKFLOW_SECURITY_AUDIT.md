# PCFM SEC156 — source-only GitHub Actions workflow boundary audit

Recorded: 2026-11-23 JST. Scope: **public** PCFM CI repository
taku077/github-runner-availability-check, isolated Draft PR #4 only.
This is NOT a signed GitHub inspection report, independent App check,
AI tool-dispatch gateway, live Ruleset enforcement test, or authority
to modify or merge a branch.

## 1. Actual source inspection

At baseline PR #4 HEAD
9071e62deddec96b72cbc01ac0dc18a53cb9419f, a read-only GitHub tree
query reported 13 files in .github/workflows/ (complete tree,
truncated=false). We fetched all 13 workflow definitions, inspected their
event, token-permission, external-Action and secret-reference statements,
and preserved the following Git blob IDs as source locators:

| Workflow | Blob SHA |
|---|---|
| hayabusa-offline-fixture.yml | 1a8b055594621dfbd5d583a0266a06d9529f767e |
| ops045-detection-controls.yml | 7e0c7b2a13a4fbef64adf7a8e65191d88456cad4 |
| ops046-benign-events.yml | cbb93dfbe3d1784daac0da05ad3b2c3fabbd6e21 |
| ops047-native-evtx-preserve.yml | 50afebb64f8ff233830c1058d0b6068cd710cd75 |
| ops048-recordid-linkage.yml | f56c6c19d5a24033d80db05e15ebab104457a2cb |
| ops049-ground-truth-gate.yml | d65bd0acc9858ce891c39e4fd73b7ed740149227 |
| ops052-otrf-archive-review.yml | d6f01ef6501bb4af145495eee0192d20754ee708 |
| ops053-otrf-nested-keys.yml | 5992214a04243161112c8692dc2da1b7bead84dd |
| ops056-native-handle-share.yml | aa3df39f16e80ea1d1b5d1a9800c5c4f03f748a9 |
| ops057-bound-security.yml | a25ae8937d3a32102a090f4c0ea9a52081cae39b |
| public-go-fixture.yml | 245cfa9311da67308a51eb7a29015aa0026b71b3 |
| runner-smoke.yml | 4a6c27a5a757d837e0d9eaa29b8c00bc6c71b15d |
| sec142-external-admission-prototype.yml | 994299042276ae1b453f90a829b9bb6869369fd7 |

At this point no workflow showed a pull_request_target trigger,
workflow_run, issue_comment or repository_dispatch trigger. All were
observed with explicit top-level token permission declarations (contents
read; some also actions read), external actions pinned to a 40-hex
commit SHA, and checkout persist-credentials false where checkout
was used. Two artifact-read workflows use the built-in
secrets.GITHUB_TOKEN with actions:read; this is not an additional
user-managed secret. These are bounded *source observations*, not
runtime execution or complete YAML-semantic attestations.

## 2. SEC156 prototype and regression controls

New security/sec142/workflow_boundary.py is a stdlib-only static
preview, restricted to a narrow, explicitly declared workflow subset:

- event list only push, pull_request, workflow_dispatch; flag
  pull_request_target / workflow_run / issue_comment / unknown events;
- root permissions must be explicit contents:read with no unchecked
  write scopes, job-level overrides require review;
- action refs must be pinned by literal 40-hex SHA and may not
  silently resolve to local actions;
- checkout must explicitly disable persistent credentials;
- flag nondefault secrets and direct GitHub event/head-ref
  interpolation in shell run blocks;
- flag unsupported YAML/aliases, missing or ambiguous mappings,
  overlarge files, noncanonical references and checkout anomalies.

New test_workflow_boundary.py runs the audit over the 13 checked-out
workflow files and multiple synthetic adversarial mutations.
The preview ALWAYS returns
PR_CONTROLLED_STATIC_PREVIEW_NOT_AUTHORIZED with independent-policy,
operator, provider, check-written and merge-authorized flags false.

**Critical limitation:** This is deliberately NOT a full YAML parser,
semantic shell analyzer, or real GitHub Actions evaluation. A creatively
encoded payload or new syntax may evade the scanner. The PR author can
change the code/test/workflow together, or remove the check; source-only
green CI cannot bind a separately governed trust root. For true protection,
an external security policy must independently inspect an immutable tree
at the exact SHA and pin the independent check source in the branch
Ruleset, with real rejection tests and separate reviewer authorization.

## 3. Intermediate CI evidence

The first test run 45060526478 failed in 14 unittest subtests:
the regular expression used a whitespace matcher spanning a newline
after a valid top-level on: key, causing **false positives** across the
13 valid workflow corpus and the nominal SEC142 fixture.
The expression was changed to a same-line-only match. The failure
must remain in audit history, not be described as a security break-in.
Final source SHA, CI run and job status are recorded in the SEC156 PR
comment and private handoff only after observed passing CI.

## 4. AI tool-selection RCA remains a separate issue

The verified historical handoff/registry propagation in
docs/PCFM_RCA_ACTIVE_HANDOFF_20261112.md concerns AI tool dispatch,
not workflow trigger semantics. That RCA describes two known pathways:
a historical registry next promoted forbidden work, and a later handoff
reintroduced forbidden work despite a prior stop decision. The first
origin of those instructions and any third-party involvement are
UNDETERMINED. The native ChatGPT tools are NOT forced through an
external policy gateway. No local static workflow scan can prove
or prevent an AI action-selection failure.

The stopped private CI's failure reasons/logs/runner/billing remain
**strictly outside** the authorized investigation. A generic "continue"
does not authorize those calls. The RCA's missing model inputs, actual
tool-dispatch records, provider access logs and explicit consent
records remain NOT_ACQUIRED; avoid false claims of root cause proof.
Do not publicize sensitive future account logs.

## 5. Acceptance and next actions

This stage's acceptance is limited to source-only regression detection.
No independent GitHub App/operator/credentials, no Ruleset edits,
no PR merge, no protected-host network collection, no Windows host/EVTX/
Defender access, no actual unauthorized-PR rejection or recovery test.

Next actionable work before live enforcement:
obtain independently verified owner/operator/reviewer authorization,
protected App key custody, a non-PR-controlled policy source, provider-
authenticated source+effective rule readback, a disposable live reject
test, rollback plan and separate AI tool-dispatch enforcement controls.

Final conditions: INDEPENDENT_ENFORCEMENT=NOT_ACCEPTED;
PRODUCTION=BLOCKED; PC_INTRUSION=UNDETERMINED;
RCA_ORIGIN=UNDETERMINED.

Official references:
- https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target
- https://docs.github.com/en/actions/reference/security/secure-use
- https://docs.github.com/en/actions/concepts/security/script-injections
- https://docs.github.com/en/rest/repos/rules?apiVersion=2026-03-10
