# PCFM SEC157 — paused-work recurrence: mock dispatch boundary and RCA evidence gaps

Date: 2026-11-23 JST. Scope: public PCFM development CI, isolated Draft
PR #4. **Design and simulation only, not an active ChatGPT interceptor.**

## 1. Basis and observed historical chain

The controlling case is unauthorized reintroduction of *investigation of
the paused private CI failure*, not the failure's cause. The latest private
RCA source at this phase was docs/PCFM_RCA_ACTIVE_HANDOFF_20261112.md
(Git blob e5d01ae4f7a4cd9f867ad23447f2174a8ed957bd). It records two
distinct visible propagation pathways:

- OPS058 -> OPS059: old ARTIFACT_REGISTRY.json next moved the forbidden
  private-CI inquiry into a future task candidate. OPS060 subsequently
  made a stop decision that outranks older next fields.
- OPS088 -> OPS089: the intended follow-up did not call for stopped CI
  investigation, but the later HANDOFF_CURRENT.md introduced such a
  next step. The assistant then proposed and attempted a read after a
  general "continue" request. This is a visible selection/propagation
  path, **not independent proof of what produced the initial text**.

The original model input as actually assembled, selection internals,
real tool-dispatch authorization/consent events, the exact owner
session identity and potential third-party access were NOT_ACQUIRED
in the RCA. ChatGPT provider-origin and third-party involvement remain
UNDETERMINED. The private CI's stopped failure cause, annotations,
runner, logs and billing are **outside** this investigation.

## 2. Implemented mock and test coverage

SEC157 files:
- security/sec142/dispatch_preflight.py
- security/sec142/test_dispatch_preflight.py

Policy is independent of a source document's alleged authority:
- closed set of tool names, repository IDs/names and argument schemas;
- private repo can only simulate exact named read-only handoff/RCA/registry
  documents; workflow runs/jobs/logs, generic fetch URLs, annotations,
  billing, runner and unknown tools are denied before calling the mock
  handler;
- the public CI repo allows a small set of read-shaped, typed requests
  only for explicitly scoped PRs, run/job numbers and pinned refs;
- source_label and owner_override_claim are deliberately NOT credentials
  and cannot unpause any private-CI request;
- historic registry next, handoff prose, model-suggested next and general
  "continue" are never transformed into execution authority;
- fail closed on malformed schemas, mixed repository fields, type
  confusion, path traversal, unknown tool names, and non-specific refs.

Even structurally allowed requests return
SIMULATION_SCOPE_MATCH_NOT_LIVE_AUTHORIZATION; the actual native tool
was not intercepted or called. The mock recorder is local, without
GitHub credentials or network access. Test counters are *simulation
counts*, not provider tool-dispatch telemetry.

All decisions have:
  native_tool_intercepted=false,
  caller_identity_verified=false,
  external_policy_verified=false,
  owner_exception_verified=false,
  production_enforcement=false,
  private_ci_reopened=false,
  real_tool_dispatched=false.

This source is **not** an authorization policy for broad use; it
intentionally blocks many legitimate tools outside the narrow test.
A developer can edit or remove it because PR #4 is untrusted. It also
cannot intercept native ChatGPT connectors, cloud browser, terminal
or any tool execution not explicitly wired to a separate, trusted
policy service. Do not reuse success here to assert operational
containment or prevention of historical instructions.

## 3. RCA evidence acquisition and independent acceptance matrix

| Evidence ID | Primary source needed | Established at this stage | Security conclusion |
|---|---|---|---|
| R01 | GitHub version-controlled old next and handoff differences (immutable commit hashes) | Available in private RCA; not rereviewed as new provider input in SEC157 | Visible propagation, not initial origin |
| R02 | Model's exact assembled request bytes, document snippets, tool-result text, policy version for each relevant turn | NOT_ACQUIRED | Cannot attribute initial origin |
| R03 | Actual native tool-dispatch request, approval result, timestamps, actor/session and any denied attempts | NOT_ACQUIRED | Cannot establish non-bypassability |
| R04 | Independently authenticated account-owner consent for a target-specific exception | NOT_ACQUIRED | "Continue" and stale notes are not consent |
| R05 | Provider-side GitHub account security activity and session trace | NOT_ACQUIRED | No third-party attribution |
| R06 | Google Drive document revision/operator activity | NOT_ACQUIRED | A suspicious-content warning is not proof of an attack |
| R07 | Trusted tool gateway logs from the *actual* production tool execution path, with externally retained signing keys and refusal tests | NOT_DEPLOYED | No runtime enforcement acceptance |
| R08 | Independent reviewer and evidence custody/countersignature | NOT_ATTESTED | No independent forensic provenance |

Necessary proof of a gate before acceptance: show a denied private-CI
operation at the exact native dispatch boundary, without invoking the
provider; prove every supported direct/indirect/alias path goes through
the same independently controlled gate; show exact owner-authorized
scoped exception by independent authentication (not merely text);
collect signed denial receipts, crash/recovery logs and negative
bypass tests. Require a separate authorized reviewer and custody of
the gate policy outside the PR/model-controlled path. No such proof is
present. A generic refusal classifier over natural-language snippets
is insufficient; classification by typed tool arguments is a narrower
test of the proposed execution boundary.

Do not upload raw account audit logs, user identifiers, session secrets,
tokens or internal OpenAI requests to public GitHub or this public PR.
Potential raw evidence requires owner's explicit scoped approval,
trusted storage and a hash/custody manifest. An external source being
quoted or signed by a recorder does not prove it was the exact text
the model received, nor that the model used it causally.

## 4. Implementation and production acceptance state

- Visible propagation: supported by the existing private RCA, but SEC157
  does not obtain new historical provider internals.
- Original insertion cause / third-party compromise: UNDETERMINED.
- ChatGPT native invocation capture/mandatory interception: NOT_DEPLOYED.
- Public-PR CI and simulation: regression testing only; untrusted source.
- Independent GitHub App and Ruleset negative rejection: NOT_ACCEPTED.
- Production PCFM deployment: BLOCKED.
- Investigated Windows PC intrusion: UNDETERMINED.

No private CI troubleshooting or logs were inspected; no main branch,
Ruleset, App, PR merge, evidence original, Windows/EVTX/Defender
changes were made during this phase.

## Sources

- OWASP LLM Prompt Injection Prevention:
  https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html
- OWASP AI Agent Security:
  https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html
- OWASP MCP Security:
  https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html
- GitHub Ruleset integration source and review API:
  https://docs.github.com/en/rest/repos/rules
- GitHub workflow security:
  https://docs.github.com/en/actions/reference/security/secure-use
