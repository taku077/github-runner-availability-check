# PCFM SEC158 — side-effect-free mock and actual tool-boundary acceptance

**Status: DESIGN / PR-CONTROLLED SYNTHETIC CODE ONLY**
Recorded 2026-11-23 JST. Repo is PCFM's public CI repo
taku077/github-runner-availability-check, isolated Draft PR #4.
This is not a third-party independent authority, provider-authenticated
gate, signed runtime trace, or permission to touch the stopped private CI.

## I. Security defect fixed in SEC157 simulation

The SEC157 class SimulatedDispatch originally accepted an arbitrary
Python callable as its constructor argument. For a policy-matched request,
it invoked that callable with the proposed tool name/parameters.
All SEC157 fixtures used an inert local Recorder, so no actual network
operation occurred in the observed CI. **However, the source allowed a
caller to accidentally supply a real API client**. The claim that the
class itself could never cause a side effect was therefore too strong.

SEC158 removes Callable imports, the callback slot and all invocation.
SimulatedDispatch() takes no handler, has __slots__ containing only
non-sensitive counters, and returns (ScopedDecision, None) for **both**
denied and shape-matched arguments. Its legacy method name "dispatch"
is just a test name. It cannot forward the examined call to an injected
client through this class. A separate program could of course call a
real connector directly, since no actual trusted execution hook exists.

New test_pure_dispatch.py verifies:
- construction with callback/handler is rejected, dynamic handler
  assignment is rejected, and the no-op class contains only the
  simulate_policy call in its AST;
- a shape-matched public-CI read and a narrowly shaped private handoff
  read both return None with all native-execution/authorization fields
  false;
- a paused private CI request remains denied even after an earlier
  shape match; no mock state changes authorization across attempts;
- source_label and owner_override_claim, including callable values,
  never grant authority or run a hook;
- malformed mapping subclasses, irrelevant native tool aliases,
  retired CI run/runner actions, and suspicious private API operations
  are rejected by the *mock*.

This AST test is a narrow regression aid, not independent proof that
another piece of code will not open sockets or use a native connector.
No test in SEC158 invokes private CI or genuine GitHub runner APIs.

## II. Actual tool-path coverage is NOT established

The following are **coverage questions**, not claims that an attacker
used those paths. None is under a mandatory external gate here.

| Path | Needed proof before operational acceptance | Current |
|---|---|---|
| Native GitHub named calls | All direct invocations pass through one authenticated policy, without alternate access | NOT_ACQUIRED |
| Generic GitHub REST fetch / arbitrary URL | Alias and URL-canonicalization bypass attempts are denied *at execution*, not only in mock | NOT_ACQUIRED |
| GraphQL or alternate API endpoints | Authorized operations and resource identity resolved after normalization | NOT_ACQUIRED |
| GitHub application/user/installation tokens | All credentials scoped to required resources and unavailable to unmediated tools | NOT_DEPLOYED |
| Browser/computer/network clients | Cannot bypass the protected tool boundary to reach the same private API | NOT_ATTESTED |
| Orchestration/function-call layers | Every nested/delegated call is checked, including retries and saved jobs | NOT_ATTESTED |
| Connected Drive content / registry / handoff | Untrusted text may inform analysis, cannot create a new private-CI execution grant | MOCK_ONLY |
| User consent and exception channel | Verified independent actor, exact tool/resource/parameters, single-use expiry, atomic consume | NOT_ACQUIRED |
| Denial audit receipts | Independently controlled trusted clock, actor/resource identity, policy version, immutable signed record | NOT_ACQUIRED |
| Provider-side absence of denied request | A verified independent trace shows no forbidden endpoint received a denied call | NOT_ACQUIRED |

A model can still use a direct native GitHub tool without referencing
the public Python file. A malicious source can also modify this file,
tests or CI result because it is in the PR-controlled branch.
The term "independent enforcement" therefore remains NOT_ACCEPTED.

## III. Future architecture: enforce where effects actually occur

OWASP AI Agent Security and MCP guidance recommend authorization in the
execution component, outside model context. For PCFM, a potential
trusted broker would be administered separately from the PR author:

1. Capture the **actual** tool execution request as structured,
   immutable parameters, resolving the true repository identity,
   API method and path, operation class, intended side effect, actor
   and exact target. Unknown or alternate routes must fail closed.
2. Enforce paused-private-CI denial regardless of model prose,
   prior registry next, handoff, assistant proposal, or fabricated
   user_confirmed flag. The stop restriction is higher priority
   than historical instructions. NO exception in current phase.
3. If the owner later issues an explicit **target-specific** instruction,
   a separate authorized service verifies actor/consent, records one
   use with exact request-binding, expiry and replay prevention.
   An assistant-generated "approved" field is never sufficient.
4. Keep credentials and provider egress accessible *only* to the broker;
   otherwise even correct validation code is bypassable. Use
   least-privilege scopes, deny unexpected repos and methods, and
   separately govern policy changes. No broad user token inside a
   public Actions preview or developer-controlled host.
5. Write a minimal independent audit receipt containing the allow/deny
   rule ID, repository/method, request-parameter digest, timestamp
   source, policy hash/version, authentication context and outcome,
   with sensitive values redacted. Store append-only outside the
   model/PR-controlled environment; verify signature and custody.
6. Test on a **disposable, owner-authorized analog** repository.
   Prove a negative case results in no downstream provider request,
   including alternate URL, GraphQL, delegation, retry, unknown tool,
   changed parameters, stale consent and crash/recovery paths.
   Do NOT probe the stopped private CI as a test.
7. Recheck the actual live access-path inventory after connector
   upgrades. If even one bypass route is reachable, fail acceptance.
   Independently review the broker policy and the evidence packet.

The actual ChatGPT tool gateway is not under control of this public
Python module. There is no present proof all native paths can be
routed through a mandatory broker. If platform policy does not provide
such a hook, scope credentials away from the model-facing connection
or disable relevant access rather than claiming Python-level protection.
These are conditional design recommendations, **not changes made**.

## IV. RCA provenance and outstanding attribution

Private RCA documents show two historical propagation pathways:
old registry.next and later handoff text promoted a stopped task
after a generic "continue." Those visible facts do not reveal the
first source of the wording or prove malicious third-party access.
Model assembled inputs, native tool dispatch/approval originals,
GitHub/Drive actor session logs, provider security records and
a trusted exception channel are NOT_ACQUIRED. Do not infer
third-party activity or assert the initial cause was established.

A successful public Actions run can attest *only its own job's*
success against the code present in the untrusted PR branch.
It does not attest that ChatGPT changed its runtime tool policy,
that private CI is inaccessible, or that an independent App exists.

## V. Exit criteria and decisions

- Source-only acceptance: **eligible after exact final-head CI success**.
- Runtime callback-miswire hazard in the SEC157 mock: **mitigated within
  the revised class**, subject to source-review and regression limits.
- Native tool interception: **NOT_DEPLOYED / NOT_PROVEN**.
- Actor and approval authentication: **NOT_ACQUIRED**.
- Live unauthorized action rejection on a disposable analog: NOT_TESTED.
- Independent GitHub App/Ruleset enforcement: NOT_ACCEPTED.
- Stopped private CI failure diagnostics: PAUSED / not inspected.
- Production PCFM: BLOCKED; actual Windows PC intrusion: UNDETERMINED;
  original instruction provenance and third-party involvement: UNDETERMINED.

No App install, Ruleset/main mutation, PR merge, Windows/Defender/EVTX
intervention, or private CI troubleshooting is authorized by this design.

## Primary sources

- OWASP AI Agent Security Cheat Sheet
  https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html
- OWASP MCP Security Cheat Sheet
  https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html
- OWASP LLM Prompt Injection Prevention Cheat Sheet
  https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html
- GitHub REST authentication and App permissions
  https://docs.github.com/en/rest/authentication/authenticating-to-the-rest-api
  https://docs.github.com/en/rest/authentication/permissions-required-for-github-apps
