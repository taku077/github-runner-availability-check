# RCA171: public GitHub live evidence without actor-attribution claims

Code in this Draft PR is a read-only historical source observation, not a
trusted authorization gate. It makes only fixed unauthenticated GitHub REST
GET requests for seven public Git commit objects, PR #4 and #5, their review
lists, and public Ruleset 27806733. It verifies the six-commit PR5 parent
chain and records Git object committer UTC, signature verification status,
the latest PR heads, review count, and ruleset review requirement.

The live API observations are **not an independent third-party signature**.
Git object committer timestamps are not proof of GitHub push receipt times.
Unsigned commits, PR reviewer count and account names do not prove or
exclude a user, ChatGPT, or third-party actor. Required authenticated
request IDs, token/session IDs, actual model input, and native dispatcher
audit remain NOT_ACQUIRED. Attribution is UNDETERMINED.

Only Python stdlib, no secrets, no upload, no Windows or private CI; no
new approvals, shared-app permission changes, or effects on other projects.
Run local unit tests using the PR's existing unittest discovery.
Run the public readback via:
  python3 security/sec142/rca171_provider_evidence.py --live

If the network/public GitHub API fails, live verification is NOT_VERIFIED.
The existing PR-controlled CI is NOT a separately administered protection.
External independent gate and evidence custody remain NOT_IMPLEMENTED.

Sources:
- https://docs.github.com/en/rest/commits/commits
- https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/security-log-events
- https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/reviewing-your-security-log
- https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html

## Actual CI execution and external readback limitation (2026-11-24 JST)

- Public PR#4 commit 439c0caf263a460cb53b84e9dbc06b3d0dd7236c:
  GitHub Actions run 45225258013, 750/750 unittest PASS; unauthenticated
  public REST live readback FAILED (HTTPError).
- Diagnostic commit b6b7b5187adcb3e6fba515d953f77fe8cae86df3:
  run 45225610430, 750/750 unittest PASS; live step HTTP_STATUS=403.
  The 403 cause is NOT_DETERMINED (rate limit / authorization / other).
- This optional live probe deliberately receives no GITHUB_TOKEN or PAT.
  A missing/failed readback is explicitly marked NOT_VERIFIED, never treated
  as independent authorization or authenticated-actor evidence.
- A failure of this supplemental public REST check does not invalidate the
  local pure-unit 750-test security-prototype smoke checks. The CI run summary
  alone is not sufficient to assert the live readback succeeded; inspect
  RCA171_LIVE_STEP_OUTCOME.
- ChatGPT's live GitHub connector separately read the historical commits,
  but that connector observation is not the public CI runner's successful
  result, nor a third-party signed audit.
