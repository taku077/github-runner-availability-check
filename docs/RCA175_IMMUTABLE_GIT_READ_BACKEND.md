# RCA175 — immutable public Git snapshot read backend (not an MCP server)

Purpose: turn RCA174's verified public Git mirror into a functioning
read-only search/fetch backend. There is no private source or credential
in this PR. It reads actual immutable Git objects from a local temporary
bare mirror, rather than calling GitHub REST for file contents.

Security properties of this narrowly scoped prototype:
- An exact PUBLIC_REMOTE is fixed; local mirror is ephemeral.
- Valid baseline SHA is pinned to the public main commit observed in RCA174.
- Only README.md is allowlisted as a document. Paths, arbitrary refs, repository
  selectors, command strings and URLs from model input are not accepted.
- Only the two operations search and fetch are exposed by the backend dispatch.
  Write/execute/approve/merge operations are rejected before Git subprocess.
- Reads use Git cat-file, not checkout/write; object type, byte size, UTF-8,
  SHA-256 and Git object SHA are checked. Search/fetch source hashes correlate.
- Ambient GitHub auth env, Git config overrides and SSH agent variables are
  omitted from Git subprocesses. No outbound request after local mirror clone.
- No token/SSH key provisioning, no user approval loop, no change to the
  connected ChatGPT GitHub plugin or other user projects.

This is ONLY a transport-agnostic backend. It does NOT provide the MCP
Streamable HTTP protocol, OAuth2.1 user authentication, an external immutable
private mirror, or a ChatGPT-visible private read-only connector.
According to OpenAI, readOnlyHint is metadata, not a server authorization
substitute. Modern MCP HTTP transport specification is 2026-07-28; this PR
does not hand-roll a client-facing pseudo-protocol.

Real public Git smoke:
  python3 security/sec142/rca175_mirror_read_backend.py --live-public

Expected: immutable README.md fetch, SHA-256 and Git blob SHA, bounded
case-insensitive search for "runner", hash equivalence and 0 Git remote
write commands. CI reads no private project material and no secrets.
No durable backup: bare mirror is removed after the smoke.

Next only after this passes: separate owner-controlled private mirror with
read-only Deploy Key and explicit OAuth resource server via a maintained MCP
SDK. Validate the private read data boundary, user token audience/scope,
tool request auth and current private Git ref integrity before any change to
the existing GitHub App installation. Testing on public Git is not evidence
that such private reader exists or that GitHub native writes are blocked.

Acceptance:
PUBLIC_PINNED_GIT_FETCH_SEARCH = CI evidence only;
PRIVATE_READ_REPLACEMENT = NOT_DEPLOYED;
MCP_OAUTH = NOT_DEPLOYED;
NATIVE_NON_BYPASS = NOT_IMPLEMENTED;
RCA_ORIGIN/THIRD_PARTY = UNDETERMINED;
PRODUCTION = BLOCKED.

Primary references:
https://developers.openai.com/plugins/build/mcp-server
https://developers.openai.com/plugins/build/auth
https://modelcontextprotocol.io/specification/2026-07-28/basic/transports
https://docs.github.com/en/authentication/connecting-to-github-with-ssh/managing-deploy-keys
