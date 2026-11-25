# RCA174 real Git mirror read-only preflight (public provider)

This Stage is a real Git provider read, not a simulated approval test.
The Python standard-library adapter uses the Git CLI to mirror the PUBLIC
PCFM CI repository over unauthenticated HTTPS. It verifies git fsck, records
main/ref inventory, creates a local git bundle and verifies its SHA-256.
The temporary bundle is discarded when the process exits. It is not a
durable backup and contains no private PCFM code.

GitHub officially supports read-only deploy keys for ONE repository each.
A private deploy key held exclusively by an independently administered
service can perform SSH Git reads of the private PCFM repo, without giving
ChatGPT the deploy key or permission to write. This is a candidate, NOT
deployed or tested in this PR. Private deploy keys have no automatic expiry
and must be protected, rotated when necessary and never pasted into chat
or uploaded to public CI. Do not check Allow write access.

For ChatGPT to read that private mirror after its native GitHub access is
removed, an authenticated CUSTOM MCP read-only gateway must be connected
to the separate service. OpenAI requires OAuth-based user authorization
for private MCP data. This setup is not yet implemented or accepted.
No custom MCP magically intercepts the existing native GitHub write tools.
GitHub App installation selection must remain unchanged until replacement
read and writer are proven, with other projects unaffected.

Verification for public CI:
  python3 security/sec142/rca174_public_mirror.py --live-public

The public Git bundle does not contain GitHub Issues, PR reviews, CI
execution records, release assets or Git LFS objects unless gathered
separately. Thus fsck + bundle verify do not establish a full forensic
backup. A real private G1/G2 needs refs and LFS/hosted metadata coverage,
an independently stored, integrity-checked copy, and restore testing.

RCA174_PUBLIC_MIRROR is a narrow Git object integrity result.
PRIVATE_GIT_MIRROR=NOT_TESTED; PRIVATE_READ=NOT_DEPLOYED;
NATIVE_NON_BYPASS=NOT_IMPLEMENTED; USER_ATTRIBUTION=UNDETERMINED.

Sources:
https://docs.github.com/en/authentication/connecting-to-github-with-ssh/managing-deploy-keys
https://docs.github.com/en/enterprise-cloud@latest/repositories/archiving-a-github-repository/backing-up-a-repository
https://help.openai.com/en/articles/12584461-connecting-custom-mcp-servers-in-chatgpt
https://developers.openai.com/plugins/build/auth
