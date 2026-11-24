# RCA176 — real SDK loopback Streamable HTTP public read proof

Only public data. Uses official MCP Python SDK v2.0.0 (test dependency pinned, not a production dependency lock). The process starts a loopback-only HTTP endpoint with a random short-lived test bearer value, exposes search/fetch of the immutable public README, checks SHA-256, and tests HTTP 401 for absent/wrong tokens plus error responses for invalid document IDs and nonexistent write tools. No private source, OAuth issuer, public hosting, account credentials, or native connector changes. This is an actual protocol/transport test, not an OAuth deployment or independent enforcement attestation. The ephemeral token is not a user identity or an approval. It is never printed. The SDK negotiates 2026-07-28; the test fails if another revision is selected. This optional CI stage cannot establish private read access, independent writer, or denial of the native GitHub connector. Read-only annotations are metadata; only fixed local Git reads are implemented.

Sources:
https://github.com/modelcontextprotocol/python-sdk/releases/tag/v2.0.0
https://py.sdk.modelcontextprotocol.io/client/
https://developers.openai.com/api/docs/mcp
https://developers.openai.com/plugins/build/auth
