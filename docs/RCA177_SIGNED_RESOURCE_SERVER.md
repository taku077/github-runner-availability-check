# RCA177: signed synthetic JWT resource-server test
Uses official SDK 2.0.0 and PyJWT (already an SDK dependency) in the existing temporary public-only CI environment. Ephemeral RSA keys, .invalid test issuer, loopback endpoint, fixed public Git snapshot. The verifier accepts only RS256 access tokens, exact issuer/audience/client/subject, short expiry, not-before and allowed scope. SDK resource binding and required scopes are enabled. Actual HTTP tests exercise thirteen negative cases; no denied request may invoke a handler. A valid token must permit fixed search/fetch with hash verification. Protected resource metadata is checked. No real OAuth authorization-code exchange, JWKS rotation, external identity provider, revocation, proof of possession, HTTPS deployment, private Git access or native connector restriction. Bearer tokens remain replayable until expiry. Never use test issuer or key in production. No approval prompt or shared app setting change. CI branch is not an independent authority.

Sources:
https://py.sdk.modelcontextprotocol.io/run/authorization/
https://developers.openai.com/plugins/build/auth
https://www.rfc-editor.org/rfc/rfc9068
