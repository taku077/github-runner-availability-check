/**
 * PCFM ENV007 — standalone operation preflight decision prototype.
 * No GitHub API calls, no repo writes, no embedded private key, no secrets.
 * This is NOT installed in ChatGPT/GitHub's real tool-dispatch path.
 */
import { createHash, createPublicKey, verify } from 'node:crypto';

const REPOSITORY = 'taku077/github-runner-availability-check';
const BRANCH = 'dev/pcfm-env003-public-main-audit';
const FIELD_NAMES = [
  'schema', 'operation', 'repository', 'branch', 'path',
  'file_sha256', 'expected_head_sha', 'instruction_sha256',
  'issued_utc', 'expires_utc', 'nonce'
].sort();
const OPERATION_ALLOW = new Set(['github.create_file', 'github.update_file']);
const SHA256_PATTERN = /^[a-f0-9]{64}$/;
const SHA_PATTERN = /^[a-f0-9]{40}$/;
const NONCE_PATTERN = /^[a-f0-9]{32}$/;
const ISO_PATTERN = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/;
const MINUTE = 60_000;

function isExactObject(value, expectedKeys) {
  return value !== null && typeof value === 'object' &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype &&
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify(expectedKeys);
}

function canonical(value) {
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (value !== null && typeof value === 'object') {
    const keys = Object.keys(value).sort();
    return '{' + keys.map(k => JSON.stringify(k) + ':' + canonical(value[k])).join(',') + '}';
  }
  return JSON.stringify(value);
}
function digest(buffer) {
  return createHash('sha256').update(buffer).digest('hex');
}

export function verifyPreflight({ request, envelope, pinnedPublicKey, pinnedPublicKeySha256,
                                  actualHeadSha, clockUtc, observedAuditHealthy, usedNonces }) {
  const deny = (reason) => ({decision: 'DENY', reason, tool_invoked: false});
  if (observedAuditHealthy !== true) return deny('AUDIT_HEALTH_UNVERIFIED');
  if (!(usedNonces instanceof Set)) return deny('TRUSTED_NONCE_STATE_MISSING');
  if (!isExactObject(envelope, ['payload','signature_base64'])) return deny('ENVELOPE_SCHEMA');
  const payload = envelope.payload;
  if (!isExactObject(payload, FIELD_NAMES)) return deny('PAYLOAD_SCHEMA');
  if (!isExactObject(request, ['branch','file_sha256','operation','path','repository'])) {
    return deny('REQUEST_SCHEMA');
  }
  for (const k of ['repository', 'branch', 'path', 'file_sha256', 'operation']) {
    if (request[k] !== payload[k]) return deny('REQUEST_TAMPER');
  }
  if (payload.schema !== 'pcfm-env007-operation-v1' ||
      !OPERATION_ALLOW.has(payload.operation)) return deny('OPERATION_NOT_ALLOWED');
  if (payload.repository !== REPOSITORY || payload.branch !== BRANCH) return deny('WRONG_SCOPE');
  if (typeof payload.path !== 'string' || payload.path.length > 180 ||
      payload.path.includes('..') || payload.path.includes('//') ||
      payload.path.includes('\\') || payload.path.startsWith('/')) return deny('INVALID_PATH');
  if (!(payload.path.startsWith('ci-fixtures/env007/') ||
        payload.path.startsWith('.github/workflows/env007-'))) return deny('PATH_NOT_ALLOWED');
  if (![payload.file_sha256, payload.instruction_sha256].every(
       x => typeof x === 'string' && SHA256_PATTERN.test(x))) return deny('INVALID_SHA256');
  if (typeof payload.expected_head_sha !== 'string' ||
      !SHA_PATTERN.test(payload.expected_head_sha) ||
      !SHA_PATTERN.test(actualHeadSha || '') ||
      payload.expected_head_sha !== actualHeadSha) return deny('REVISION_MISMATCH');
  if (typeof payload.nonce !== 'string' || !NONCE_PATTERN.test(payload.nonce)) return deny('INVALID_NONCE');
  if (usedNonces.has(payload.nonce)) return deny('NONCE_REPLAY');
  if (![payload.issued_utc, payload.expires_utc, clockUtc].every(
       x => typeof x === 'string' && ISO_PATTERN.test(x) &&
       !Number.isNaN(Date.parse(x)))) return deny('INVALID_UTC');
  const now = Date.parse(clockUtc);
  const issued = Date.parse(payload.issued_utc);
  const expires = Date.parse(payload.expires_utc);
  if (issued > now + 60_000 || issued < now - 2 * MINUTE ||
      expires < now || expires <= issued ||
      expires - issued > 10 * MINUTE) return deny('APPROVAL_EXPIRED_OR_INVALID');
  if (typeof pinnedPublicKey !== 'string' ||
      typeof pinnedPublicKeySha256 !== 'string' ||
      !SHA256_PATTERN.test(pinnedPublicKeySha256)) return deny('TRUST_ANCHOR_MISSING');
  let key;
  try { key = createPublicKey(pinnedPublicKey); } catch { return deny('INVALID_TRUST_ANCHOR'); }
  if (key.asymmetricKeyType !== 'ed25519') return deny('WRONG_KEY_TYPE');
  const fingerprint = digest(key.export({format:'der', type:'spki'}));
  if (fingerprint !== pinnedPublicKeySha256) return deny('ANCHOR_FINGERPRINT_MISMATCH');
  if (typeof envelope.signature_base64 !== 'string' ||
      !/^[A-Za-z0-9+/]{86}==$/.test(envelope.signature_base64)) return deny('SIGNATURE_FORMAT');
  const signature = Buffer.from(envelope.signature_base64, 'base64');
  if (signature.length !== 64) return deny('SIGNATURE_LENGTH');
  let ok = false;
  try { ok = verify(null, Buffer.from(canonical(payload), 'utf8'), key, signature); }
  catch { return deny('SIGNATURE_VERIFICATION_ERROR'); }
  if (!ok) return deny('SIGNATURE_INVALID');
  // A caller must atomically persist nonce consumption BEFORE acting.
  // This function only mutates in-memory test state: no real dispatch.
  usedNonces.add(payload.nonce);
  return {decision: 'ALLOW_SYNTHETIC_ONLY', reason: 'SIGNATURE_AND_SCOPE_MATCH',
          tool_invoked: false, operator_identity_verified: false,
          evidence: {approval_payload_sha256: digest(Buffer.from(canonical(payload))),
                     pinned_key_sha256: fingerprint, operation: payload.operation,
                     repository: payload.repository, branch: payload.branch,
                     path: payload.path, expected_head_sha: payload.expected_head_sha}};
}

export function canonicalForSyntheticSigning(value) {
  return canonical(value);
}
