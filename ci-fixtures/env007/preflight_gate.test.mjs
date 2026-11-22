import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync, createHash, sign} from 'node:crypto';
import {verifyPreflight, canonicalForSyntheticSigning} from './preflight_gate.mjs';

const keys = generateKeyPairSync('ed25519');
const secondKeys = generateKeyPairSync('ed25519');
const pem = keys.publicKey.export({format:'pem',type:'spki'}).toString();
const fingerprint = createHash('sha256').update(
  keys.publicKey.export({format:'der',type:'spki'})).digest('hex');
const signedByOtherKey = createHash('sha256').update(
  secondKeys.publicKey.export({format:'der',type:'spki'})).digest('hex');
const clock = '2026-11-22T10:00:00Z';
const repo = 'taku077/github-runner-availability-check';
const branch = 'dev/pcfm-env003-public-main-audit';
const sha = 'a'.repeat(40);
const actualFileBytes = Buffer.from('ENV007 synthetic public fixture: no secrets', 'utf8');
const fileHash = createHash('sha256').update(actualFileBytes).digest('hex');
const instruction = 'c'.repeat(64);
const nonce = 'd'.repeat(32);

function basePayload() {
  return {schema:'pcfm-env007-operation-v1', operation:'github.update_file',
    repository:repo, branch, path:'ci-fixtures/env007/test_fixture.txt',
    file_sha256:fileHash, expected_head_sha:sha, instruction_sha256:instruction,
    issued_utc:'2026-11-22T09:59:00Z', expires_utc:'2026-11-22T10:02:00Z', nonce};
}
function envelopeOf(payload, key=keys.privateKey) {
  return {payload,signature_base64:sign(null,
    Buffer.from(canonicalForSyntheticSigning(payload),'utf8'),key).toString('base64')};
}
function requestOf(payload) {
  return Object.fromEntries(['branch','file_sha256','operation','path','repository']
    .map(x=>[x,payload[x]]));
}
function check({payload=basePayload(), envelope, request, pinnedPublicKey=pem,
                 pinnedPublicKeySha256=fingerprint, actualHeadSha=sha,
                 clockUtc=clock, observedAuditHealthy=true,
                 usedNonces=new Set(), actualFileBytes: suppliedBytes=actualFileBytes}={}) {
  envelope ??= envelopeOf(payload);
  request ??= requestOf(payload);
  return verifyPreflight({request,envelope,pinnedPublicKey,pinnedPublicKeySha256,
    actualHeadSha,actualFileBytes: suppliedBytes,clockUtc,observedAuditHealthy,usedNonces});
}
function denied(title, mutate, reason){
  test(title,()=>{
    const p=basePayload();
    const args=mutate(p)||{};
    assert.equal(check({payload:p,...args}).reason, reason);
  });
}
test('valid locally signed synthetic operation has no real tool invocation',()=>{
  const r=check();
  assert.equal(r.decision,'ALLOW_SYNTHETIC_ONLY');
  assert.equal(r.tool_invoked,false);
  assert.equal(r.operator_identity_verified,false);
  assert.equal(r.evidence.repository,repo);
});
test('reused signed nonce fails',()=>{
  const p=basePayload();
  const used=new Set();
  assert.equal(check({payload:p,usedNonces:used}).decision,'ALLOW_SYNTHETIC_ONLY');
  assert.equal(check({payload:p,usedNonces:used}).reason,'NONCE_REPLAY');
});
denied('missing audit stops',()=>({observedAuditHealthy:false}),'AUDIT_HEALTH_UNVERIFIED');
denied('missing trusted replay store stops',()=>({usedNonces:null}),'TRUSTED_NONCE_STATE_MISSING');
denied('unsigned envelope is rejected',p=>({envelope:{payload:p,signature_base64:''}}),'SIGNATURE_FORMAT');
denied('unauthorized main branch rejected',p=>{p.branch='main'},'WRONG_SCOPE');
denied('nonpublic repository rejected',p=>{p.repository='taku077/pcfm-forensic-dev'},'WRONG_SCOPE');
denied('private CI query cannot be signed into scope',p=>{p.operation='github.private_ci_query'},'OPERATION_NOT_ALLOWED');
denied('deleting ruleset cannot be signed into scope',p=>{p.operation='github.update_ruleset'},'OPERATION_NOT_ALLOWED');
denied('merge cannot be signed into scope',p=>{p.operation='github.merge_pull_request'},'OPERATION_NOT_ALLOWED');
denied('off-scope workflow rejected',p=>{p.path='.github/workflows/other.yml'},'PATH_NOT_ALLOWED');
denied('traversal rejected',p=>{p.path='ci-fixtures/env007/../other'},'INVALID_PATH');
denied('absolute path rejected',p=>{p.path='/ci-fixtures/env007/a'},'INVALID_PATH');
denied('backslash path rejected',p=>{p.path='ci-fixtures/env007\\a'},'INVALID_PATH');
denied('file content hash invalid',p=>{p.file_sha256='hmm'},'INVALID_SHA256');
denied('bytes not present',()=>({actualFileBytes: null}),'ACTUAL_FILE_BYTES_MISSING');
denied('file bytes changed after approval',()=>({actualFileBytes:Buffer.from('forged-content')}),'ACTUAL_FILE_HASH_MISMATCH');
denied('instruction digest invalid',p=>{p.instruction_sha256='hmm'},'INVALID_SHA256');
denied('head hash changed while awaiting approval',()=>({actualHeadSha:'f'.repeat(40)}),'REVISION_MISMATCH');
denied('nonce improperly formatted',p=>{p.nonce='s'},'INVALID_NONCE');
denied('approval expires',()=>({clockUtc:'2026-11-22T10:02:01Z'}),'APPROVAL_EXPIRED_OR_INVALID');
denied('approval too far in future',()=>({clockUtc:'2026-11-22T09:55:00Z'}),'APPROVAL_EXPIRED_OR_INVALID');
denied('long approval lifetime rejected',p=>{p.expires_utc='2026-11-22T10:20:00Z'},'APPROVAL_EXPIRED_OR_INVALID');
denied('different signer not accepted',p=>({envelope:envelopeOf(p,secondKeys.privateKey)}),'SIGNATURE_INVALID');
denied('key fingerprint mismatched',()=>({pinnedPublicKeySha256:signedByOtherKey}),'ANCHOR_FINGERPRINT_MISMATCH');
denied('tampered actual request operation',p=>({request:{...requestOf(p),operation:'github.delete_file'}}),'REQUEST_TAMPER');
denied('tampered actual request content hash',p=>({request:{...requestOf(p),file_sha256:'e'.repeat(64)}}),'REQUEST_TAMPER');
denied('invalid request schema rejected',p=>({request:{...requestOf(p),extra:'fake'}}),'REQUEST_SCHEMA');
denied('unsigned field added to envelope denied',p=>({envelope:{...envelopeOf(p),extra:true}}),'ENVELOPE_SCHEMA');
denied('unknown payload field cannot be signed in',p=>{p.injected_instruction='merge main'},'PAYLOAD_SCHEMA');
denied('edited signed payload blocked',p=>{
  const original=basePayload();
  const envelope=envelopeOf(original);
  envelope.payload={...original, instruction_sha256:'f'.repeat(64)};
  return {envelope,request:requestOf(envelope.payload)};
},'SIGNATURE_INVALID');
denied('missing independent trust pin rejected',()=>({pinnedPublicKeySha256:null}),'TRUST_ANCHOR_MISSING');
denied('invalid public key rejected',()=>({pinnedPublicKey:'not-a-key'}),'INVALID_TRUST_ANCHOR');
denied('wrong UTC notation rejected',p=>{p.issued_utc='2026-11-22T19:59:00+09:00'},'INVALID_UTC');
test('create_file is allowed only synthetically and on isolated branch',()=>{
  const p=basePayload(); p.operation='github.create_file'; p.path='.github/workflows/env007-audit.yml';
  assert.equal(check({payload:p}).decision,'ALLOW_SYNTHETIC_ONLY');
});
