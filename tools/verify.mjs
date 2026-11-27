// Where in Russia · independent receipt verifier. No dependencies, no Where in Russia code: WebCrypto and the public
// endpoints only. Node 20+ or any modern browser.
//   node verify.mjs receipt.json            checks the signature, the register entry and the transparency-log inclusion
//   node verify.mjs --snapshot              recomputes the knowledge snapshot digest from the published parts
const BASE = 'https://whereinrussia.com';
const canonical = v => Array.isArray(v) ? '[' + v.map(canonical).join(',') + ']'
  : v && typeof v === 'object' ? '{' + Object.keys(v).sort().map(k => JSON.stringify(k) + ':' + canonical(v[k])).join(',') + '}'
  : JSON.stringify(v);
const enc = new TextEncoder();
const hex = b => [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('');
const unhex = h => new Uint8Array(h.match(/../g).map(x => parseInt(x, 16)));
const sha = async b => new Uint8Array(await crypto.subtle.digest('SHA-256', b));
const b64u = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
const getJson = async p => (await fetch(BASE + p)).json();

export async function verifySignature(signed, jwks) {
  const { signature, ...body } = signed;
  const jwk = jwks.keys.find(k => k.kid === body.signed.kid);
  if (!jwk) return { valid: false, reason: 'unknown_key' };
  const key = await crypto.subtle.importKey('jwk', { kty: 'OKP', crv: 'Ed25519', x: jwk.x }, { name: 'Ed25519' }, false, ['verify']);
  const ok = await crypto.subtle.verify({ name: 'Ed25519' }, key, b64u(signature), enc.encode(canonical(body)));
  return { valid: ok && !jwk.revoked, signatureMatches: ok, keyStatus: jwk.status, revokedAt: jwk.revoked_at || null };
}
// RFC 9162 §2.1.3.2: root from a leaf hash, its index, the tree size and the audit path
export async function rootFromProof(leaf, index, size, path) {
  const node = async (l, r) => hex(await sha(new Uint8Array([1, ...unhex(l), ...unhex(r)])));
  let fn = index, sn = size - 1, r = leaf;
  for (const p of path) {
    if (sn === 0) return null;
    if (fn % 2 === 1 || fn === sn) { r = await node(p, r); if (fn % 2 === 0) while (fn % 2 === 0 && fn !== 0) { fn >>= 1; sn >>= 1; } }
    else r = await node(r, p);
    fn >>= 1; sn >>= 1;
  }
  return sn === 0 ? r : null;
}
export async function verifyReceipt(receipt) {
  const jwks = await getJson('/.well-known/jwks.json');
  const sig = await verifySignature(receipt, jwks);
  const id = hex(await sha(enc.encode(receipt.signature))).slice(0, 32);
  const proof = await getJson('/api/transparency/proof/' + id).catch(() => ({ found: false }));
  let log = { included: false, reason: proof.pending ? 'checkpoint for this day not signed yet' : 'not in the log' };
  if (proof.checkpoint) {
    const leafOk = hex(await sha(new Uint8Array([0, ...enc.encode(proof.leafData)]))) === proof.leaf && proof.leafData.startsWith(id + '|');
    const { digest, ...cp } = proof.checkpoint;
    const rootOk = (await rootFromProof(proof.leaf, proof.index, proof.size, proof.path)) === cp.root;
    log = { included: leafOk && rootOk, day: proof.day, checkpointSignature: await verifySignature(cp, jwks), checkpointCreated: cp.createdAt };
  }
  return { id, signature: sig, log };
}
export async function verifySnapshot() {
  const s = await getJson('/api/snapshots'), parts = {};
  for (const p of Object.keys(s.current.knowledge.parts)) parts[p] = hex(await sha(enc.encode(await (await fetch(`${BASE}/api/snapshots/current/${p}`)).text())));
  const digest = hex(await sha(enc.encode(canonical(parts))));
  return { matches: digest === s.current.knowledge.digest && Object.entries(parts).every(([k, v]) => v === s.current.knowledge.parts[k]), digest, published: s.current.knowledge.digest };
}
if (typeof process !== 'undefined' && process.argv && import.meta.url === `file://${process.argv[1]}`) {
  const arg = process.argv[2];
  const out = arg === '--snapshot' ? await verifySnapshot() : await verifyReceipt(JSON.parse((await import('node:fs')).readFileSync(arg, 'utf8')).receipt || JSON.parse((await import('node:fs')).readFileSync(arg, 'utf8')));
  console.log(JSON.stringify(out, null, 2));
}
