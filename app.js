const DEFAULT_RPC = (() => {
  if (location.protocol === 'http:' || location.protocol === 'https:') return location.origin.replace(/\/$/, '') + '/rpc';
  return 'https://trpc.kodok.lol/rpc';
})();

const CHAIN_ID = 801;
const FIXED_FEE_WEI = '1000000000000000';
const DECIMALS = 18n;
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const VAULT_KEY = 'rafaela_web_wallet_vault_spa_v3';
const OLD_VAULT_KEY = 'rafaela_web_wallet_vault_v2';
const THEME_KEY = 'rafaela_wallet_theme';
const RPC_KEY = 'rafaela_rpc_url';
const WORDS = Array.from({ length: 256 }, (_, i) => 'rafa' + i.toString(16).padStart(2, '0'));
const WORD_INDEX = Object.fromEntries(WORDS.map((w, i) => [w, i]));

const P256 = {
  p: BigInt('0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff'),
  a: BigInt('0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc'),
  b: BigInt('0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b'),
  n: BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551'),
  gx: BigInt('0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296'),
  gy: BigInt('0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5')
};

let session = { unlocked: false, wallet: null, privateKey: null };
let pendingWallet = null;
let pendingSecrets = { phrase: '', privateKey: '' };
let verifyPositions = [];
let phraseVisible = false;
let privateVisible = false;

const $ = id => document.getElementById(id);
const enc = new TextEncoder();
const dec = new TextDecoder();

function has(id) { return !!$(id); }
function nowTime() { return new Date().toLocaleTimeString(); }
function toast(message, type = 'ok', title = type === 'err' ? 'Error' : type === 'warn' ? 'Notice' : 'Rafaela') {
  const host = $('toastHost');
  if (!host) return;
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.innerHTML = `<strong>${escapeHTML(title)}</strong><small>${escapeHTML(message)}</small>`;
  host.prepend(el);
  setTimeout(() => el.remove(), 5200);
}
function log(x) {
  if (!has('log')) return;
  const line = typeof x === 'string' ? x : JSON.stringify(x, null, 2);
  $('log').textContent = `[${nowTime()}] ${line}\n\n` + $('log').textContent;
}
function escapeHTML(s) {
  return String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
function truncateMiddle(s, a = 15, b = 10) {
  s = String(s || '');
  return s.length > a + b + 3 ? s.slice(0, a) + '…' + s.slice(-b) : s;
}
function bytesToB64(buf) { return btoa(String.fromCharCode(...new Uint8Array(buf))); }
function b64ToBytes(s) { return Uint8Array.from(atob(s), c => c.charCodeAt(0)); }
function b64urlToBytes(s) {
  s = String(s || '').replace(/-/g, '+').replace(/_/g, '/');
  s += '='.repeat((4 - s.length % 4) % 4);
  return b64ToBytes(s);
}
function bytesToB64url(bytes) {
  return bytesToB64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}
function randomBytes(n) { const a = new Uint8Array(n); crypto.getRandomValues(a); return a; }
async function sha256(buf) { return crypto.subtle.digest('SHA-256', buf); }
function base58Encode(bytes) {
  let x = 0n;
  for (const b of bytes) x = (x << 8n) + BigInt(b);
  let out = '';
  while (x > 0n) { const m = x % 58n; out = B58[Number(m)] + out; x = x / 58n; }
  for (const b of bytes) { if (b === 0) out = B58[0] + out; else break; }
  return out || B58[0];
}
async function addressFromSpki(spki) { const h = new Uint8Array(await sha256(spki)); return '@rafa.' + base58Encode(h); }
function validAddress(a) { return /^@rafa\.[1-9A-HJ-NP-Za-km-z]{40,55}$/.test(String(a || '')); }
function decimalToWei(s) {
  s = String(s || '').trim();
  if (!/^\d+(\.\d+)?$/.test(s)) throw new Error('Invalid amount');
  const [w, f = ''] = s.split('.');
  if (f.length > Number(DECIMALS)) throw new Error('Too many decimals');
  return (BigInt(w) * 10n ** DECIMALS + BigInt((f || '').padEnd(Number(DECIMALS), '0'))).toString();
}
function weiToDecimal(s, max = 8) {
  let n = BigInt(s || '0');
  const base = 10n ** DECIMALS;
  const whole = n / base;
  let frac = String(n % base).padStart(Number(DECIMALS), '0').replace(/0+$/g, '');
  if (frac.length > max) frac = frac.slice(0, max);
  return frac ? `${whole}.${frac}` : String(whole);
}
function bytesToBigInt(bytes) { let x = 0n; for (const b of bytes) x = (x << 8n) + BigInt(b); return x; }
function bigIntToBytes(n, len = 32) {
  let hex = n.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  const raw = hex.match(/../g)?.map(x => parseInt(x, 16)) || [];
  const out = new Uint8Array(len);
  out.set(raw.slice(-len), len - Math.min(len, raw.length));
  return out;
}
function mod(a, p = P256.p) { const r = a % p; return r >= 0n ? r : r + p; }
function invMod(a, p = P256.p) {
  let t = 0n, newT = 1n, r = p, newR = mod(a, p);
  while (newR !== 0n) {
    const q = r / newR;
    [t, newT] = [newT, t - q * newT];
    [r, newR] = [newR, r - q * newR];
  }
  if (r > 1n) throw new Error('Not invertible');
  return t < 0n ? t + p : t;
}
function pointAdd(P, Q) {
  if (!P) return Q;
  if (!Q) return P;
  if (P.x === Q.x && mod(P.y + Q.y) === 0n) return null;
  let m;
  if (P.x === Q.x && P.y === Q.y) {
    m = mod((3n * P.x * P.x + P256.a) * invMod(2n * P.y));
  } else {
    m = mod((Q.y - P.y) * invMod(Q.x - P.x));
  }
  const x = mod(m * m - P.x - Q.x);
  const y = mod(m * (P.x - x) - P.y);
  return { x, y };
}
function scalarMult(k, P = { x: P256.gx, y: P256.gy }) {
  let N = P, Q = null;
  while (k > 0n) {
    if (k & 1n) Q = pointAdd(Q, N);
    N = pointAdd(N, N);
    k >>= 1n;
  }
  return Q;
}
function phraseFromScalarBytes(bytes) { return Array.from(bytes).map(b => WORDS[b]).join(' '); }
function scalarBytesFromPhrase(phrase) {
  const words = String(phrase || '').toLowerCase().trim().split(/\s+/).filter(Boolean);
  if (words.length !== 32) throw new Error('Recovery phrase must contain 32 Rafaela words.');
  const bytes = new Uint8Array(32);
  words.forEach((w, i) => {
    if (!(w in WORD_INDEX)) throw new Error(`Unknown phrase word: ${w}`);
    bytes[i] = WORD_INDEX[w];
  });
  return bytes;
}
function jwkFromScalarBytes(bytes) {
  const d = bytesToBigInt(bytes);
  if (d <= 0n || d >= P256.n) throw new Error('Invalid private key scalar.');
  const pub = scalarMult(d);
  return {
    kty: 'EC', crv: 'P-256', ext: true,
    d: bytesToB64url(bigIntToBytes(d, 32)),
    x: bytesToB64url(bigIntToBytes(pub.x, 32)),
    y: bytesToB64url(bigIntToBytes(pub.y, 32))
  };
}
async function walletFromJwk(jwk) {
  const privateKey = await crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);
  const publicJwk = { kty: 'EC', crv: 'P-256', ext: true, x: jwk.x, y: jwk.y };
  const publicKey = await crypto.subtle.importKey('jwk', publicJwk, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);
  const spki = await crypto.subtle.exportKey('spki', publicKey);
  const address = await addressFromSpki(spki);
  return {
    payload: { address, privateJwk: jwk, publicKeySpkiB64: bytesToB64(spki), chainId: CHAIN_ID, createdAt: Date.now() },
    privateKey
  };
}
function normalizePrivateKeyInput(s) {
  s = String(s || '').trim();
  if (!s) throw new Error('Private key input is empty.');
  try { const parsed = JSON.parse(s); return parsed.privateJwk || parsed; } catch {}
  try {
    const text = dec.decode(b64ToBytes(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - s.length % 4) % 4)));
    return JSON.parse(text);
  } catch {}
  const maybeWords = s.toLowerCase().split(/\s+/).filter(Boolean);
  if (maybeWords.length === 32) return jwkFromScalarBytes(scalarBytesFromPhrase(s));
  throw new Error('Private key must be JSON, base64url JSON, or a 32-word Rafaela phrase.');
}
function privateKeyExportString(jwk) { return bytesToB64url(enc.encode(JSON.stringify(jwk))); }
function canonicalMessage(from, to, amountWei, feeWei, nonce) { return `rafaela-tx:v1|chainId=${CHAIN_ID}|from=${from}|to=${to}|amount=${amountWei}|fee=${feeWei}|nonce=${nonce}`; }
function canonicalInteropMessage(from, to, source, destination, amountWei, feeWei, nonce, memo) { return `rafaela-interop:v1|chainId=${CHAIN_ID}|from=${from}|to=${to}|source=${source}|destination=${destination}|amount=${amountWei}|fee=${feeWei}|nonce=${nonce}|memo=${memo}`; }
function canonicalArgs(args) { const keys = Object.keys(args || {}).sort(); return keys.length ? keys.map(k => `${k}=${args[k]}`).join('&') : '{}'; }
function canonicalContractDeployMessage(from, template, name, symbol, decimals, maxSupplyWei, initialSupplyWei, feeWei, nonce, metadata = '') { return `rafaela-contract-deploy:v1|chainId=${CHAIN_ID}|from=${from}|template=${String(template).trim().toLowerCase()}|name=${String(name).trim()}|symbol=${String(symbol).trim().toUpperCase()}|decimals=${decimals}|maxSupply=${maxSupplyWei}|initialSupply=${initialSupplyWei}|fee=${feeWei}|nonce=${nonce}|metadata=${String(metadata).trim()}`; }
function canonicalContractCallMessage(from, contractId, method, args, feeWei, nonce) { return `rafaela-contract-call:v1|chainId=${CHAIN_ID}|from=${from}|contract=${String(contractId).trim()}|method=${String(method).trim()}|args=${canonicalArgs(args)}|fee=${feeWei}|nonce=${nonce}`; }
function canonicalStakeMessage(from, amountWei, feeWei, nonce) { return `rafaela-stake:v1|chainId=${CHAIN_ID}|from=${from}|amount=${amountWei}|fee=${feeWei}|nonce=${nonce}`; }
function canonicalUnstakeMessage(from, amountWei, feeWei, nonce) { return `rafaela-unstake:v1|chainId=${CHAIN_ID}|from=${from}|amount=${amountWei}|fee=${feeWei}|nonce=${nonce}`; }
function canonicalClaimStakeRewardMessage(from, feeWei, nonce) { return `rafaela-stake-claim:v1|chainId=${CHAIN_ID}|from=${from}|fee=${feeWei}|nonce=${nonce}`; }
function rpcUrl() { return ($('rpcUrlModal')?.value.trim() || localStorage.getItem(RPC_KEY) || DEFAULT_RPC).replace(/\/$/, ''); }
async function rpc(method, params = []) {
  const res = await fetch(rpcUrl(), { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', method, params, id: Date.now() }) });
  const json = await res.json();
  if (json.error) throw new Error(json.error.message);
  return json.result;
}
async function deriveVaultKey(pin, salt) {
  const base = await crypto.subtle.importKey('raw', enc.encode(pin), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: 250000, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
async function encryptVault(payload, pin) {
  if (!pin || pin.length < 6) throw new Error('PIN must be at least 6 characters.');
  const salt = randomBytes(16), iv = randomBytes(12), key = await deriveVaultKey(pin, salt);
  const cipher = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(JSON.stringify(payload)));
  return { version: 3, wallet: 'rafaela-spa', kdf: 'PBKDF2-SHA256', iterations: 250000, cipher: 'AES-GCM-256', salt: bytesToB64(salt), iv: bytesToB64(iv), data: bytesToB64(cipher), createdAt: Date.now() };
}
async function decryptVault(vault, pin) {
  const salt = b64ToBytes(vault.salt), iv = b64ToBytes(vault.iv), data = b64ToBytes(vault.data);
  const key = await deriveVaultKey(pin, salt);
  const raw = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, data);
  return JSON.parse(dec.decode(raw));
}
function loadVault() {
  const raw = localStorage.getItem(VAULT_KEY) || localStorage.getItem(OLD_VAULT_KEY);
  return raw ? JSON.parse(raw) : null;
}
function saveVaultRaw(vault) { localStorage.setItem(VAULT_KEY, JSON.stringify(vault)); localStorage.removeItem(OLD_VAULT_KEY); }
function setView() {
  const vault = loadVault();
  $('authView').classList.toggle('hidden', session.unlocked);
  $('dashboardView').classList.toggle('hidden', !session.unlocked);
  $('createStartCard').classList.toggle('hidden', !!pendingWallet || !!vault || session.unlocked);
  $('unlockCard').classList.toggle('hidden', !vault || !!pendingWallet || session.unlocked);
  $('vaultBadge').textContent = vault ? 'Vault found' : 'No vault';
}
function updateDashboard() {
  if (!session.wallet) return;
  $('shortAddress').textContent = truncateMiddle(session.wallet.address, 18, 12);
}
function displayPendingWallet() {
  if (!pendingWallet) return;
  $('newAddress').value = pendingWallet.address;
  $('newPublicKey').value = pendingWallet.publicKeySpkiB64;
  updateSecretBoxes();
  buildVerifyChallenge();
  $('backupCard').classList.remove('hidden');
  $('pinCard').classList.add('hidden');
  setView();
}
function updateSecretBoxes() {
  $('phraseBox').textContent = phraseVisible ? pendingSecrets.phrase : 'Hidden';
  $('phraseBox').classList.toggle('revealed', phraseVisible);
  $('privateKeyBox').textContent = privateVisible ? pendingSecrets.privateKey : 'Hidden';
  $('privateKeyBox').classList.toggle('revealed', privateVisible);
}
function buildVerifyChallenge() {
  const words = pendingSecrets.phrase.split(/\s+/);
  verifyPositions = [];
  while (verifyPositions.length < 3) {
    const n = crypto.getRandomValues(new Uint32Array(1))[0] % words.length;
    if (!verifyPositions.includes(n)) verifyPositions.push(n);
  }
  $('verifyFields').innerHTML = verifyPositions.map((pos, i) => `
    <div>
      <label>Word #${pos + 1}</label>
      <input id="verifyWord${i}" autocomplete="off" spellcheck="false" placeholder="rafa..">
    </div>
  `).join('');
}
function assertPending() { if (!pendingWallet) throw new Error('Create or import a wallet first.'); }
async function createWallet() {
  const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const jwk = await crypto.subtle.exportKey('jwk', kp.privateKey);
  const spki = await crypto.subtle.exportKey('spki', kp.publicKey);
  const address = await addressFromSpki(spki);
  pendingWallet = { address, privateJwk: jwk, publicKeySpkiB64: bytesToB64(spki), chainId: CHAIN_ID, createdAt: Date.now() };
  pendingSecrets.phrase = phraseFromScalarBytes(b64urlToBytes(jwk.d));
  pendingSecrets.privateKey = privateKeyExportString(jwk);
  session.privateKey = kp.privateKey;
  phraseVisible = false; privateVisible = false;
  displayPendingWallet();
  toast('Wallet created. Back up phrase/private key, then verify 3 words.', 'ok');
  log({ created: true, address });
}
async function importPendingFromJwk(jwk) {
  const w = await walletFromJwk(jwk);
  pendingWallet = w.payload;
  pendingSecrets.phrase = phraseFromScalarBytes(b64urlToBytes(jwk.d));
  pendingSecrets.privateKey = privateKeyExportString(jwk);
  session.privateKey = w.privateKey;
  phraseVisible = false; privateVisible = false;
  displayPendingWallet();
  toast('Wallet imported. Verify backup, then create a local PIN.', 'ok');
  log({ imported: true, address: pendingWallet.address });
}
async function importPhraseOrPrivateKey() {
  const phrase = $('importPhrase')?.value.trim();
  const pk = $('importPrivateKey')?.value.trim();
  if (!phrase && !pk) throw new Error('Paste recovery phrase or private key.');
  const jwk = phrase ? jwkFromScalarBytes(scalarBytesFromPhrase(phrase)) : normalizePrivateKeyInput(pk);
  await importPendingFromJwk(jwk);
  closeModal();
}
async function importBackupFile(file) {
  const text = await file.text();
  const obj = JSON.parse(text);
  if (obj.privateJwk) {
    await importPendingFromJwk(obj.privateJwk);
    return;
  }
  if (obj.data && obj.salt && obj.iv) {
    saveVaultRaw(obj);
    pendingWallet = null;
    toast('Encrypted wallet JSON imported. Enter PIN to unlock.', 'ok');
    log('Encrypted wallet JSON imported.');
    setView();
    return;
  }
  throw new Error('Unsupported wallet JSON.');
}
function verifyPhrase() {
  assertPending();
  const words = pendingSecrets.phrase.split(/\s+/);
  const ok = verifyPositions.every((pos, i) => ($(`verifyWord${i}`).value || '').trim().toLowerCase() === words[pos]);
  if (!ok) throw new Error('Phrase verification failed. Check the requested words.');
  $('pinCard').classList.remove('hidden');
  toast('Backup verified. Create your PIN.', 'ok');
}
async function savePin() {
  assertPending();
  const p1 = $('newPin').value, p2 = $('confirmPin').value;
  if (p1 !== p2) throw new Error('PIN confirmation does not match.');
  const vault = await encryptVault(pendingWallet, p1);
  saveVaultRaw(vault);
  session.wallet = pendingWallet;
  session.unlocked = true;
  session.privateKey = await crypto.subtle.importKey('jwk', session.wallet.privateJwk, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);
  pendingWallet = null;
  pendingSecrets = { phrase: '', privateKey: '' };
  $('newPin').value = ''; $('confirmPin').value = '';
  $('backupCard').classList.add('hidden'); $('pinCard').classList.add('hidden');
  updateDashboard(); setView();
  toast('PIN saved. Dashboard opened.', 'ok');
  await refreshBalance().catch(e => toast(e.message, 'warn'));
}
async function unlockWallet() {
  const vault = loadVault();
  if (!vault) throw new Error('No local wallet found.');
  const payload = await decryptVault(vault, $('pinInput').value);
  session.wallet = payload;
  session.privateKey = await crypto.subtle.importKey('jwk', payload.privateJwk, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);
  session.unlocked = true;
  $('pinInput').value = '';
  updateDashboard(); setView();
  toast('Wallet unlocked.', 'ok');
  log({ unlocked: true, address: payload.address });
  await refreshBalance();
}
function lockWallet() {
  session = { unlocked: false, wallet: null, privateKey: null };
  toast('Wallet locked.', 'warn');
  log('Wallet locked.');
  setView();
}
function deleteWallet() {
  if (!confirm('Delete encrypted wallet from this browser? Make sure you already downloaded a backup.')) return;
  localStorage.removeItem(VAULT_KEY); localStorage.removeItem(OLD_VAULT_KEY);
  lockWallet();
  toast('Local wallet deleted.', 'warn');
}
async function refreshBalance(writeLog = true) {
  if (!session.wallet) throw new Error('Unlock wallet first.');
  const [b, n] = await Promise.all([rpc('rafa_getBalance', [session.wallet.address]), rpc('rafa_getNonce', [session.wallet.address])]);
  const bal = weiToDecimal(b.balance_wei, 6);
  $('balance').textContent = bal;
  $('assetBalance').textContent = bal;
  $('nonce').textContent = n.nonce;
  if (writeLog) log({ balance: b.balance_rafa, nonce: n.nonce });
  return { balance: b, nonce: n };
}
async function signAndSendRaw(rawBuilder) {
  if (!session.unlocked) throw new Error('Unlock wallet first.');
  const nonceRes = await rpc('rafa_getNonce', [session.wallet.address]);
  const nonce = Number(nonceRes.nonce) + 1;
  const raw = await rawBuilder(nonce);
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, session.privateKey, enc.encode(raw.message));
  raw.signature = bytesToB64(sig);
  raw.public_key = session.wallet.publicKeySpkiB64;
  return raw;
}
async function sendTx(to, amountRafa) {
  if (!validAddress(to)) throw new Error('Invalid recipient address.');
  const amountWei = decimalToWei(amountRafa);
  const raw = await signAndSendRaw(async nonce => {
    const msg = canonicalMessage(session.wallet.address, to, amountWei, FIXED_FEE_WEI, nonce);
    return { chain_id: CHAIN_ID, from: session.wallet.address, to, amount_wei: amountWei, fee_wei: FIXED_FEE_WEI, nonce, message: msg };
  });
  const sent = await rpc('rafa_sendRawTransaction', [raw]);
  toast(`Transfer sent in block ${sent.block}.`, 'ok');
  log({ sent: true, hash: sent.hash, block: sent.block });
  await refreshBalance(false);
  openReceipt('Transfer receipt', sent.hash, sent.block, [ ['To', to], ['Amount', `${amountRafa} RAFA`], ['Fee', '0.001 RAFA'] ]);
}
async function claimFaucet() {
  if (!session.wallet) throw new Error('Unlock wallet first.');
  const base = rpcUrl().replace(/\/rpc\/?$/, '');
  const res = await fetch(base + '/faucet/claim', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ address: session.wallet.address }) });
  const json = await res.json();
  if (!json.ok) throw new Error(json.error || 'Faucet failed');
  toast('Faucet claimed.', 'ok');
  log(json);
  await refreshBalance(false);
}
async function refreshStake(writeLog = true) {
  if (!session.wallet) throw new Error('Unlock wallet first.');
  const out = await rpc('rafa_getStake', [session.wallet.address]);
  const staked = weiToDecimal(out.principal_wei || '0');
  const reward = weiToDecimal(out.claimable_reward_wei || '0');
  if (has('stakeSummary')) $('stakeSummary').innerHTML = stakeSummaryHTML(out, staked, reward);
  if (writeLog) log({ staking: out });
  return out;
}
function stakeSummaryHTML(out, staked, reward) {
  return `<div class="mini-stats">
    <span>Staked <strong>${escapeHTML(staked)} RAFA</strong></span>
    <span>Claimable <strong>${escapeHTML(reward)} RAFA</strong></span>
    <span>APR <strong>${Number(out.apr_bp || 1000) / 100}%</strong></span>
  </div>
  <p class="hint">Weekly reward eligibility · Minimum stake 1 RAFA · Staking does not automatically make this wallet a validator.</p>`;
}
async function stakeRAFA(amountRafa) {
  const amountWei = decimalToWei(amountRafa);
  const raw = await signAndSendRaw(async nonce => ({ chain_id: CHAIN_ID, from: session.wallet.address, amount_wei: amountWei, fee_wei: FIXED_FEE_WEI, nonce, message: canonicalStakeMessage(session.wallet.address, amountWei, FIXED_FEE_WEI, nonce) }));
  const sent = await rpc('rafa_stake', [raw]);
  toast('Stake transaction confirmed.', 'ok'); log({ staked: true, hash: sent.hash, block: sent.block, position: sent.position }); await refreshBalance(false); await refreshStake(false);
}
async function unstakeRAFA(amountRafa) {
  const amountWei = String(amountRafa || '').trim() ? decimalToWei(amountRafa) : '0';
  const raw = await signAndSendRaw(async nonce => ({ chain_id: CHAIN_ID, from: session.wallet.address, amount_wei: amountWei, fee_wei: FIXED_FEE_WEI, nonce, message: canonicalUnstakeMessage(session.wallet.address, amountWei, FIXED_FEE_WEI, nonce) }));
  const sent = await rpc('rafa_unstake', [raw]);
  toast('Unstake transaction confirmed.', 'ok'); log({ unstaked: true, hash: sent.hash, block: sent.block, net_return_wei: sent.net_return_wei }); await refreshBalance(false); await refreshStake(false);
}
async function claimStakeReward() {
  const raw = await signAndSendRaw(async nonce => ({ chain_id: CHAIN_ID, from: session.wallet.address, fee_wei: FIXED_FEE_WEI, nonce, message: canonicalClaimStakeRewardMessage(session.wallet.address, FIXED_FEE_WEI, nonce) }));
  const sent = await rpc('rafa_claimStakeReward', [raw]);
  toast('Stake reward claimed.', 'ok'); log({ stake_reward_claimed: true, hash: sent.hash, block: sent.block, net_reward_wei: sent.net_reward_wei }); await refreshBalance(false); await refreshStake(false);
}
async function loadZones() {
  const zones = await rpc('rafa_l0GetZones');
  return (zones.items || []).filter(z => z.id !== 'rafaela-hub' && z.status === 'active');
}
async function sendInteropTx(destination, to, amountRafa, memo = '') {
  if (!destination) throw new Error('Choose destination zone.');
  if (!validAddress(to)) throw new Error('Invalid destination address.');
  const amountWei = decimalToWei(amountRafa);
  memo = String(memo || '').slice(0, 240);
  const raw = await signAndSendRaw(async nonce => ({ chain_id: CHAIN_ID, from: session.wallet.address, to, source_zone_id: 'rafaela-hub', destination_zone_id: destination, amount_wei: amountWei, fee_wei: FIXED_FEE_WEI, nonce, memo, message: canonicalInteropMessage(session.wallet.address, to, 'rafaela-hub', destination, amountWei, FIXED_FEE_WEI, nonce, memo) }));
  const sent = await rpc('rafa_l0SendPacket', [raw]);
  toast(`L0 packet created: ${truncateMiddle(sent.packet.id, 12, 6)}.`, 'ok'); log({ l0_packet_sent: true, packet: sent.packet.id, hash: sent.hash, block: sent.block }); await refreshBalance(false);
}
async function deployContract(form) {
  const template = form.template;
  const name = form.name || (template === 'raf721' ? 'Rafaela NFT' : 'Rafaela Token');
  const symbol = (form.symbol || (template === 'raf721' ? 'RNFT' : 'R20')).toUpperCase();
  const maxRaw = form.max || (template === 'raf721' ? '10000' : '1000000');
  const initialRaw = form.initial || '0';
  const maxSupplyWei = template === 'raf721' || template === 'kv' ? maxRaw : decimalToWei(maxRaw);
  const initialSupplyWei = template === 'raf20' ? decimalToWei(initialRaw) : '0';
  const decimals = template === 'raf20' ? 18 : 0;
  const raw = await signAndSendRaw(async nonce => ({ chain_id: CHAIN_ID, from: session.wallet.address, template, name, symbol, decimals, max_supply_wei: maxSupplyWei, initial_supply_wei: initialSupplyWei, metadata: '', fee_wei: FIXED_FEE_WEI, nonce, message: canonicalContractDeployMessage(session.wallet.address, template, name, symbol, decimals, maxSupplyWei, initialSupplyWei, FIXED_FEE_WEI, nonce, '') }));
  const sent = await rpc('rafa_contractDeploy', [raw]);
  toast(`Contract deployed: ${sent.contract_id}`, 'ok'); log({ contract_deployed: true, contract_id: sent.contract_id, hash: sent.hash, block: sent.block }); await refreshBalance(false);
}
async function callContract(contractId, method, args) {
  const raw = await signAndSendRaw(async nonce => ({ chain_id: CHAIN_ID, from: session.wallet.address, contract_id: contractId, method, args, fee_wei: FIXED_FEE_WEI, nonce, message: canonicalContractCallMessage(session.wallet.address, contractId, method, args, FIXED_FEE_WEI, nonce) }));
  const sent = await rpc('rafa_contractCall', [raw]);
  toast('Contract call sent.', 'ok'); log({ contract_call: true, hash: sent.hash, block: sent.block, result: sent.result, events: sent.events }); await refreshBalance(false);
}
async function queryContract(contractId, query, args) {
  const out = await rpc('rafa_contractQuery', [contractId, query || 'metadata', args || {}]);
  toast('Contract query complete.', 'ok'); log({ contract_query: true, out }); return out;
}
function openModal(title, html, setup, eyebrow = 'Wallet') {
  $('modalTitle').textContent = title;
  $('modalEyebrow').textContent = eyebrow;
  $('modalBody').innerHTML = html;
  $('modalBackdrop').classList.remove('hidden');
  setup?.();
}
function closeModal() { $('modalBackdrop').classList.add('hidden'); $('modalBody').innerHTML = ''; }
function openConfirm(title, rows, onConfirm) {
  openModal(title, `<div class="review-card">${rows.map(([k, v]) => `<div class="review-row"><span>${escapeHTML(k)}</span><code>${escapeHTML(v)}</code></div>`).join('')}</div><div class="modal-actions"><button id="cancelConfirm" type="button">Cancel</button><button id="yesConfirm" class="primary" type="button">Yes, Continue</button></div>`, () => {
    $('cancelConfirm').onclick = closeModal;
    $('yesConfirm').onclick = () => run(async () => { await onConfirm(); }, 'Transaction failed');
  }, 'Confirm');
}
function openReceipt(title, hash, block, rows) {
  openModal(title, `<div class="receipt-card"><div class="review-row"><span>Status</span><code>Sent</code></div><div class="review-row"><span>Hash</span><code>${escapeHTML(hash)}</code></div><div class="review-row"><span>Block</span><code>${escapeHTML(block)}</code></div>${rows.map(([k, v]) => `<div class="review-row"><span>${escapeHTML(k)}</span><code>${escapeHTML(v)}</code></div>`).join('')}</div><div class="modal-actions"><button id="closeReceipt" class="primary" type="button">Done</button></div>`, () => $('closeReceipt').onclick = closeModal, 'Receipt');
}
function parsePaymentPayload(text) {
  text = String(text || '').trim();
  try {
    const o = JSON.parse(text);
    return { address: o.address || o.to, amount: o.amount || o.amount_rafa || '' };
  } catch {}
  if (text.startsWith('rafaela:')) {
    const u = new URL(text.replace('rafaela:', 'https://wallet.local/'));
    return { address: u.pathname.replace(/^\//, ''), amount: u.searchParams.get('amount') || '' };
  }
  return { address: text, amount: '' };
}
async function scanQrFromFile(file) {
  if (!('BarcodeDetector' in window)) throw new Error('QR scan needs a browser with BarcodeDetector support. Paste address manually if unavailable.');
  const detector = new BarcodeDetector({ formats: ['qr_code'] });
  const bitmap = await createImageBitmap(file);
  const codes = await detector.detect(bitmap);
  if (!codes.length) throw new Error('No QR code found in image.');
  return codes[0].rawValue;
}
async function qrSVG(text, size = 29) {
  const hash = new Uint8Array(await sha256(enc.encode(text)));
  const cells = [];
  function bit(i) { return (hash[Math.floor(i / 8) % hash.length] >> (i % 8)) & 1; }
  function finder(x, y) { for (let yy = 0; yy < 7; yy++) for (let xx = 0; xx < 7; xx++) { const edge = xx === 0 || yy === 0 || xx === 6 || yy === 6; const core = xx >= 2 && xx <= 4 && yy >= 2 && yy <= 4; if (edge || core) cells.push(`<rect x="${x + xx}" y="${y + yy}" width="1" height="1"/>`); } }
  finder(1, 1); finder(size - 8, 1); finder(1, size - 8);
  let i = 0;
  for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) {
    const inFinder = (x < 9 && y < 9) || (x > size - 10 && y < 9) || (x < 9 && y > size - 10);
    if (!inFinder && bit(i++)) cells.push(`<rect x="${x}" y="${y}" width="1" height="1"/>`);
  }
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" shape-rendering="crispEdges"><rect width="${size}" height="${size}" fill="white"/><g fill="#1b0d18">${cells.join('')}</g></svg>`;
}
async function renderReceiveQR() {
  const amount = $('receiveAmount')?.value.trim() || '';
  const payload = JSON.stringify({ chain: 'rafaela', address: session.wallet.address, amount_rafa: amount, symbol: 'RAFA' });
  const svg = await qrSVG(payload);
  $('qrBox').innerHTML = svg;
  $('qrPayload').textContent = payload;
}
function downloadText(filename, text, type = 'application/json') {
  const blob = new Blob([text], { type });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob); a.download = filename; a.click(); URL.revokeObjectURL(a.href);
}
function downloadPendingWalletFile() {
  assertPending();
  const data = { type: 'rafaela-plain-wallet-export', warning: 'Contains private key. Store offline.', address: pendingWallet.address, publicKeySpkiB64: pendingWallet.publicKeySpkiB64, privateJwk: pendingWallet.privateJwk, recoveryPhrase: pendingSecrets.phrase, chainId: CHAIN_ID, exportedAt: Date.now() };
  downloadText(`rafaela-wallet-${pendingWallet.address.slice(6, 14)}.json`, JSON.stringify(data, null, 2));
  toast('Wallet file downloaded. Keep it private.', 'warn');
}
function exportEncryptedBackup() {
  const raw = localStorage.getItem(VAULT_KEY);
  if (!raw) throw new Error('No encrypted vault found.');
  downloadText('rafaela-encrypted-wallet-backup.json', raw);
  toast('Encrypted backup exported.', 'ok');
}
function openImportPopup() {
  openModal('Import wallet', `
    <label>Recovery phrase</label><textarea id="importPhrase" placeholder="rafa00 rafa01 ... 32 words"></textarea>
    <label>Private key JSON / base64url JSON</label><textarea id="importPrivateKey" placeholder='{"kty":"EC","crv":"P-256",...}'></textarea>
    <div class="modal-actions"><button id="cancelImport" type="button">Cancel</button><button id="doImport" class="primary" type="button">Import Wallet</button></div>
  `, () => {
    $('cancelImport').onclick = closeModal;
    $('doImport').onclick = () => run(importPhraseOrPrivateKey, 'Import failed');
  }, 'Restore');
}
function openSendModal(prefill = {}) {
  openModal('Send RAFA', `
    <label>Recipient address</label><input id="sendTo" spellcheck="false" placeholder="@rafa.longBase58Address" value="${escapeHTML(prefill.address || '')}">
    <div class="scan-row"><label for="scanFile" class="file-label">Scan QR Image</label><input id="scanFile" type="file" accept="image/*" hidden><span class="hint">Camera/file scan uses browser BarcodeDetector when available.</span></div>
    <label>Amount</label><input id="sendAmount" inputmode="decimal" placeholder="1.25" value="${escapeHTML(prefill.amount || '')}">
    <div class="review-card"><div class="review-row"><span>Network fee</span><code>0.001 RAFA</code></div></div>
    <button id="reviewSend" class="primary full" type="button">Review Transfer</button>
  `, () => {
    $('scanFile').onchange = e => run(async () => { const raw = await scanQrFromFile(e.target.files[0]); const p = parsePaymentPayload(raw); if (p.address) $('sendTo').value = p.address; if (p.amount) $('sendAmount').value = p.amount; toast('QR parsed.', 'ok'); }, 'QR scan failed');
    $('reviewSend').onclick = () => {
      const to = $('sendTo').value.trim(); const amount = $('sendAmount').value.trim();
      openConfirm('Confirm transfer', [['From', session.wallet.address], ['To', to], ['Amount', `${amount} RAFA`], ['Fee', '0.001 RAFA']], async () => sendTx(to, amount));
    };
  }, 'Transfer');
}
function openReceiveModal() {
  openModal('Receive RAFA', `
    <div class="qr-wrap"><div class="qr-canvas" id="qrBox"></div><div><label>Your address</label><div class="address-block">${escapeHTML(session.wallet.address)}</div><label>Request amount, optional</label><input id="receiveAmount" inputmode="decimal" placeholder="2"><p class="hint">The QR payload follows the typed amount. You can download or share it.</p><div class="two-actions"><button id="downloadQR" type="button">Download QR</button><button id="shareReceive" type="button">Share</button></div></div></div>
    <label>Payload</label><div id="qrPayload" class="address-block"></div>
  `, () => {
    renderReceiveQR(); $('receiveAmount').oninput = () => renderReceiveQR();
    $('downloadQR').onclick = () => { const svg = $('qrBox').innerHTML; downloadText('rafaela-receive-qr.svg', svg, 'image/svg+xml'); };
    $('shareReceive').onclick = () => run(async () => { const text = $('qrPayload').textContent; if (navigator.share) await navigator.share({ title: 'Rafaela payment request', text }); else await navigator.clipboard.writeText(text); toast('Receive payload shared/copied.', 'ok'); }, 'Share failed');
  }, 'Receive');
}
function openStakeModal() {
  openModal('Stake RAFA', `
    <div id="stakeSummary" class="stake-summary">Loading staking data...</div>
    <div class="form-grid"><div><label>Stake amount</label><input id="stakeAmount" inputmode="decimal" placeholder="10"></div><div><label>Unstake amount, empty = all</label><input id="unstakeAmount" inputmode="decimal" placeholder="Leave empty"></div></div>
    <div class="modal-actions"><button id="refreshStakeModal" type="button">Refresh</button><button id="reviewStake" class="primary" type="button">Stake</button><button id="reviewUnstake" type="button">Unstake</button><button id="reviewClaimStake" type="button">Claim Reward</button></div>
  `, () => {
    refreshStake(false).catch(e => $('stakeSummary').textContent = e.message);
    $('refreshStakeModal').onclick = () => run(() => refreshStake(true), 'Stake refresh failed');
    $('reviewStake').onclick = () => openConfirm('Confirm stake', [['Amount', `${$('stakeAmount').value} RAFA`], ['Fee', '0.001 RAFA']], async () => stakeRAFA($('stakeAmount').value));
    $('reviewUnstake').onclick = () => openConfirm('Confirm unstake', [['Amount', $('unstakeAmount').value || 'All available principal'], ['Fee', '0.001 RAFA']], async () => unstakeRAFA($('unstakeAmount').value));
    $('reviewClaimStake').onclick = () => openConfirm('Confirm claim reward', [['Action', 'Claim weekly stake reward'], ['Fee', '0.001 RAFA']], claimStakeReward);
  }, 'Native staking');
}
function openDeployModal() {
  openModal('Deploy Contract', `
    <div class="form-grid"><div><label>Template</label><select id="contractTemplate"><option value="raf20">RAF20 Token</option><option value="raf721">RAF721 NFT</option><option value="kv">KV dApp Storage</option></select></div><div><label>Symbol</label><input id="contractSymbol" placeholder="DEMO"></div><div><label>Name</label><input id="contractName" placeholder="Demo Token"></div><div><label>Max supply / NFT count</label><input id="contractMax" placeholder="1000000"></div><div class="wide"><label>Initial supply, RAF20 only</label><input id="contractInitial" placeholder="1000"></div></div>
    <button id="reviewDeploy" class="primary full" type="button">Review Deploy</button>
  `, () => $('reviewDeploy').onclick = () => {
    const form = { template: $('contractTemplate').value, name: $('contractName').value.trim(), symbol: $('contractSymbol').value.trim(), max: $('contractMax').value.trim(), initial: $('contractInitial').value.trim() };
    openConfirm('Confirm contract deploy', [['Template', form.template], ['Name', form.name || '(default)'], ['Symbol', form.symbol || '(default)'], ['Fee', '0.001 RAFA']], async () => deployContract(form));
  }, 'Smart contract');
}
function openQueryModal() {
  openModal('Call / Query Contract', `
    <label>Contract ID</label><input id="callContractId" placeholder="rct_...">
    <div class="form-grid"><div><label>Call method</label><input id="callMethod" placeholder="transfer / mint / set"></div><div><label>Query name</label><input id="queryName" placeholder="metadata / balanceOf / ownerOf"></div><div class="wide"><label>Call args JSON</label><textarea id="callArgs" placeholder='{"to":"@rafa...","amount_wei":"1000000000000000000"}'></textarea></div><div class="wide"><label>Query args JSON</label><textarea id="queryArgs" placeholder='{"address":"@rafa..."}'></textarea></div></div>
    <div class="modal-actions"><button id="doQuery" type="button">Query</button><button id="reviewCall" class="primary" type="button">Review Call</button></div>
  `, () => {
    $('doQuery').onclick = () => run(async () => { const out = await queryContract($('callContractId').value.trim(), $('queryName').value.trim(), JSON.parse($('queryArgs').value.trim() || '{}')); toast('Query output sent to console.', 'ok'); }, 'Query failed');
    $('reviewCall').onclick = () => { const args = JSON.parse($('callArgs').value.trim() || '{}'); openConfirm('Confirm contract call', [['Contract', $('callContractId').value.trim()], ['Method', $('callMethod').value.trim()], ['Fee', '0.001 RAFA']], async () => callContract($('callContractId').value.trim(), $('callMethod').value.trim(), args)); };
  }, 'Web3');
}
function openSettingsModal() {
  openModal('Settings & Security', `
    <div class="settings-card"><label>RPC endpoint</label><input id="rpcUrlModal" spellcheck="false" value="${escapeHTML(localStorage.getItem(RPC_KEY) || DEFAULT_RPC)}"><p id="rpcStatus" class="hint">RPC target: ${escapeHTML(localStorage.getItem(RPC_KEY) || DEFAULT_RPC)}</p><div class="modal-actions"><button id="checkRpc" type="button">Check</button><button id="saveRpc" class="primary" type="button">Save RPC</button></div></div>
    <div class="settings-card"><label>Account</label><div class="address-block">${escapeHTML(session.wallet.address)}</div><div class="modal-actions"><button id="copyPub" type="button">Copy Public Key</button><button id="exportBackup" type="button">Export Encrypted Backup</button><label for="importSettingsFile" class="file-label">Import JSON</label><input id="importSettingsFile" type="file" accept="application/json" hidden></div></div>
    <div class="settings-card"><p class="hint">Lock only when needed. While this browser tab stays open, Rafaela keeps the wallet unlocked in memory and will not ask PIN repeatedly.</p><div class="modal-actions"><button id="lockWalletModal" type="button">Lock Wallet</button><button id="deleteWalletModal" class="danger" type="button">Delete Local Wallet</button></div></div>
  `, () => {
    $('saveRpc').onclick = () => { localStorage.setItem(RPC_KEY, rpcUrl()); $('rpcStatus').textContent = 'RPC saved: ' + rpcUrl(); toast('RPC saved.', 'ok'); };
    $('checkRpc').onclick = () => run(async () => { const info = await rpc('rafa_chainInfo'); $('rpcStatus').textContent = `Connected · ${info.name} ${info.symbol} · height ${info.height}`; log(info); }, 'RPC check failed');
    $('copyPub').onclick = () => copyText(session.wallet.publicKeySpkiB64, 'Public key copied.');
    $('exportBackup').onclick = () => run(() => exportEncryptedBackup(), 'Export failed');
    $('importSettingsFile').onchange = e => { const f = e.target.files[0]; if (f) run(() => importBackupFile(f), 'Import failed'); };
    $('lockWalletModal').onclick = () => { closeModal(); lockWallet(); };
    $('deleteWalletModal').onclick = () => { closeModal(); deleteWallet(); };
  }, 'Security');
}
function copyText(text, message = 'Copied.') { return navigator.clipboard.writeText(text).then(() => { toast(message, 'ok'); log(message); }); }
async function run(fn, errPrefix = 'Error') { try { await fn(); } catch (e) { toast(e.message, 'err', errPrefix); log('Error: ' + e.message); } }
function bind() {
  $('createWallet').onclick = () => run(createWallet, 'Create failed');
  $('openImportModal').onclick = openImportPopup; $('openImportModal2').onclick = openImportPopup; $('openImportModal3').onclick = openImportPopup;
  $('togglePhrase').onclick = () => { phraseVisible = !phraseVisible; updateSecretBoxes(); };
  $('togglePrivateKey').onclick = () => { privateVisible = !privateVisible; updateSecretBoxes(); };
  $('copyPhrase').onclick = () => copyText(pendingSecrets.phrase, 'Recovery phrase copied.');
  $('copyPrivateKey').onclick = () => copyText(pendingSecrets.privateKey, 'Private key copied.');
  $('downloadWalletFile').onclick = () => run(() => downloadPendingWalletFile(), 'Download failed');
  $('verifyPhrase').onclick = () => run(() => verifyPhrase(), 'Verification failed');
  $('savePin').onclick = () => run(savePin, 'PIN save failed');
  $('unlockWallet').onclick = () => run(unlockWallet, 'Unlock failed');
  $('deleteWallet').onclick = deleteWallet;
  ['importFile', 'importFile2', 'importFile3'].forEach(id => $(id).onchange = e => { const f = e.target.files[0]; if (f) run(() => importBackupFile(f), 'Import failed'); });
  document.querySelectorAll('[data-copy]').forEach(btn => btn.onclick = () => copyText($(btn.dataset.copy).value, 'Copied.'));
  $('refreshBalance').onclick = () => run(() => refreshBalance(true), 'Refresh failed');
  $('copyAddress').onclick = () => copyText(session.wallet?.address || '', 'Address copied.');
  $('claimFaucet').onclick = () => run(claimFaucet, 'Faucet failed');
  $('clearLog').onclick = () => { $('log').textContent = ''; };
  document.querySelectorAll('.round-action').forEach(btn => btn.onclick = () => {
    const a = btn.dataset.action;
    if (a === 'send') openSendModal();
    if (a === 'receive') openReceiveModal();
    if (a === 'stake') openStakeModal();
    if (a === 'deploy') openDeployModal();
    if (a === 'query') openQueryModal();
    if (a === 'settings') openSettingsModal();
  });
  $('modalClose').onclick = closeModal;
  $('modalBackdrop').onclick = e => { if (e.target.id === 'modalBackdrop') closeModal(); };
  document.addEventListener('keydown', e => { if (e.key === 'Escape') closeModal(); });
  $('themeToggle').onclick = () => { const html = document.documentElement; const next = html.dataset.theme === 'dark' ? 'light' : 'dark'; html.dataset.theme = next; localStorage.setItem(THEME_KEY, next); };
}
async function init() {
  document.documentElement.dataset.theme = localStorage.getItem(THEME_KEY) || 'light';
  if (!localStorage.getItem(RPC_KEY)) localStorage.setItem(RPC_KEY, DEFAULT_RPC);
  bind(); setView();
  const vault = loadVault();
  if (vault) log('Encrypted local wallet found. Enter PIN and unlock.');
  else log('Ready. Create wallet or import existing credentials.');
  if ('serviceWorker' in navigator) window.addEventListener('load', () => navigator.serviceWorker.register('/wallet/sw.js').catch(() => {}));
}
init();
