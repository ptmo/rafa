const DEFAULT_RPC = (() => {
  if (location.protocol === 'http:' || location.protocol === 'https:') return location.origin.replace(/\/$/, '') + '/rpc';
  return 'https://trpc.kodok.lol/rpc';
})();
const CHAIN_ID = 801;
const FIXED_FEE_WEI = '1000000000000000';
const DECIMALS = 18n;
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const VAULT_KEY = 'rafaela_web_wallet_vault_v2';
let session = {unlocked:false, wallet:null, privateKey:null};
const $ = id => document.getElementById(id);
const enc = new TextEncoder(); const dec = new TextDecoder();

function log(x){ const line = typeof x === 'string' ? x : JSON.stringify(x,null,2); $('log').textContent = `[${new Date().toLocaleTimeString()}] ${line}\n\n` + $('log').textContent; }
function setLockState(){ $('lockState').textContent = session.unlocked ? 'Unlocked' : 'Locked'; $('lockState').style.color = session.unlocked ? 'var(--brand2)' : 'var(--muted)'; }
function bytesToB64(buf){ return btoa(String.fromCharCode(...new Uint8Array(buf))); }
function b64ToBytes(s){ return Uint8Array.from(atob(s), c=>c.charCodeAt(0)); }
function randomBytes(n){ const a=new Uint8Array(n); crypto.getRandomValues(a); return a; }
function base58Encode(bytes){ let x=0n; for(const b of bytes)x=(x<<8n)+BigInt(b); let out=''; while(x>0n){const m=x%58n; out=B58[Number(m)]+out; x=x/58n;} for(const b of bytes){if(b===0)out=B58[0]+out;else break;} return out||B58[0]; }
async function sha256(buf){ return crypto.subtle.digest('SHA-256', buf); }
async function addressFromSpki(spki){ const h=new Uint8Array(await sha256(spki)); return '@rafa.'+base58Encode(h); }
function validAddress(a){ return /^@rafa\.[1-9A-HJ-NP-Za-km-z]{40,55}$/.test(String(a||'')); }
function decimalToWei(s){ s=String(s||'').trim(); if(!/^\d+(\.\d+)?$/.test(s)) throw new Error('Invalid amount'); const [w,f='']=s.split('.'); if(f.length>Number(DECIMALS)) throw new Error('Too many decimals'); return (BigInt(w)*10n**DECIMALS + BigInt((f||'').padEnd(Number(DECIMALS),'0'))).toString(); }
function weiToDecimal(s, max=8){ let n=BigInt(s||'0'); const base=10n**DECIMALS; const whole=n/base; let frac=String(n%base).padStart(Number(DECIMALS),'0').replace(/0+$/,''); if(frac.length>max) frac=frac.slice(0,max); return frac?`${whole}.${frac}`:String(whole); }
function canonicalMessage(from,to,amountWei,feeWei,nonce){ return `rafaela-tx:v1|chainId=${CHAIN_ID}|from=${from}|to=${to}|amount=${amountWei}|fee=${feeWei}|nonce=${nonce}`; }
function canonicalInteropMessage(from,to,source,destination,amountWei,feeWei,nonce,memo){ return `rafaela-interop:v1|chainId=${CHAIN_ID}|from=${from}|to=${to}|source=${source}|destination=${destination}|amount=${amountWei}|fee=${feeWei}|nonce=${nonce}|memo=${memo}`; }
function rpcUrl(){ return ($('rpcUrl').value.trim() || DEFAULT_RPC).replace(/\/$/,''); }
async function rpc(method, params=[]){ const res=await fetch(rpcUrl(),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',method,params,id:Date.now()})}); const json=await res.json(); if(json.error) throw new Error(json.error.message); return json.result; }
async function deriveVaultKey(password, salt){ const base=await crypto.subtle.importKey('raw',enc.encode(password),'PBKDF2',false,['deriveKey']); return crypto.subtle.deriveKey({name:'PBKDF2',salt,iterations:250000,hash:'SHA-256'},base,{name:'AES-GCM',length:256},false,['encrypt','decrypt']); }
async function encryptVault(payload,password){ if(!password || password.length<8) throw new Error('Password must be at least 8 characters.'); const salt=randomBytes(16), iv=randomBytes(12), key=await deriveVaultKey(password,salt); const raw=enc.encode(JSON.stringify(payload)); const cipher=await crypto.subtle.encrypt({name:'AES-GCM',iv},key,raw); return {version:2,kdf:'PBKDF2-SHA256',iterations:250000,cipher:'AES-GCM-256',salt:bytesToB64(salt),iv:bytesToB64(iv),data:bytesToB64(cipher),createdAt:Date.now()}; }
async function decryptVault(vault,password){ const salt=b64ToBytes(vault.salt), iv=b64ToBytes(vault.iv), data=b64ToBytes(vault.data); const key=await deriveVaultKey(password,salt); const raw=await crypto.subtle.decrypt({name:'AES-GCM',iv},key,data); return JSON.parse(dec.decode(raw)); }
async function importPrivateKey(jwk){ return crypto.subtle.importKey('jwk',jwk,{name:'ECDSA',namedCurve:'P-256'},true,['sign']); }
async function saveVault(payload){ const vault=await encryptVault(payload,$('password').value); localStorage.setItem(VAULT_KEY,JSON.stringify(vault)); }
function loadVault(){ const raw=localStorage.getItem(VAULT_KEY); return raw?JSON.parse(raw):null; }
function displayWallet(){ if(session.wallet){ $('address').value=session.wallet.address; } setLockState(); }
async function createWallet(){
  const kp=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);
  const jwk=await crypto.subtle.exportKey('jwk',kp.privateKey); const spki=await crypto.subtle.exportKey('spki',kp.publicKey); const address=await addressFromSpki(spki);
  const payload={address,privateJwk:jwk,publicKeySpkiB64:bytesToB64(spki),chainId:CHAIN_ID,createdAt:Date.now()};
  await saveVault(payload); session={unlocked:true,wallet:payload,privateKey:kp.privateKey}; displayWallet(); log({created:true,address,notice:'Encrypted vault saved in this browser. Export a backup now.'}); await refreshBalance();
}
async function unlockWallet(){ const vault=loadVault(); if(!vault) throw new Error('No local wallet found. Create or import first.'); const payload=await decryptVault(vault,$('password').value); session.wallet=payload; session.privateKey=await importPrivateKey(payload.privateJwk); session.unlocked=true; displayWallet(); log({unlocked:true,address:payload.address}); await refreshBalance(); }
function lockWallet(){ session={unlocked:false,wallet:null,privateKey:null}; $('password').value=''; $('address').value=''; $('balance').textContent='0'; $('nonce').textContent='0'; setLockState(); log('Wallet locked.'); }
async function refreshBalance(){ if(!session.wallet) throw new Error('Unlock wallet first.'); const [b,n]=await Promise.all([rpc('rafa_getBalance',[session.wallet.address]),rpc('rafa_getNonce',[session.wallet.address])]); $('balance').textContent=weiToDecimal(b.balance_wei); $('nonce').textContent=n.nonce; log({balance:b.balance_rafa,nonce:n.nonce}); }
async function sendTx(){
  if(!session.unlocked) throw new Error('Unlock wallet first.'); const to=$('toAddress').value.trim(); if(!validAddress(to)) throw new Error('Invalid recipient address.'); const amountWei=decimalToWei($('amount').value); const nonceRes=await rpc('rafa_getNonce',[session.wallet.address]); const nonce=Number(nonceRes.nonce)+1; const msg=canonicalMessage(session.wallet.address,to,amountWei,FIXED_FEE_WEI,nonce); const sig=await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},session.privateKey,enc.encode(msg)); const rawTx={chain_id:CHAIN_ID,from:session.wallet.address,to,amount_wei:amountWei,fee_wei:FIXED_FEE_WEI,nonce,public_key:session.wallet.publicKeySpkiB64,signature:bytesToB64(sig),message:msg}; const sent=await rpc('rafa_sendRawTransaction',[rawTx]); log({sent:true,hash:sent.hash,block:sent.block}); await refreshBalance();
}

async function loadZones(){
  const zones = await rpc('rafa_l0GetZones');
  const sel = $('zoneSelect');
  sel.innerHTML = '';
  const items = (zones.items||[]).filter(z=>z.id !== 'rafaela-hub' && z.status === 'active');
  items.forEach(z=>{
    const opt=document.createElement('option');
    opt.value=z.id; opt.textContent=`${z.name} · ${z.kind}`;
    sel.appendChild(opt);
  });
  $('l0Status').textContent = items.length ? `Loaded ${items.length} active destination zones.` : 'No active destination zone found.';
}
async function sendInteropTx(){
  if(!session.unlocked) throw new Error('Unlock wallet first.');
  const destination = $('zoneSelect').value;
  const to = $('interopTo').value.trim();
  if(!destination) throw new Error('Choose a destination zone.');
  if(!validAddress(to)) throw new Error('Invalid destination address.');
  const amountWei=decimalToWei($('interopAmount').value);
  const memo=String($('interopMemo').value||'').slice(0,240);
  const nonceRes=await rpc('rafa_getNonce',[session.wallet.address]);
  const nonce=Number(nonceRes.nonce)+1;
  const msg=canonicalInteropMessage(session.wallet.address,to,'rafaela-hub',destination,amountWei,FIXED_FEE_WEI,nonce,memo);
  const sig=await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},session.privateKey,enc.encode(msg));
  const rawInteropTx={chain_id:CHAIN_ID,from:session.wallet.address,to,source_zone_id:'rafaela-hub',destination_zone_id:destination,amount_wei:amountWei,fee_wei:FIXED_FEE_WEI,nonce,memo,public_key:session.wallet.publicKeySpkiB64,signature:bytesToB64(sig),message:msg};
  const sent=await rpc('rafa_l0SendPacket',[rawInteropTx]);
  log({l0_packet_sent:true,packet:sent.packet.id,hash:sent.hash,block:sent.block,status:sent.packet.status});
  $('l0Status').textContent = `Packet ${sent.packet.id.slice(0,12)}… created and pending relay.`;
  await refreshBalance();
}
async function claimFaucet(){ if(!session.wallet) throw new Error('Unlock wallet first.'); const base=rpcUrl().replace(/\/rpc\/?$/,''); const res=await fetch(base+'/faucet/claim',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({address:session.wallet.address})}); const json=await res.json(); if(!json.ok) throw new Error(json.error||'Faucet failed'); log(json); await refreshBalance(); }
function exportBackup(){ const raw=localStorage.getItem(VAULT_KEY); if(!raw) throw new Error('No vault found.'); const blob=new Blob([raw],{type:'application/json'}); const a=document.createElement('a'); a.href=URL.createObjectURL(blob); a.download='rafaela-encrypted-wallet-backup.json'; a.click(); URL.revokeObjectURL(a.href); log('Encrypted backup exported. Keep password separately.'); }
async function importBackup(file){ const text=await file.text(); const vault=JSON.parse(text); if(!vault.data || !vault.salt || !vault.iv) throw new Error('Invalid backup file.'); localStorage.setItem(VAULT_KEY,JSON.stringify(vault)); log('Encrypted backup imported. Enter password and unlock.'); }
async function checkRpc(){ const info=await rpc('rafa_chainInfo'); $('rpcStatus').textContent=`Connected · ${info.name} ${info.symbol} · height ${info.height} · ${info.l0_protocol||'L0'}`; log(info); await loadZones(); }
function deleteWallet(){ if(!confirm('Delete encrypted wallet from this browser? Make sure you already exported a backup.')) return; localStorage.removeItem(VAULT_KEY); lockWallet(); log('Local encrypted wallet deleted.'); }
function init(){ $('rpcUrl').value=localStorage.getItem('rafaela_rpc_url')||DEFAULT_RPC; $('rpcStatus').textContent='RPC target: '+$('rpcUrl').value; setLockState(); const vault=loadVault(); if(vault) log('Encrypted local wallet found. Enter password and unlock.'); loadZones().catch(e=>$('l0Status').textContent='L0 zones unavailable: '+e.message); }

$('createWallet').onclick=()=>createWallet().catch(e=>log('Error: '+e.message));
$('unlockWallet').onclick=()=>unlockWallet().catch(e=>log('Error: '+e.message));
$('lockWallet').onclick=lockWallet;
$('deleteWallet').onclick=deleteWallet;
$('refreshBalance').onclick=()=>refreshBalance().catch(e=>log('Error: '+e.message));
$('sendTx').onclick=()=>sendTx().catch(e=>log('Error: '+e.message));
$('sendInterop').onclick=()=>sendInteropTx().catch(e=>log('Error: '+e.message));
$('reloadZones').onclick=()=>loadZones().catch(e=>log('Error: '+e.message));
$('claimFaucet').onclick=()=>claimFaucet().catch(e=>log('Error: '+e.message));
$('copyAddress').onclick=()=>navigator.clipboard.writeText($('address').value).then(()=>log('Address copied.')).catch(e=>log('Clipboard error: '+e.message));
$('saveRpc').onclick=()=>{ localStorage.setItem('rafaela_rpc_url',rpcUrl()); $('rpcStatus').textContent='RPC saved: '+rpcUrl(); log('RPC saved.'); };
$('checkRpc').onclick=()=>checkRpc().catch(e=>{ $('rpcStatus').textContent='RPC error: '+e.message; log('Error: '+e.message); });
$('exportBackup').onclick=()=>{ try{exportBackup();}catch(e){log('Error: '+e.message)} };
$('importFile').onchange=e=>{ const f=e.target.files[0]; if(f) importBackup(f).catch(err=>log('Error: '+err.message)); };
$('clearLog').onclick=()=>{$('log').textContent=''};
$('themeToggle').onclick=()=>{ const html=document.documentElement; const next=html.dataset.theme==='dark'?'light':'dark'; html.dataset.theme=next; localStorage.setItem('rafaela_wallet_theme',next); };
const theme=localStorage.getItem('rafaela_wallet_theme'); if(theme) document.documentElement.dataset.theme=theme;
init();
