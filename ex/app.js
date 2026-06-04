const DEFAULT_RPC = (() => {
  if (location.protocol === 'http:' || location.protocol === 'https:') return location.origin.replace(/\/$/, '') + '/rpc';
  return 'https://trpc.kodok.lol/rpc';
})();
const DECIMALS = 18n;
const $ = (id) => document.getElementById(id);
let latestBlocks = [];
let latestTxs = [];
let latestPackets = [];

function setStatus(msg, bad=false){ const s=$('status'); s.textContent=msg; s.style.color=bad?'var(--danger)':'var(--muted)'; }
function short(s,n=10){ s=String(s||''); return s.length>n*2 ? s.slice(0,n)+'…'+s.slice(-n) : s; }
function age(ts){ const d=Math.max(0,Math.floor(Date.now()/1000-Number(ts||0))); if(d<60)return d+'s ago'; if(d<3600)return Math.floor(d/60)+'m ago'; if(d<86400)return Math.floor(d/3600)+'h ago'; return Math.floor(d/86400)+'d ago'; }
function weiToDecimal(s, max=6){ let n=BigInt(s||'0'); const base=10n**DECIMALS; const whole=n/base; let frac=String(n%base).padStart(Number(DECIMALS),'0').replace(/0+$/,''); if(frac.length>max) frac=frac.slice(0,max); return frac?`${whole}.${frac}`:String(whole); }
function fmtInt(x){ return Number(x||0).toLocaleString('en-US'); }
async function rpc(method, params=[]){
  const res = await fetch(DEFAULT_RPC,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',method,params,id:Date.now()})});
  const json = await res.json();
  if(json.error) throw new Error(json.error.message);
  return json.result;
}
function clear(node){ while(node.firstChild) node.removeChild(node.firstChild); }
function cell(text, cls){ const td=document.createElement('td'); td.textContent=text; if(cls) td.className=cls; return td; }
function clickCell(text, handler){ const td=cell(text,'clickable hash'); td.onclick=handler; return td; }
function showDetail(title, data){ $('detailTitle').textContent=title; $('detailBox').textContent=JSON.stringify(data,null,2); $('detailPanel').hidden=false; $('detailPanel').scrollIntoView({behavior:'smooth',block:'start'}); }

async function loadStats(){
  const st = await rpc('rafa_getStats');
  $('statHeight').textContent = fmtInt(st.height);
  $('statTx').textContent = fmtInt(st.tx_count);
  $('statSupply').textContent = fmtInt(Math.floor(Number(st.total_supply_rafa||0))) + ' RAFA';
  $('statAccounts').textContent = fmtInt(st.account_count);
  $('statZones').textContent = fmtInt(st.l0_zone_count);
  $('statRoutes').textContent = fmtInt(st.l0_route_count);
  $('statPackets').textContent = fmtInt(st.l0_packet_count);
  $('statCheckpoints').textContent = fmtInt(st.l0_checkpoint_count);
  $('rpcLabel').textContent = DEFAULT_RPC;
  $('fixedFee').textContent = (st.fixed_tx_fee_rafa||'0') + ' RAFA';
  $('faucetBalance').textContent = (st.faucet_balance_rafa||'0') + ' RAFA';
  $('validatorAddr').textContent = st.validator_address || '–';
  $('l0Protocol').textContent = st.l0_protocol || '–';
  $('l0Hub').textContent = st.l0_hub_zone_id || '–';
  const l0info = await rpc('rafa_l0Info');
  $('l0Escrow').textContent = l0info.escrow_address || '–';
  setStatus('RPC target: '+DEFAULT_RPC);
  return st;
}
async function loadBlocks(){
  const data = await rpc('rafa_getBlocks',[16,0]);
  latestBlocks = data.items || [];
  const body=$('blocksBody'); clear(body);
  latestBlocks.forEach(b=>{
    const tr=document.createElement('tr');
    tr.append(clickCell(String(b.number),()=>openBlock(b.number)));
    tr.append(cell(age(b.timestamp)));
    tr.append(cell(String(b.tx_count)));
    tr.append(cell(weiToDecimal(b.mint_reward_wei)+' RAFA'));
    tr.append(clickCell(short(b.hash),()=>openBlock(b.hash)));
    body.append(tr);
  });
  drawChart(latestBlocks.slice().reverse());
}
async function loadTxs(){
  const data = await rpc('rafa_getTransactions',[16,0]);
  latestTxs = data.items || [];
  const body=$('txBody'); clear(body);
  latestTxs.forEach(tx=>{
    const tr=document.createElement('tr');
    tr.append(clickCell(short(tx.hash),()=>openTx(tx.hash)));
    tr.append(cell(tx.type));
    tr.append(clickCell(String(tx.block),()=>openBlock(tx.block)));
    tr.append(cell(weiToDecimal(tx.amount_wei)+' RAFA'));
    tr.append(cell(`${short(tx.from,8)} → ${short(tx.to,8)}`,'hash'));
    body.append(tr);
  });
}
async function openBlock(q){ try{ showDetail('Block', await rpc('rafa_getBlock',[q])); }catch(e){ showDetail('Block lookup failed',{error:e.message, query:q}); } }
async function openTx(hash){ try{ showDetail('Transaction', await rpc('rafa_getTransaction',[hash])); }catch(e){ showDetail('Transaction lookup failed',{error:e.message, hash}); } }
async function openAddress(addr){ try{ showDetail('Address', await rpc('rafa_getAddress',[addr,50])); }catch(e){ showDetail('Address lookup failed',{error:e.message, address:addr}); } }
async function doSearch(q){
  q = String(q||'').trim();
  if(!q) return;
  setStatus('Searching '+q+' ...');
  try{
    const res = await rpc('rafa_search',[q]);
    if(res.type === 'address') return openAddress(q);
    if(res.type === 'transaction') return openTx(q);
    if(res.type === 'block') return openBlock(res.block?.number || q);
    if(res.type === 'l0_packet') return openPacket(q);
    showDetail('Search result', res);
    setStatus('Search complete.');
  }catch(e){ setStatus('Search failed: '+e.message,true); showDetail('No result',{query:q,error:e.message}); }
}
function drawChart(blocks){
  const c=$('blockChart'), ctx=c.getContext('2d');
  const w=c.width, h=c.height; ctx.clearRect(0,0,w,h);
  const pad=34, max=Math.max(1,...blocks.map(b=>Number(b.tx_count||0)));
  ctx.font='12px ui-sans-serif, system-ui';
  ctx.fillStyle=getComputedStyle(document.documentElement).getPropertyValue('--muted');
  ctx.fillText('txs per recent block', pad, 22);
  const bw=(w-pad*2)/Math.max(1,blocks.length);
  blocks.forEach((b,i)=>{
    const x=pad+i*bw+bw*.18;
    const barH=(h-pad*2)*(Number(b.tx_count||0)/max);
    const y=h-pad-barH;
    const grad=ctx.createLinearGradient(0,y,0,h-pad);
    grad.addColorStop(0,'rgba(255,99,226,.96)'); grad.addColorStop(1,'rgba(180,24,148,.76)');
    ctx.fillStyle=grad; roundRect(ctx,x,y,bw*.64,Math.max(3,barH),8); ctx.fill();
    if(i%Math.ceil(blocks.length/8 || 1)===0){ ctx.fillStyle=getComputedStyle(document.documentElement).getPropertyValue('--muted'); ctx.fillText(String(b.number),x,h-10); }
  });
}
function roundRect(ctx,x,y,w,h,r){ ctx.beginPath(); ctx.moveTo(x+r,y); ctx.arcTo(x+w,y,x+w,y+h,r); ctx.arcTo(x+w,y+h,x,y+h,r); ctx.arcTo(x,y+h,x,y,r); ctx.arcTo(x,y,x+w,y,r); ctx.closePath(); }

async function loadL0(){
  const [zones, routes, packets, checkpoints, validators] = await Promise.all([
    rpc('rafa_l0GetZones'), rpc('rafa_l0GetRoutes'), rpc('rafa_l0GetPackets',[16,0]), rpc('rafa_l0GetCheckpoints',[12,0]), rpc('rafa_l0GetValidators')
  ]);
  latestPackets = packets.items || [];

  const zb=$('zonesBody'); clear(zb);
  (zones.items||[]).forEach(z=>{
    const tr=document.createElement('tr');
    tr.append(clickCell(z.id,()=>showDetail('L0 Zone',z)));
    tr.append(cell(z.kind));
    tr.append(cell(z.status));
    tr.append(cell(z.security_model));
    tr.append(cell(String(z.last_height||0)));
    zb.append(tr);
  });

  const rb=$('routesBody'); clear(rb);
  (routes.items||[]).forEach(r=>{
    const tr=document.createElement('tr');
    tr.append(clickCell(r.id,()=>showDetail('L0 Route',r)));
    tr.append(cell(r.status));
    tr.append(cell(String(r.ordered)));
    tr.append(cell(weiToDecimal(r.fee_wei)+' RAFA'));
    rb.append(tr);
  });

  const pb=$('packetsBody'); clear(pb);
  latestPackets.forEach(pkt=>{
    const tr=document.createElement('tr');
    tr.append(clickCell(short(pkt.id),()=>openPacket(pkt.id)));
    tr.append(cell(pkt.status));
    tr.append(cell(`${pkt.source_zone_id} → ${pkt.destination_zone_id}`,'hash'));
    tr.append(cell(weiToDecimal(pkt.amount_wei)+' RAFA'));
    tr.append(clickCell(short(pkt.tx_hash),()=>openTx(pkt.tx_hash)));
    pb.append(tr);
  });

  const cb=$('checkpointsBody'); clear(cb);
  (checkpoints.items||[]).forEach(cp=>{
    const tr=document.createElement('tr');
    tr.append(cell(cp.zone_id));
    tr.append(cell(String(cp.height)));
    tr.append(cell(short(cp.state_root),'hash'));
    tr.append(cell(age(cp.timestamp)));
    cb.append(tr);
  });

  if(validators.items) {
    $('chartNote').textContent = `L0 validators ${validators.total} · packets ${packets.total}`;
  }
}
async function openPacket(id){ try{ showDetail('L0 Packet', await rpc('rafa_l0GetPacket',[id])); }catch(e){ showDetail('L0 packet lookup failed',{error:e.message, id}); } }

async function refreshAll(){ try{ await loadStats(); await loadBlocks(); await loadTxs(); await loadL0(); }catch(e){ setStatus('RPC error: '+e.message,true); } }


$('themeToggle').onclick=()=>{ const html=document.documentElement; const next=html.dataset.theme==='dark'?'light':'dark'; html.dataset.theme=next; localStorage.setItem('rafaela_explorer_theme',next); drawChart(latestBlocks.slice().reverse()); };
$('refreshAll').onclick=refreshAll; $('reloadBlocks').onclick=loadBlocks; $('reloadTxs').onclick=loadTxs; $('reloadL0').onclick=loadL0; $('closeDetail').onclick=()=>{$('detailPanel').hidden=true};
$('searchForm').onsubmit=(e)=>{ e.preventDefault(); doSearch($('searchInput').value); };
const savedTheme=localStorage.getItem('rafaela_explorer_theme'); if(savedTheme) document.documentElement.dataset.theme=savedTheme;
refreshAll(); setInterval(refreshAll,15000);
