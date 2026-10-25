"""Live jail dashboard. Mount it somewhere only staff can reach:

    app.mount("/jail", ctt.dashboard())
"""
from __future__ import annotations

from starlette.applications import Starlette
from starlette.responses import HTMLResponse, JSONResponse
from starlette.routing import Route

PAGE = r"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Jail Log · catch-the-thief</title>
<style>
:root{--bg:#0e1013;--panel:#161a1f;--panel2:#1c2128;--line:#2a313a;--ink:#e9edf1;--mute:#8b96a3;
--red:#ff4d4f;--amber:#ffb020;--green:#3ddc84;--blue:#4da3ff;--chart:#232a33}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.45 Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
.mono{font-family:ui-monospace,"JetBrains Mono",Menlo,Consolas,monospace}
header{display:flex;align-items:center;justify-content:space-between;padding:16px 22px;border-bottom:1px solid var(--line);
position:relative;overflow:hidden}
header h1{margin:0;font-size:17px;letter-spacing:.14em;font-weight:800}
header h1 span{color:var(--red)}
.live{display:flex;align-items:center;gap:8px;color:var(--mute);font-size:12px;letter-spacing:.1em}
.dot{width:8px;height:8px;border-radius:50%;background:var(--green);box-shadow:0 0 0 0 rgba(61,220,132,.6);animation:pulse 1.6s infinite}
@keyframes pulse{70%{box-shadow:0 0 0 8px rgba(61,220,132,0)}100%{box-shadow:0 0 0 0 rgba(61,220,132,0)}}
.siren{position:absolute;inset:0;pointer-events:none;opacity:0}
.siren.on{animation:siren 1.2s ease-out}
@keyframes siren{0%,30%,60%{opacity:.55;background:linear-gradient(90deg,var(--red),transparent 50%,var(--blue))}
15%,45%,75%{opacity:.55;background:linear-gradient(90deg,var(--blue),transparent 50%,var(--red))}100%{opacity:0}}
.stats{display:grid;grid-template-columns:repeat(5,1fr);gap:1px;background:var(--line);border-bottom:1px solid var(--line)}
.stat{background:var(--panel);padding:14px 18px}
.stat b{display:block;font-size:24px;font-weight:800;font-variant-numeric:tabular-nums}
.stat span{color:var(--mute);font-size:11px;letter-spacing:.12em;text-transform:uppercase}
.stat.red b{color:var(--red)}.stat.amber b{color:var(--amber)}.stat.green b{color:var(--green)}.stat.blue b{color:var(--blue)}
main{display:grid;grid-template-columns:minmax(0,1.6fr) minmax(0,1fr);gap:18px;padding:18px 22px}
h2{font-size:11px;letter-spacing:.16em;color:var(--mute);margin:0 0 10px;font-weight:700}
.empty{color:var(--mute);border:1px dashed var(--line);border-radius:10px;padding:26px;text-align:center}
.card{display:flex;gap:16px;background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px;margin-bottom:12px}
.card.fresh{animation:in .5s ease-out;border-color:var(--red);box-shadow:0 0 0 1px var(--red),0 0 30px -6px rgba(255,77,79,.5)}
@keyframes in{from{transform:translateY(-8px);opacity:0}to{transform:none;opacity:1}}
.mug{flex:0 0 112px}
.mug .photo{height:124px;border-radius:8px;position:relative;overflow:hidden;
background:repeating-linear-gradient(to bottom,var(--chart) 0 1px,transparent 1px 15px),#11151a;display:flex;align-items:center;justify-content:center}
.mug .photo i{position:absolute;left:4px;font-style:normal;font-size:8px;color:#4b5663}
.mug svg{width:70px;height:70px;position:relative}
.mug .plate{margin-top:6px;background:#0a0c0f;border:1px solid var(--line);border-radius:6px;padding:4px 6px;text-align:center;font-size:11px}
.mug .plate b{display:block;font-size:13px;letter-spacing:.08em}
.body{flex:1;min-width:0}
.badge{display:inline-block;font-size:10px;font-weight:800;letter-spacing:.12em;padding:3px 8px;border-radius:999px;text-transform:uppercase}
.b-suspect{background:rgba(255,77,79,.14);color:var(--red)}.b-uncertain{background:rgba(255,176,32,.14);color:var(--amber)}
.b-verified{background:rgba(77,163,255,.14);color:var(--blue)}.b-human{background:rgba(255,176,32,.14);color:var(--amber)}.b-paroled{background:rgba(61,220,132,.14);color:var(--green)}
.ua{color:var(--mute);font-size:11px;margin:6px 0 8px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.sub{font-size:10px;letter-spacing:.14em;color:var(--mute);font-weight:700;margin:8px 0 4px}
.charge{display:flex;justify-content:space-between;gap:8px;font-size:13px;padding:2px 0}
.charge em{font-style:normal;color:var(--mute);font-size:11px;white-space:nowrap}
.sent{display:flex;gap:8px;align-items:baseline;font-size:13px;padding:3px 0;border-top:1px solid var(--line)}
.sent:first-of-type{border-top:0}
.o{font-size:10px;font-weight:800;letter-spacing:.1em;padding:2px 6px;border-radius:4px;flex:0 0 auto}
.o-hold{background:var(--amber);color:#1a1300}.o-deny{background:var(--red);color:#fff}.o-allow{background:#2b3440;color:var(--ink)}
.sent .r{color:var(--mute);font-size:12px}
.side .box{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:12px 14px;margin-bottom:14px}
.visitor{padding:8px 0;border-top:1px solid var(--line)}.visitor:first-child{border-top:0}
.visitor b{font-size:14px}
.feed div{display:flex;gap:8px;font-size:12px;padding:4px 0;border-top:1px solid var(--line);align-items:baseline}
.feed div:first-child{border-top:0}
.feed time{color:var(--mute);flex:0 0 auto}
.feed .p{color:var(--mute);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
@media (max-width:900px){main{grid-template-columns:minmax(0,1fr)}.stat{padding:12px}.stat b{font-size:20px}.stat span{font-size:9px}}
@media (max-width:560px){.stats{grid-template-columns:repeat(3,1fr)}}
</style></head><body>
<header><div class="siren" id="siren"></div>
<h1>🚨 CATCH <span>THE</span> THIEF</h1><div class="live"><div class="dot"></div>LIVE JAIL LOG</div></header>
<section class="stats">
<div class="stat red"><b id="s-inmates">0</b><span>Agents jailed</span></div>
<div class="stat amber"><b id="s-held">$0</b><span>Money held</span></div>
<div class="stat red"><b id="s-denied">0</b><span>Actions blocked</span></div>
<div class="stat blue"><b id="s-verified">0</b><span>Verified agent actions</span></div>
<div class="stat green"><b id="s-humans">0</b><span>Humans waved through</span></div>
</section>
<main>
<section><h2>CELL BLOCK · UNVERIFIED AGENTS</h2><div id="cells"><div class="empty">No inmates. All quiet.</div></div></section>
<section class="side">
<h2>VISITOR LOG · VERIFIED AGENTS</h2><div class="box" id="visitors"><div class="p" style="color:var(--mute)">No verified agents yet.</div></div>
<h2>LIVE FEED</h2><div class="box feed" id="feed"></div>
</section></main>
<script>
const $=id=>document.getElementById(id);
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const money=n=>'$'+Number(n||0).toLocaleString(undefined,{maximumFractionDigits:0});
const t=ts=>new Date(ts*1000).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit',second:'2-digit'});
function hash(s){let h=2166136261;for(const c of s){h^=c.charCodeAt(0);h=Math.imul(h,16777619)}return h>>>0}
function face(sid){ // deterministic 5x5 "mugshot" identicon
  const h=hash(sid),hue=h%360,col=`hsl(${hue} 70% 62%)`;let r='';
  for(let y=0;y<5;y++)for(let x=0;x<3;x++){if((h>>((y*3+x)%31))&1){
    r+=`<rect x="${x*14}" y="${y*14}" width="14" height="14" fill="${col}"/>`;
    if(x<2)r+=`<rect x="${(4-x)*14}" y="${y*14}" width="14" height="14" fill="${col}"/>`;}}
  return `<svg viewBox="0 0 70 70">${r}</svg>`;}
const label={suspect:'Suspected AI agent',uncertain:'Unverified, possibly automated',verified:'Verified agent',paroled:'On parole',human:'Looked human · step-up hold'};
const oname=s=>s.outcome==='allow'?'WATCHED':s.outcome.toUpperCase();
const verb=s=>s.action==='money'?`${money(s.amount)} transfer`:(s.action==='human_only'?'human-only action':s.action);
let seen=new Set(),first=true;
function card(m){
  const fresh=!seen.has(m.sid)&&!first; seen.add(m.sid);
  const ch=m.charges.slice(0,5).map(c=>`<div class="charge"><span>${esc(c.charge)}</span><em class="mono">+${c.weight}</em></div>`).join('');
  const se=m.sentences.slice().reverse().map(s=>`<div class="sent"><span class="o o-${s.outcome}">${oname(s)}</span>
    <span>${esc(verb(s))} <span class="r mono">${esc(s.method)} ${esc(s.path)}</span></span></div>`).join('')
    ||'<div class="sent"><span class="r">Booked. Watching quietly in read-only mode.</span></div>';
  return `<article class="card ${fresh?'fresh':''}"><div class="mug"><div class="photo"><i class="mono" style="top:2px">6'0</i><i class="mono" style="top:44px">5'6</i><i class="mono" style="top:88px">5'0</i>${face(m.sid)}</div>
  <div class="plate mono"><b>#${String(m.no).padStart(4,'0')}</b>score ${m.score}/100</div></div>
  <div class="body"><span class="badge b-${m.cls}">${label[m.cls]||m.cls}</span>
  <div class="ua mono" title="${esc(m.ua)}">${esc(m.ua||'no user agent')}</div>
  <div class="sub">CHARGES</div>${ch||'<div class="charge"><span>No agent signals. Held by the large-transfer step-up rule.</span></div>'}
  <div class="sub">SENTENCE</div>${se}</div></article>`;}
async function tick(){
  let d;try{d=await (await fetch('api',{cache:'no-store'})).json()}catch(e){return}
  const s=d.stats;
  $('s-inmates').textContent=s.inmates;$('s-held').textContent=money(s.held_total);$('s-denied').textContent=s.denied;
  $('s-verified').textContent=s.verified_actions+s.paroled_actions;$('s-humans').textContent=s.humans;
  const before=seen.size;
  $('cells').innerHTML=d.inmates.length?d.inmates.map(card).join(''):'<div class="empty">No inmates. All quiet.</div>';
  if(seen.size>before&&!first){const el=$('siren');el.classList.remove('on');void el.offsetWidth;el.classList.add('on')}
  $('visitors').innerHTML=d.visitors.length?d.visitors.map(v=>`<div class="visitor"><span class="badge b-${v.cls}">${v.cls==='paroled'?'On parole':'Verified · no consent'}</span>
    <div><b>${esc(v.agent)}</b> <span style="color:var(--mute)">${esc(v.operator||'')}</span></div>
    ${v.actions.slice(-3).reverse().map(a=>`<div class="sent"><span class="o o-${a.outcome}">${a.outcome.toUpperCase()}</span><span class="r">${esc(verb(a))}</span></div>`).join('')}</div>`).join('')
    :'<div style="color:var(--mute)">No verified agents yet.</div>';
  $('feed').innerHTML=d.feed.map(e=>`<div><time class="mono">${t(e.ts)}</time><span class="o o-${e.outcome==='booked'?'deny':e.outcome}">${e.outcome.toUpperCase()}</span>
    <span class="p">${esc(e.agent||e.cls)} · ${esc(e.method)} ${esc(e.path)}</span></div>`).join('')||'<div style="color:var(--mute)">Waiting for traffic…</div>';
  first=false;}
tick();setInterval(tick,700);
</script></body></html>"""


def build_dashboard(thief):
    async def page(request):
        return HTMLResponse(PAGE)

    async def api(request):
        return JSONResponse(thief.log.summary())

    return Starlette(routes=[Route("/", page), Route("/api", api)])
