"""Local live dashboard for safe assessment progress."""
import json
import logging
import threading
import time
import webbrowser
from flask import Flask, jsonify, render_template_string

DASHBOARD_HOST = "127.0.0.1"
DASHBOARD_PORT = 8765

HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sentinel Assessment Console | Created by Satyendra Kumar Namdeo</title>
<meta name="author" content="Satyendra Kumar Namdeo">
<meta name="copyright" content="© 2026 Satyendra Kumar Namdeo. All rights reserved.">
<style>
:root{--bg:#020308;--panel:#07101a;--line:#15334a;--text:#dce8f5;--muted:#7890aa;--accent:#38e8a0;--blue:#4ea1ff;--warn:#ffc857;--danger:#ff3864}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 50% 15%,#0a2430 0,#03070d 42%,#010207 100%);color:var(--text);font:14px/1.45 Inter,Segoe UI,Arial,sans-serif;min-height:100vh;overflow-x:hidden}
.app{max-width:1500px;margin:auto;padding:18px;position:relative}.app:before{content:"";position:fixed;inset:0;pointer-events:none;background:repeating-linear-gradient(0deg,rgba(56,232,160,.025) 0,rgba(56,232,160,.025) 1px,transparent 1px,transparent 4px);mix-blend-mode:screen;z-index:20}.brand:after{content:" // ACTIVE SECURITY";color:var(--danger);animation:blink 1s steps(2,end) infinite}@keyframes blink{50%{opacity:.35}}.top{display:flex;justify-content:space-between;gap:16px;align-items:center;margin-bottom:14px}.brand{font-weight:800;letter-spacing:.12em;text-transform:uppercase}.status{padding:7px 11px;border:1px solid var(--line);border-radius:999px;color:var(--accent);background:#07140f}
.grid{display:grid;grid-template-columns:1.15fr .85fr;gap:14px}.panel{background:linear-gradient(180deg,#0b1320ee,#070d17ee);border:1px solid var(--line);border-radius:16px;box-shadow:0 16px 60px #0007;overflow:hidden}.pad{padding:16px}.hero{min-height:440px;position:relative}.hero canvas{width:100%;height:390px;display:block}.overlay{position:absolute;inset:0;pointer-events:none;display:flex;flex-direction:column;justify-content:center;align-items:center;text-align:center}.ring{width:190px;height:190px;border:1px solid #38e8a066;border-radius:50%;box-shadow:0 0 50px #38e8a01a,inset 0 0 50px #38e8a01a;animation:pulse 2.4s ease-in-out infinite}.core{position:absolute;width:72px;height:72px;border-radius:50%;background:#38e8a015;border:1px solid var(--accent);box-shadow:0 0 35px #38e8a055}.title{font-size:19px;font-weight:800;letter-spacing:.08em;margin-top:20px}.sub{color:var(--muted);margin-top:5px}@keyframes pulse{50%{transform:scale(1.08);opacity:.75}}
.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}.metric{background:#08101c;border:1px solid var(--line);border-radius:12px;padding:12px}.metric b{font-size:22px}.metric span{display:block;color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.08em}
.bar{height:8px;background:#101b2a;border-radius:99px;overflow:hidden;margin-top:10px}.fill{height:100%;width:0;background:linear-gradient(90deg,var(--blue),var(--accent));transition:width .4s}
.side h3,.logs h3{margin:0 0 10px;font-size:12px;text-transform:uppercase;letter-spacing:.12em;color:#9bb1c9}.kv{display:grid;grid-template-columns:100px 1fr;gap:7px;font-size:13px}.kv div:nth-child(odd){color:var(--muted)}.kv div:nth-child(even){word-break:break-all}
.evidence{margin-top:14px}.evidence-toolbar{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-top:12px}.evidence-toolbar input,.evidence-toolbar select{background:#03070d;color:var(--text);border:1px solid var(--line);border-radius:8px;padding:9px;min-width:150px}.evidence-stats{display:flex;flex-wrap:wrap;gap:8px;margin-top:10px}.e-stat{border:1px solid var(--line);border-radius:8px;padding:7px 10px;color:var(--muted);font-size:11px}.e-stat b{color:var(--accent);font-size:14px;margin-right:5px}.evidencebox{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px;padding:12px;max-height:none;overflow:visible}.e-card{border:1px solid var(--line);border-radius:12px;background:#040912;overflow:hidden;min-width:0}.e-card img{width:100%;height:260px;object-fit:contain;background:#02050a;display:block;cursor:zoom-in}.e-card img.fullpage{height:440px;object-fit:contain}.e-body{padding:10px}.e-id{font-weight:800;color:var(--accent);font-size:12px}.e-url{color:var(--muted);font-size:11px;word-break:break-all;margin-top:4px}.e-meta{font-size:11px;margin-top:6px;overflow-wrap:anywhere}.e-links{display:flex;flex-wrap:wrap;gap:10px}.e-card a{display:inline-block;margin-top:8px;color:var(--blue);text-decoration:none}.e-card a:focus,.evidence-toolbar input:focus,.evidence-toolbar select:focus{outline:2px solid var(--accent);outline-offset:2px}.e-card[hidden]{display:none}.evidence-note{color:var(--muted);font-size:11px;margin-top:6px}.coverage{margin-top:14px;display:grid;grid-template-columns:repeat(3,1fr);gap:9px}.coverage-card{border:1px solid var(--line);border-radius:11px;padding:10px;background:#07101a}.coverage-card b{display:block;font-size:12px}.coverage-card span{display:block;color:var(--muted);font-size:10px;text-transform:uppercase;margin-top:4px}.logs{margin-top:14px}.logbox{height:270px;overflow:auto;background:#03070d;border-top:1px solid var(--line);padding:12px;font:12px/1.6 Consolas,monospace}.log{color:#9db2c9}.log.ok{color:var(--accent)}.log.warn{color:var(--warn)}.log.err{color:var(--danger)}
table{width:100%;border-collapse:collapse;font-size:12px}th,td{padding:8px;border-bottom:1px solid #152337;text-align:left}th{color:var(--muted);font-weight:600}
@media(max-width:900px){.grid{grid-template-columns:1fr}.metrics{grid-template-columns:repeat(2,1fr)}.coverage{grid-template-columns:repeat(2,1fr)}.evidencebox{grid-template-columns:1fr}.hero{min-height:380px}.hero canvas{height:330px}}
@media(prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
</style></head>
<body><div class="app">
<div class="top"><div class="brand">SENTINEL // ASSESSMENT CONSOLE</div><div id="status" class="status">INITIALIZING</div></div>
<div style="color:var(--muted);font-size:11px;letter-spacing:.04em;margin:-5px 0 14px;padding-left:2px">CREATED BY SATYENDRA KUMAR NAMDEO · © 2026 ALL RIGHTS RESERVED</div>
<div class="grid">
<section class="panel hero"><canvas id="scene"></canvas><div class="overlay"><div class="ring"></div><div class="core"></div><div class="title" id="stage">WAITING FOR ENGINE</div><div class="sub" style="color:var(--accent);font-family:Consolas,monospace">[ ACCESSING AUTHORIZED TARGET ]</div><div class="sub" id="detail">Starting local assessment telemetry...</div></div></section>
<aside class="panel pad side"><h3>Target</h3><div class="kv"><div>URL</div><div id="target">-</div><div>Profile</div><div id="profile">-</div><div>Browser</div><div id="browser">-</div><div>Viewport</div><div id="viewport">-</div></div>
<hr style="border:0;border-top:1px solid var(--line);margin:18px 0"><h3>Progress</h3><div id="progressText">0%</div><div class="bar"><div id="fill" class="fill"></div></div>
<div class="metrics" style="margin-top:14px"><div class="metric"><b id="pages">0</b><span>pages</span></div><div class="metric"><b id="checks">0</b><span>checks</span></div><div class="metric"><b id="findings">0</b><span>findings</span></div><div class="metric"><b id="errors">0</b><span>errors</span></div></div></aside></div>
<section class="panel evidence"><div class="pad"><h3 style="margin:0">Evidence Vault · Full-Page + Focused Proof</h3><div class="sub">Retains the available artifacts per finding: complete document-height page, focused element, viewport context, and clearly labelled diagnostic fallback. A generated diagnostic card is not a webpage screenshot.</div><div class="evidence-stats"><div class="e-stat"><b id="ev-total">0</b> evidence records</div><div class="e-stat"><b id="ev-fullpage">0</b> full-page captures</div><div class="e-stat"><b id="ev-focused">0</b> focused/context artifacts</div><div class="e-stat"><b id="ev-errors">0</b> capture warnings</div></div><div class="evidence-toolbar"><input id="ev-search" type="search" placeholder="Find issue ID, title, URL…" aria-label="Search evidence"><select id="ev-type" aria-label="Filter evidence type"><option value="all">All evidence types</option><option value="full-page">Full-page screenshots</option><option value="focused">Focused / viewport</option><option value="diagnostic">Diagnostic cards</option><option value="warning">Capture warnings</option></select><select id="ev-sort" aria-label="Sort evidence"><option value="newest">Newest first</option><option value="id">Issue ID</option><option value="url">URL</option></select></div><div class="evidence-note">Use “Open full page” to inspect the entire captured page at its original image size. All displayed text is escaped before rendering.</div></div><div id="evidence" class="evidencebox"><div class="muted pad">Waiting for evidence...</div></div></section>
<section class="panel pad coverage"><div class="coverage-card"><b>UI / Responsive</b><span id="cov-ui">PENDING</span></div><div class="coverage-card"><b>Functional</b><span id="cov-functional">PENDING</span></div><div class="coverage-card"><b>Security</b><span id="cov-security">PENDING</span></div><div class="coverage-card"><b>Penetration</b><span id="cov-penetration">PENDING</span></div><div class="coverage-card"><b>Info Leak</b><span id="cov-info">PENDING</span></div><div class="coverage-card"><b>Focused Evidence</b><span id="cov-evidence">PENDING</span></div></section>
<section class="panel logs"><div class="pad"><h3>Live console telemetry</h3></div><div id="logs" class="logbox" aria-live="polite"></div></section>
<section class="panel pad" style="margin-top:14px"><h3 style="margin-top:0">Browser / viewport coverage</h3><table><thead><tr><th>Browser</th><th>Viewport</th><th>Page</th><th>Status</th></tr></thead><tbody id="matrix"></tbody></table></section>
</div>
<script>
const $=function(id){return document.getElementById(id)};let last=0;
function draw(){const c=$("scene"),x=c.getContext("2d"),d=window.devicePixelRatio||1,w=c.clientWidth,h=c.clientHeight;c.width=w*d;c.height=h*d;x.setTransform(d,0,0,d,0,0);x.clearRect(0,0,w,h);const t=Date.now()/1000,cx=w/2,cy=h/2,nodes=[];
for(let i=0;i<70;i++){const a=i*.897+t*.05,r=45+(i%9)*24+Math.sin(t+i)*10;nodes.push([cx+Math.cos(a)*r,cy+Math.sin(a)*r*.58])}
x.lineWidth=1;for(let i=0;i<nodes.length;i++){for(let j=i+1;j<nodes.length;j++){const dx=nodes[i][0]-nodes[j][0],dy=nodes[i][1]-nodes[j][1],dist=Math.hypot(dx,dy);if(dist<95){x.strokeStyle="rgba(78,161,255,"+Math.max(0,.18-dist/600)+")";x.beginPath();x.moveTo(nodes[i][0],nodes[i][1]);x.lineTo(nodes[j][0],nodes[j][1]);x.stroke()}}}
for(const n of nodes){x.fillStyle="#38e8a0";x.globalAlpha=.35;x.beginPath();x.arc(n[0],n[1],1.5,0,7);x.fill()}x.globalAlpha=1;requestAnimationFrame(draw)}
function esc(v){return String(v).replace(/[&<>"']/g,function(c){return {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]})}
function render(s){$("status").textContent=s.status||"RUNNING";$("stage").textContent=s.stage||"ASSESSMENT ENGINE";$("detail").textContent=s.detail||"";$("target").textContent=s.target||"-";$("profile").textContent=s.profile||"-";$("browser").textContent=s.browser||"-";$("viewport").textContent=s.viewport||"-";$("progressText").textContent=(s.progress||0)+"%";$("fill").style.width=(s.progress||0)+"%";$("pages").textContent=s.pages_tested||0;$("checks").textContent=s.checks||0;$("findings").textContent=s.findings||0;$("errors").textContent=s.errors||0;
if(s.logs&&s.logs.length!==last){$("logs").innerHTML=s.logs.slice(-250).map(function(l){return '<div class="log '+(l.level||"")+'">['+esc(l.time||"")+'] '+esc(l.message||"")+"</div>"}).join("");$("logs").scrollTop=$("logs").scrollHeight;last=s.logs.length}
if(s.matrix){$("matrix").innerHTML=s.matrix.slice(-60).map(function(r){return "<tr><td>"+esc(r.browser)+"</td><td>"+esc(r.viewport)+"</td><td>"+esc(r.url)+"</td><td>"+esc(r.status||"-")+"</td></tr>"}).join("")}
const cov=s.coverage||{}; [["ui","ui_responsive"],["functional","functional"],["security","security"],["penetration","penetration"],["info","information_disclosure"],["evidence","evidence"]].forEach(function(pair){const node=$("cov-"+pair[0]);if(node)node.textContent=String(cov[pair[1]]||"pending").toUpperCase()});
const evidenceSource=Array.isArray(s.evidence_archive)?s.evidence_archive:s.live_evidence;const ev=Array.isArray(evidenceSource)?evidenceSource.slice():[]; const box=$("evidence"); if(box){const fullCount=ev.filter(function(e){return !!(e.full_page_artifact_url||e.full_page_screenshot_url||e.full_page_url||e.full_page_screenshot)}).length;const focusCount=ev.filter(function(e){return !!e.artifact_url}).length;const warningCount=ev.filter(function(e){return !!e.error||!!e.full_page_capture_error}).length;$("ev-total").textContent=ev.length;$("ev-fullpage").textContent=fullCount;$("ev-focused").textContent=focusCount;$("ev-errors").textContent=warningCount;const sorted=ev.sort(function(a,b){if($("ev-sort").value==="id")return String(a.finding_id||"").localeCompare(String(b.finding_id||""));if($("ev-sort").value==="url")return String(a.url||"").localeCompare(String(b.url||""));return Date.parse(b.captured_at||"")-Date.parse(a.captured_at||"")});box.innerHTML=sorted.length?sorted.map(function(e){const full=e.full_page_artifact_url||e.full_page_screenshot_url||e.full_page_url||"";const primary=e.artifact_url||full||"";const mode=String(e.capture_mode||e.capture_scope||"artifact");const diagnostic=/diagnostic/i.test(mode)||!!e.diagnostic_artifact;const kind=full?"full-page":(diagnostic?"diagnostic":"focused");const search=[e.finding_id,e.title,e.severity,e.url,e.capture_mode,e.capture_scope,e.evidence_summary,e.impact,e.remediation,e.error].join(" ").toLowerCase();return '<article class="e-card" data-kind="'+kind+'" data-warning="'+((e.error||e.full_page_capture_error)?'yes':'no')+'" data-search="'+esc(search)+'"><img loading="lazy" class="'+(full?'fullpage':'')+'" src="'+esc(full||primary)+'" alt="'+esc(kind==='full-page'?'Full-page evidence for ':'Evidence for ')+esc(e.finding_id||'finding')+'" onerror="this.hidden=true"><div class="e-body"><div class="e-id">'+esc(e.finding_id||"EVIDENCE")+' · '+esc(e.title||"Evidence artifact")+'</div><div class="e-url">'+esc(e.url||"URL not recorded")+'</div><div class="e-meta">Type: '+esc(kind)+' · Capture: '+esc(mode)+(e.status!==undefined&&e.status!==null?' · HTTP '+esc(e.status):'')+'</div>'+(e.evidence_summary?'<div class="e-meta"><b>What was observed:</b> '+esc(e.evidence_summary)+'</div>':'')+(e.impact?'<div class="e-meta"><b>Why it matters:</b> '+esc(e.impact)+'</div>':'')+(e.remediation?'<div class="e-meta"><b>Recommended fix:</b> '+esc(e.remediation)+'</div>':'')+(e.error||e.full_page_capture_error?'<div class="e-meta log warn">Capture warning: '+esc(e.error||e.full_page_capture_error)+'</div>':'')+'<div class="e-links">'+(full?'<a href="'+esc(full)+'" target="_blank" rel="noopener">Open full page</a>':'')+(primary?'<a href="'+esc(primary)+'" target="_blank" rel="noopener">Open primary artifact</a>':'')+(e.diagnostic_artifact_url?'<a href="'+esc(e.diagnostic_artifact_url)+'" target="_blank" rel="noopener">Open diagnostic card</a>':'')+'</div></div></article>'}).join(""):'<div class="muted pad">No captured evidence yet. Records will appear as the evidence phase emits artifacts.</div>';function filterEvidence(){const q=$("ev-search").value.toLowerCase();const type=$("ev-type").value;Array.from(box.querySelectorAll(".e-card")).forEach(function(card){const typeOk=type==="all"||(type==="warning"?card.dataset.warning==="yes":card.dataset.kind===type||(type==="focused"&&card.dataset.kind==="full-page"));card.hidden=!(typeOk&&card.dataset.search.includes(q))})}["ev-search","ev-type","ev-sort"].forEach(function(id){$(id).oninput=filterEvidence;$(id).onchange=filterEvidence});filterEvidence()}}
async function poll(){try{const r=await fetch("/api/status?ts="+Date.now());render(await r.json())}catch(e){}setTimeout(poll,500)}draw();poll();
</script></body></html>"""

class DashboardState:
    def __init__(self, target="", profile="compatibility"):
        self.lock=threading.Lock()
        self.data={"status":"INITIALIZING","stage":"STARTING","detail":"","target":target,"profile":profile,
                   "browser":"-","viewport":"-","progress":0,"pages_tested":0,"checks":0,"findings":0,"errors":0,
                   "logs":[],"matrix":[],"live_evidence":[],"coverage":{},"started_at":time.time(),"finished_at":None}

    def update(self, **kwargs):
        with self.lock:
            log=kwargs.pop("log",None)
            matrix_item=kwargs.pop("matrix_item",None)
            self.data.update(kwargs)
            if log:
                self.data["logs"].append(log)
                self.data["logs"]=self.data["logs"][-300:]
            if matrix_item:
                self.data["matrix"].append(matrix_item)
                self.data["matrix"]=self.data["matrix"][-100:]

    def snapshot(self):
        with self.lock:
            return json.loads(json.dumps(self.data))

def start_dashboard(state: DashboardState, open_browser=True):
    # Keep the assessment console clean: browser polling is telemetry, not noise.
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    app=Flask("assessment_dashboard")
    @app.get("/")
    def index():
        return render_template_string(HTML)
    @app.get("/api/status")
    def status():
        return jsonify(state.snapshot())
    def serve():
        app.run(host=DASHBOARD_HOST,port=DASHBOARD_PORT,debug=False,use_reloader=False,threaded=True)
    thread=threading.Thread(target=serve,daemon=True)
    thread.start()
    time.sleep(.35)
    url="http://"+DASHBOARD_HOST+":"+str(DASHBOARD_PORT)+"/"
    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    return url
