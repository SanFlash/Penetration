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
<title>Sentinel Assessment Console</title>
<style>
:root{--bg:#050810;--panel:#0b1220;--line:#1c2d43;--text:#dce8f5;--muted:#7890aa;--accent:#38e8a0;--blue:#4ea1ff;--warn:#ffc857;--danger:#ff5c7a}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 50% 15%,#11233b 0,#050810 48%,#02040a 100%);color:var(--text);font:14px/1.45 Inter,Segoe UI,Arial,sans-serif;min-height:100vh;overflow-x:hidden}
.app{max-width:1500px;margin:auto;padding:18px}.top{display:flex;justify-content:space-between;gap:16px;align-items:center;margin-bottom:14px}.brand{font-weight:800;letter-spacing:.12em;text-transform:uppercase}.status{padding:7px 11px;border:1px solid var(--line);border-radius:999px;color:var(--accent);background:#07140f}
.grid{display:grid;grid-template-columns:1.35fr .65fr;gap:14px}.panel{background:linear-gradient(180deg,#0b1320ee,#070d17ee);border:1px solid var(--line);border-radius:16px;box-shadow:0 16px 60px #0007;overflow:hidden}.pad{padding:16px}.hero{min-height:440px;position:relative}.hero canvas{width:100%;height:390px;display:block}.overlay{position:absolute;inset:0;pointer-events:none;display:flex;flex-direction:column;justify-content:center;align-items:center;text-align:center}.ring{width:190px;height:190px;border:1px solid #38e8a066;border-radius:50%;box-shadow:0 0 50px #38e8a01a,inset 0 0 50px #38e8a01a;animation:pulse 2.4s ease-in-out infinite}.core{position:absolute;width:72px;height:72px;border-radius:50%;background:#38e8a015;border:1px solid var(--accent);box-shadow:0 0 35px #38e8a055}.title{font-size:19px;font-weight:800;letter-spacing:.08em;margin-top:20px}.sub{color:var(--muted);margin-top:5px}@keyframes pulse{50%{transform:scale(1.08);opacity:.75}}
.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}.metric{background:#08101c;border:1px solid var(--line);border-radius:12px;padding:12px}.metric b{font-size:22px}.metric span{display:block;color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.08em}
.bar{height:8px;background:#101b2a;border-radius:99px;overflow:hidden;margin-top:10px}.fill{height:100%;width:0;background:linear-gradient(90deg,var(--blue),var(--accent));transition:width .4s}
.side h3,.logs h3{margin:0 0 10px;font-size:12px;text-transform:uppercase;letter-spacing:.12em;color:#9bb1c9}.kv{display:grid;grid-template-columns:100px 1fr;gap:7px;font-size:13px}.kv div:nth-child(odd){color:var(--muted)}.kv div:nth-child(even){word-break:break-all}
.logs{margin-top:14px}.logbox{height:270px;overflow:auto;background:#03070d;border-top:1px solid var(--line);padding:12px;font:12px/1.6 Consolas,monospace}.log{color:#9db2c9}.log.ok{color:var(--accent)}.log.warn{color:var(--warn)}.log.err{color:var(--danger)}
table{width:100%;border-collapse:collapse;font-size:12px}th,td{padding:8px;border-bottom:1px solid #152337;text-align:left}th{color:var(--muted);font-weight:600}
@media(max-width:900px){.grid{grid-template-columns:1fr}.metrics{grid-template-columns:repeat(2,1fr)}.hero{min-height:380px}.hero canvas{height:330px}}
@media(prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
</style></head>
<body><div class="app">
<div class="top"><div class="brand">SENTINEL // ASSESSMENT CONSOLE</div><div id="status" class="status">INITIALIZING</div></div>
<div class="grid">
<section class="panel hero"><canvas id="scene"></canvas><div class="overlay"><div class="ring"></div><div class="core"></div><div class="title" id="stage">WAITING FOR ENGINE</div><div class="sub" id="detail">Starting local assessment telemetry...</div></div></section>
<aside class="panel pad side"><h3>Target</h3><div class="kv"><div>URL</div><div id="target">-</div><div>Profile</div><div id="profile">-</div><div>Browser</div><div id="browser">-</div><div>Viewport</div><div id="viewport">-</div></div>
<hr style="border:0;border-top:1px solid var(--line);margin:18px 0"><h3>Progress</h3><div id="progressText">0%</div><div class="bar"><div id="fill" class="fill"></div></div>
<div class="metrics" style="margin-top:14px"><div class="metric"><b id="pages">0</b><span>pages</span></div><div class="metric"><b id="checks">0</b><span>checks</span></div><div class="metric"><b id="findings">0</b><span>findings</span></div><div class="metric"><b id="errors">0</b><span>errors</span></div></div></aside></div>
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
if(s.matrix){$("matrix").innerHTML=s.matrix.slice(-60).map(function(r){return "<tr><td>"+esc(r.browser)+"</td><td>"+esc(r.viewport)+"</td><td>"+esc(r.url)+"</td><td>"+esc(r.status||"-")+"</td></tr>"}).join("")}}
async function poll(){try{const r=await fetch("/api/status?ts="+Date.now());render(await r.json())}catch(e){}setTimeout(poll,500)}draw();poll();
</script></body></html>"""

class DashboardState:
    def __init__(self, target="", profile="compatibility"):
        self.lock=threading.Lock()
        self.data={"status":"INITIALIZING","stage":"STARTING","detail":"","target":target,"profile":profile,
                   "browser":"-","viewport":"-","progress":0,"pages_tested":0,"checks":0,"findings":0,"errors":0,
                   "logs":[],"matrix":[],"started_at":time.time(),"finished_at":None}

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
