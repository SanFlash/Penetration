"""Phase 12: aggressive-but-controlled authenticated API attack-surface matrix."""
from __future__ import annotations
import hashlib, json, os, re, time
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, quote, urlencode, urlparse, urlunparse
import requests
from utils.scope import assert_same_target

MAX_BODY=200_000
TIMEOUT=10
SAFE_METHODS=("GET","HEAD","OPTIONS")
REDACT_KEYS=re.compile(r"(token|secret|password|passwd|api[_-]?key|authorization|cookie|session)",re.I)

def redact_url(url:str)->str:
    p=urlparse(url); pairs=[]
    for k,v in parse_qsl(p.query,keep_blank_values=True):
        pairs.append((k,"[REDACTED]" if REDACT_KEYS.search(k) else v))
    return urlunparse((p.scheme,p.netloc,p.path,p.params,urlencode(pairs),p.fragment))

def fp(resp:requests.Response)->dict[str,Any]:
    return {"status":resp.status_code,"bytes":len(resp.content),"content_type":resp.headers.get("Content-Type",""),
            "location":resp.headers.get("Location",""),"allow":resp.headers.get("Allow",""),
            "sha256":hashlib.sha256(resp.content[:MAX_BODY]).hexdigest()}

def json_shape(resp:requests.Response)->dict[str,Any]:
    if "json" not in resp.headers.get("Content-Type","").lower(): return {}
    try: obj=resp.json()
    except (ValueError,TypeError): return {}
    def shape(x):
        if isinstance(x,dict): return {str(k):shape(v) for k,v in sorted(x.items()) if not REDACT_KEYS.search(str(k))}
        if isinstance(x,list): return [shape(x[0])] if x else []
        return type(x).__name__
    return shape(obj)

def login(base,user_env,pass_env,login_path="/login"):
    u,p=os.getenv(user_env),os.getenv(pass_env)
    if not u or not p: raise RuntimeError(f"Missing credentials in {user_env}/{pass_env}")
    if not login_path.startswith("/"): raise ValueError("login path must start with /")
    url=base.rstrip("/") + login_path; assert_same_target(base,url)
    s=requests.Session(); s.headers["User-Agent"]="Sentinel-Phase12-Authorized/1.0"
    r=s.post(url,data={"username":u,"password":p},timeout=TIMEOUT,allow_redirects=False)
    if r.status_code not in {200,201,202,204,302,303}: raise RuntimeError(f"Authentication failed: HTTP {r.status_code}")
    return s

def _safe_url(base,endpoint):
    if not endpoint.startswith("/"): raise ValueError("endpoint must be an absolute same-origin path")
    url=base.rstrip("/") + endpoint; assert_same_target(base,url); return url

def _query_mutations(url,max_probes):
    pairs=parse_qsl(urlparse(url).query,keep_blank_values=True); vals=["","0","-1","1.5","abc","A"*128,"%2F","🙂"]
    out=[]; seen=set()
    for name,_ in pairs:
        for value in vals:
            if len(out)>=max_probes: return out
            p=urlparse(url); qp=[(k,value if k==name else v) for k,v in pairs]
            m=urlunparse((p.scheme,p.netloc,p.path,p.params,urlencode(qp),p.fragment))
            if m not in seen: seen.add(m); out.append((name,value,m))
    return out

def run_phase12(base_url,endpoints,login_path,user_a_env,pass_a_env,user_b_env,pass_b_env,
                object_endpoint=None,object_a=None,object_b=None,max_probes=80,evidence_dir="evidence"):
    base=base_url.rstrip("/")
    if not endpoints: raise ValueError("At least one endpoint is required")
    if not 1<=max_probes<=300: raise ValueError("max_probes must be 1..300")
    for e in endpoints: _safe_url(base,e)
    a=login(base,user_a_env,pass_a_env,login_path); b=login(base,user_b_env,pass_b_env,login_path)
    sessions={"unauthenticated":requests.Session(),"user_a":a,"user_b":b}
    inventory=[]; findings=[]; probes=0
    for endpoint in endpoints:
        url=_safe_url(base,endpoint); row={"endpoint":endpoint,"url":redact_url(url),"methods":{}}
        row["query_parameters"]=list(dict.fromkeys(k for k,_ in parse_qsl(urlparse(url).query,keep_blank_values=True)))
        for label,s in sessions.items():
            row["methods"][label]={}
            for method in SAFE_METHODS:
                if probes>=max_probes: break
                t=time.monotonic()
                try:
                    r=s.request(method,url,timeout=TIMEOUT,allow_redirects=False); probes+=1
                    row["methods"][label][method]={"fingerprint":fp(r),"shape":json_shape(r),
                                                    "elapsed_ms":round((time.monotonic()-t)*1000,1)}
                except requests.RequestException as exc: row["methods"][label][method]={"error":str(exc)}
        ua=row["methods"].get("user_a",{}).get("GET",{}).get("fingerprint",{})
        un=row["methods"].get("unauthenticated",{}).get("GET",{}).get("fingerprint",{})
        if ua.get("status")==200 and un.get("status")==200 and ua.get("sha256")==un.get("sha256"):
            findings.append({"id":"P12-AUTH-001","title":"Authenticated endpoint is indistinguishable from unauthenticated GET",
                             "severity":"High","confidence":"Medium","category":"API Authorization","cwe":"CWE-306",
                             "method":"GET","url":redact_url(url),
                             "detail":"The same successful response fingerprint was observed before and after authentication.",
                             "impact":"If intended to be private, unauthenticated callers may receive the same data.",
                             "remediation":"Enforce authentication and authorization at the API boundary and verify intended public endpoints.",
                             "evidence":{"authenticated":ua,"unauthenticated":un}})
        budget=max(0,min(8,max_probes-probes))
        for name,value,mutated in _query_mutations(url,budget):
            r=a.get(mutated,timeout=TIMEOUT,allow_redirects=False); probes+=1
            item={"parameter":name,"value_length":len(value),"value_preview":value[:40],"fingerprint":fp(r),"url":redact_url(mutated)}
            row.setdefault("parameter_differentials",[]).append(item)
            if r.status_code>=500:
                findings.append({"id":"P12-INPUT-001","title":"Bounded malformed input reached a server error","severity":"Medium",
                                 "confidence":"Medium","category":"Input Validation","cwe":"CWE-20","method":"GET","url":redact_url(mutated),
                                 "detail":f"Parameter '{name}' produced HTTP {r.status_code}.",
                                 "impact":"Unhandled input may expose error paths or cause instability.",
                                 "remediation":"Validate types, ranges, encoding and requiredness and return controlled 4xx responses.","evidence":item})
        inventory.append(row)
        if probes>=max_probes: break
    bola=None
    if object_endpoint and object_a is not None and object_b is not None:
        if str(object_a)==str(object_b): raise ValueError("BOLA object IDs must differ")
        cases=[("a_own",a,object_a),("a_other",a,object_b),("b_own",b,object_b),("b_other",b,object_a)]
        responses={}
        for key,s,obj in cases:
            endpoint=object_endpoint.format(id=quote(str(obj),safe="")); url=_safe_url(base,endpoint)
            r=s.get(url,timeout=TIMEOUT,allow_redirects=False); probes+=1
            responses[key]={"url":redact_url(url),"fingerprint":fp(r),"shape":json_shape(r)}
        bypasses=[]
        for own,other in (("a_own","a_other"),("b_own","b_other")):
            if responses[other]["fingerprint"]["status"]==200 and responses[other]["fingerprint"]["sha256"]==responses[own]["fingerprint"]["sha256"]:
                bypasses.append(other)
        if bypasses:
            findings.append({"id":"P12-BOLA-001","title":"Potential cross-account object authorization bypass","severity":"High",
                             "confidence":"High","category":"Authorization / BOLA","cwe":"CWE-639",
                             "owasp":"API1:2023 Broken Object Level Authorization","method":"GET","url":responses[bypasses[0]]["url"],
                             "detail":"A second account received an indistinguishable successful response for another disposable object's endpoint.",
                             "impact":"An authenticated user may access another user's object by changing its identifier.",
                             "remediation":"Authorize object ownership/access server-side for every lookup.","evidence":responses})
        bola={"objects":{"a":str(object_a),"b":str(object_b)},"responses":responses,"bypasses":bypasses}
    evidence={"schema":"phase12-aggressive-api-matrix-1.0","target":base,
              "scope_policy":"exact same-origin; redirects disabled; GET/HEAD/OPTIONS application probes",
              "safety":{"state_changing_requests":False,"credential_attacks":False,"dos":False,"persistence":False},
              "limits":{"max_probes":max_probes,"actual_probes":probes,"timeout_seconds":TIMEOUT},
              "inventory":inventory,"bola":bola,"findings":findings,
              "summary":{"endpoints_tested":len(inventory),"findings":len(findings),"bola_tested":bola is not None,"probes":probes}}
    Path(evidence_dir).mkdir(parents=True,exist_ok=True)
    Path(evidence_dir,"phase12_aggressive_api_matrix.json").write_text(json.dumps(evidence,indent=2),encoding="utf-8")
    return evidence
