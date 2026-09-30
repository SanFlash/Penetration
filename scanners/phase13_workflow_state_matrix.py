"""Phase 13: read-only authenticated workflow state/action matrix."""
from __future__ import annotations
import hashlib,json,os,re
from pathlib import Path
from urllib.parse import quote,urljoin
import requests
from utils.scope import assert_same_target

TIMEOUT=10
ALLOWED_LOGIN={200,201,202,204,302,303}
def _fp(r):
    return {"status":r.status_code,"bytes":len(r.content),"content_type":r.headers.get("Content-Type",""),
            "allow":r.headers.get("Allow",""),"sha256":hashlib.sha256(r.content[:200000]).hexdigest()}
def _decision(r):
    if "json" not in r.headers.get("Content-Type","").lower(): return None
    try:p=r.json()
    except (ValueError,TypeError):return None
    if isinstance(p,dict):
        for k in ("allowed","authorized","permitted"):
            if isinstance(p.get(k),bool):return p[k]
        if isinstance(p.get("decision"),dict):
            for k in ("allowed","authorized","permitted"):
                if isinstance(p["decision"].get(k),bool):return p["decision"][k]
    return None
def login(base,user_env,pass_env,path="/login"):
    u,p=os.getenv(user_env),os.getenv(pass_env)
    if not u or not p: raise RuntimeError(f"Missing credentials in {user_env}/{pass_env}")
    if not path.startswith("/"): raise ValueError("login path must begin with /")
    url=urljoin(base.rstrip("/")+"/",path.lstrip("/")); assert_same_target(base,url)
    s=requests.Session(); s.headers["User-Agent"]="Sentinel-Phase13-WorkflowMatrix/1.0"
    r=s.post(url,data={"username":u,"password":p},timeout=TIMEOUT,allow_redirects=False)
    if r.status_code not in ALLOWED_LOGIN: raise RuntimeError(f"Authentication failed: HTTP {r.status_code}")
    return s
def _url(base,tpl,obj,action):
    if not tpl.startswith("/") or "{id}" not in tpl or "{action}" not in tpl: raise ValueError("endpoint must be absolute and contain {id} and {action}")
    u=urljoin(base.rstrip("/")+"/",tpl.format(id=quote(str(obj),safe=""),action=quote(str(action),safe="")).lstrip("/"))
    assert_same_target(base,u); return u
def run_phase13(base_url,endpoint,cases,user_a_env="SENTINEL_TEST_A_USER",pass_a_env="SENTINEL_TEST_A_PASS",
                user_b_env="SENTINEL_TEST_B_USER",pass_b_env="SENTINEL_TEST_B_PASS",object_a=None,object_b=None,
                login_path="/login",max_probes=60,evidence_dir="evidence"):
    base=base_url.rstrip("/")
    if object_a is None or object_b is None or str(object_a)==str(object_b): raise ValueError("two distinct disposable object IDs are required")
    if not cases: raise ValueError("at least one action case is required")
    if max_probes<1 or max_probes>300: raise ValueError("max_probes must be 1..300")
    a=login(base,user_a_env,pass_a_env,login_path); b=login(base,user_b_env,pass_b_env,login_path)
    matrix=[]; findings=[]; probes=0
    for case in cases:
        if probes+2>max_probes: break
        action,expected_a,expected_b, state_a, state_b = case
        rows=[]
        for label,s,obj,state,expected in (("state_a",a,object_a,state_a,expected_a),("state_b",b,object_b,state_b,expected_b)):
            u=_url(base,endpoint,obj,action)
            r=s.get(u,timeout=TIMEOUT,allow_redirects=False); probes+=1
            observed=_decision(r)
            row={"case":action,"object_id":str(obj),"known_state":state,"expected_allowed":expected,
                 "observed_allowed":observed,"url":u,"fingerprint":_fp(r)}
            rows.append(row)
            if observed is not None and observed!=expected:
                findings.append({"id":"P13-WORKFLOW-001","title":"Workflow state/action authorization mismatch",
                                 "severity":"High","confidence":"High","category":"Business Workflow Authorization",
                                 "cwe":"CWE-841","owasp":"API6:2023 Unrestricted Access to Sensitive Business Flows",
                                 "method":"GET","url":u,
                                 "detail":f"Action '{action}' returned {observed} for state '{state}', expected {expected}.",
                                 "impact":"A sensitive workflow action may be reachable in an invalid state.",
                                 "remediation":"Enforce server-side state-machine transitions and authorize the action against trusted current state and principal.",
                                 "evidence":row})
        # Differential consistency: two different states should not collapse to identical
        # authorization decisions when the operator declared them different.
        if len(rows)==2 and rows[0]["observed_allowed"] is not None and rows[1]["observed_allowed"] is not None:
            if rows[0]["observed_allowed"]==rows[1]["observed_allowed"] and expected_a!=expected_b:
                findings.append({"id":"P13-WORKFLOW-002","title":"State differential collapsed for an authorization-sensitive action",
                                 "severity":"Medium","confidence":"Medium","category":"Workflow State Differential",
                                 "cwe":"CWE-841","method":"GET","url":rows[0]["url"],
                                 "detail":f"Action '{action}' produced the same observed authorization decision across two operator-declared states despite different expected decisions.",
                                 "impact":"The application may not be enforcing a state-dependent authorization rule consistently.",
                                 "remediation":"Validate the authoritative workflow state on every action and reject actions outside the allowed transition set.",
                                 "evidence":{"state_a":rows[0],"state_b":rows[1]}})
        matrix.append({"action":action,"state_a":state_a,"state_b":state_b,"responses":rows})
    evidence={"schema":"phase13-workflow-state-action-matrix-1.0","target":base,
              "endpoint_template":endpoint,"objects":{"a":str(object_a),"b":str(object_b)},
              "matrix":matrix,"findings":findings,
              "safety":{"method":"GET","same_origin":True,"redirects":False,"state_changing_requests":False,
                        "automatic_state_transition":False,"operator_supplied_expected_decisions":True},
              "limits":{"max_probes":max_probes,"actual_probes":probes},
              "summary":{"actions_tested":len(matrix),"probes":probes,"findings":len(findings)}}
    Path(evidence_dir).mkdir(parents=True,exist_ok=True)
    Path(evidence_dir,"phase13_workflow_state_matrix.json").write_text(json.dumps(evidence,indent=2),encoding="utf-8")
    return evidence
