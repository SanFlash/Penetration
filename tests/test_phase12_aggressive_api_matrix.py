import os,sys
sys.path.insert(0,os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scanners.phase12_aggressive_api_matrix import redact_url,json_shape,_query_mutations,_safe_url

class R:
    headers={"Content-Type":"application/json"}
    def __init__(self,payload): self._p=payload
    def json(self): return self._p

def test_phase12_redacts_secrets():
    u=redact_url("https://example.test/api?token=abc&name=x&api_key=secret")
    assert "abc" not in u and "secret" not in u and "name=x" in u

def test_phase12_json_shape_omits_secret_keys():
    shape=json_shape(R({"id":1,"email":"x","token":"hidden","items":[{"name":"x"}]}))
    assert "token" not in shape and shape["id"]=="int" and shape["items"]==[{"name":"str"}]

def test_phase12_mutations_bounded():
    xs=_query_mutations("https://example.test/api?page=1&q=x",5)
    assert len(xs)==5 and all(len(v)<=128 for _,v,_ in xs)

def test_phase12_origin_lock():
    assert _safe_url("https://example.test","/api/x")=="https://example.test/api/x"

def test_phase12_rejects_relative_endpoint():
    try: _safe_url("https://example.test","api/x")
    except ValueError: return
    assert False

def test_phase12_redacts_case_insensitive():
    assert "Bearer" not in redact_url("https://example.test/x?Authorization=Bearer")

def test_phase12_rejects_cross_origin():
    try: _safe_url("https://example.test","https://evil.test/x")
    except ValueError: return
    assert False
