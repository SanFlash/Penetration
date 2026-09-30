from scanners.authz_correlation import _build_url, assess_correlation

def test_build_url_requires_all_placeholders():
    try: _build_url("http://127.0.0.1:5000","/api/{id}/{owner}","1","alice","cancel")
    except ValueError: return
    raise AssertionError("missing action placeholder should fail")

def test_build_url_rejects_external_target():
    try: _build_url("http://127.0.0.1:5000","https://evil.test/{id}/{owner}/{action}","1","alice","cancel")
    except ValueError: return
    raise AssertionError("external endpoint should fail")

def test_correlation_detects_invalid_allowed_decision():
    class Response:
        content=b'{"allowed":true}'; status_code=200; headers={"Content-Type":"application/json"}
        def json(self): return {"allowed":True}
    class Session:
        def get(self,url,**kwargs): return Response()
    result=assess_correlation(Session(),Session(),"http://127.0.0.1:5000","/api/orders/{id}/correlate?owner={owner}&action={action}","1","2","alice","bob","cancel",True,False)
    assert result["mismatches"] and len(result["findings"])==1

def test_correlation_accepts_expected_decisions():
    class Response:
        content=b'{"allowed":false}'; status_code=200; headers={"Content-Type":"application/json"}
        def json(self): return {"allowed":False}
    class Session:
        def get(self,url,**kwargs): return Response()
    result=assess_correlation(Session(),Session(),"http://127.0.0.1:5000","/api/orders/{id}/correlate?owner={owner}&action={action}","1","2","alice","bob","cancel",False,False)
    assert result["mismatches"]==[] and result["findings"]==[]

def test_same_objects_are_rejected():
    class Session: pass
    try: assess_correlation(Session(),Session(),"http://127.0.0.1:5000","/api/{id}/{owner}/{action}","1","1","alice","bob","cancel",True,False)
    except ValueError: return
    raise AssertionError("same objects should fail")
