import os,sys
sys.path.insert(0,os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scanners.phase13_workflow_state_matrix import _url

def test_phase13_url_quotes_object_and_action():
    assert _url("https://example.test","/api/orders/{id}/workflow/{action}","1/2","cancel now")=="https://example.test/api/orders/1%2F2/workflow/cancel%20now"

def test_phase13_rejects_relative_template():
    try:_url("https://example.test","api/{id}/{action}","1","cancel")
    except ValueError:return
    assert False

def test_phase13_rejects_missing_tokens():
    try:_url("https://example.test","/api/orders/{id}","1","cancel")
    except ValueError:return
    assert False
