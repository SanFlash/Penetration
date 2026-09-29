from scanners.workflow_state_preconditions import (
    _build_url,
    assess_workflow_preconditions,
)


def test_build_url_requires_state_workflow_template():
    assert _build_url(
        "http://127.0.0.1:5000",
        "/api/orders/{id}/workflow/{action}",
        "1",
        "cancel",
    ) == "http://127.0.0.1:5000/api/orders/1/workflow/cancel"


def test_build_url_rejects_external_template():
    try:
        _build_url(
            "http://127.0.0.1:5000",
            "https://evil.example/{id}/{action}",
            "1",
            "cancel",
        )
    except ValueError:
        return
    raise AssertionError("external template should fail")


class Response:
    def __init__(self, allowed):
        self.status_code = 200
        self.content = ('{"allowed":%s}' % str(allowed).lower()).encode()
        self.headers = {"Content-Type": "application/json"}

    def json(self):
        return {"allowed": self.content == b'{"allowed":true}'}


class Session:
    def __init__(self, decisions):
        self.decisions = decisions

    def get(self, url, **kwargs):
        object_id = url.split("/orders/", 1)[1].split("/", 1)[0]
        return Response(self.decisions[object_id])


def test_expected_state_decisions_pass():
    result = assess_workflow_preconditions(
        Session({"1": True, "2": False}),
        "http://127.0.0.1:5000",
        "/api/orders/{id}/workflow/{action}",
        "1",
        "2",
        "cancel",
        True,
        False,
        "pending",
        "completed",
    )
    assert result["mismatches"] == []
    assert result["findings"] == []


def test_invalid_state_decision_is_detected():
    result = assess_workflow_preconditions(
        Session({"1": True, "2": True}),
        "http://127.0.0.1:5000",
        "/api/orders/{id}/workflow/{action}",
        "1",
        "2",
        "cancel",
        True,
        False,
        "pending",
        "completed",
    )
    assert result["mismatches"] == ["state_b"]
    assert result["findings"][0]["id"] == "P9-WORKFLOW-001"


def test_both_states_can_be_expected_denied():
    result = assess_workflow_preconditions(
        Session({"1": False, "2": False}),
        "http://127.0.0.1:5000",
        "/api/orders/{id}/workflow/{action}",
        "1",
        "2",
        "cancel",
        False,
        False,
        "cancelled",
        "completed",
    )
    assert result["mismatches"] == []
    assert result["findings"] == []


def test_same_object_ids_rejected():
    try:
        assess_workflow_preconditions(
            Session({"1": True}),
            "http://127.0.0.1:5000",
            "/api/orders/{id}/workflow/{action}",
            "1",
            "1",
            "cancel",
            True,
            False,
            "pending",
            "completed",
        )
    except ValueError:
        return
    raise AssertionError("same object IDs should fail")


def test_same_states_rejected_for_differential_check():
    try:
        assess_workflow_preconditions(
            Session({"1": True, "2": True}),
            "http://127.0.0.1:5000",
            "/api/orders/{id}/workflow/{action}",
            "1",
            "2",
            "cancel",
            True,
            True,
            "pending",
            "pending",
        )
    except ValueError:
        return
    raise AssertionError("same workflow states should fail")
