from scanners.authenticated_workflow_auth import _build_url, compare_workflow_action


def test_build_url_formats_id_and_action():
    assert _build_url(
        "http://127.0.0.1:5000",
        "/api/orders/{id}/action/{action}",
        "1",
        "cancel",
    ) == "http://127.0.0.1:5000/api/orders/1/action/cancel"


def test_build_url_rejects_external_template():
    try:
        _build_url("http://127.0.0.1:5000", "https://evil.example/{id}/{action}", "1", "cancel")
    except ValueError:
        return
    raise AssertionError("external template should fail")


def test_workflow_check_uses_get_only():
    calls = []

    class Response:
        def __init__(self):
            self.content = b"denied"
            self.status_code = 403
            self.headers = {"Content-Type": "application/json"}

    class Session:
        def get(self, url, **kwargs):
            calls.append(("GET", url))
            return Response()

        def post(self, *args, **kwargs):
            raise AssertionError("workflow assessment must not POST")

    result = compare_workflow_action(
        Session(), Session(), "http://127.0.0.1:5000",
        "/api/orders/{id}/action/{action}", "1", "2", "cancel",
    )
    assert len(calls) == 4
    assert all(method == "GET" for method, _ in calls)
    assert result["findings"] == []


def test_cross_account_workflow_bypass_is_detected():
    class Response:
        def __init__(self, status, body):
            self.content = body
            self.status_code = status
            self.headers = {"Content-Type": "application/json"}

    class Session:
        def __init__(self, owner):
            self.owner = owner

        def get(self, url, **kwargs):
            object_id = url.split("/orders/", 1)[1].split("/", 1)[0]
            if object_id == self.owner:
                return Response(200, b'{"allowed":true,"action":"cancel"}')
            return Response(200, b'{"allowed":true,"action":"cancel"}')

    result = compare_workflow_action(
        Session("1"), Session("2"), "http://127.0.0.1:5000",
        "/api/orders/{id}/action/{action}", "1", "2", "cancel",
    )
    assert result["cross_account_match"] == {"a_to_b": True, "b_to_a": True}
    assert len(result["findings"]) == 1


def test_same_object_ids_are_rejected():
    class Session:
        pass

    try:
        compare_workflow_action(
            Session(), Session(), "http://127.0.0.1:5000",
            "/api/orders/{id}/action/{action}", "1", "1", "cancel",
        )
    except ValueError:
        return
    raise AssertionError("same object IDs should fail")


def test_semantic_allowed_decision_detects_bypass_even_when_bodies_differ():
    class Response:
        def __init__(self, allowed, order_id):
            self.content = (
                '{"order_id":%d,"allowed":%s,"server_note":"unique-%d"}'
                % (order_id, str(allowed).lower(), order_id)
            ).encode()
            self.status_code = 200
            self.headers = {"Content-Type": "application/json"}

        def json(self):
            return {"order_id": 1, "allowed": True} if b'"allowed":true' in self.content else {
                "order_id": 2,
                "allowed": False,
            }

    class Session:
        def __init__(self, owner):
            self.owner = owner

        def get(self, url, **kwargs):
            object_id = url.split("/orders/", 1)[1].split("/", 1)[0]
            # Deliberately return different bodies while granting the same
            # authorization decision cross-account.
            return Response(True, int(object_id))

    result = compare_workflow_action(
        Session("1"), Session("2"), "http://127.0.0.1:5000",
        "/api/orders/{id}/action/{action}", "1", "2", "cancel",
    )
    assert result["cross_account_match"] == {"a_to_b": True, "b_to_a": True}
    assert result["detection"] == {"a_to_b": "semantic", "b_to_a": "semantic"}
    assert len(result["findings"]) == 1


def test_semantic_denial_does_not_report_bypass():
    class Response:
        def __init__(self, allowed):
            self.content = ('{"allowed":%s}' % str(allowed).lower()).encode()
            self.status_code = 200
            self.headers = {"Content-Type": "application/json"}

        def json(self):
            return {"allowed": b'"allowed":true' in self.content}

    class Session:
        def __init__(self, owner):
            self.owner = owner

        def get(self, url, **kwargs):
            object_id = url.split("/orders/", 1)[1].split("/", 1)[0]
            return Response(str(object_id) == self.owner)

    result = compare_workflow_action(
        Session("1"), Session("2"), "http://127.0.0.1:5000",
        "/api/orders/{id}/action/{action}", "1", "2", "cancel",
    )
    assert result["cross_account_match"] == {"a_to_b": False, "b_to_a": False}
    assert result["findings"] == []
