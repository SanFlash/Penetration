from scanners.authenticated_method_diff import _build_url, compare_methods


def test_build_url_requires_id_placeholder():
    assert _build_url("http://127.0.0.1:5000", "/api/orders/{id}", "2") == "http://127.0.0.1:5000/api/orders/2"


def test_build_url_rejects_external_template():
    try:
        _build_url("http://127.0.0.1:5000", "https://evil.example/{id}", "2")
    except ValueError:
        return
    raise AssertionError("external template should fail")


def test_method_differential_only_uses_read_only_methods():
    calls = []

    class Response:
        def __init__(self, status=403, body=b""):
            self.content = body
            self.status_code = status
            self.headers = {"Content-Type": "application/json", "Allow": "GET, HEAD, OPTIONS"}

    class Session:
        def request(self, method, url, **kwargs):
            calls.append((method, url))
            return Response(403, b"denied")

        def post(self, *args, **kwargs):
            raise AssertionError("method differential must not POST")

    result = compare_methods(Session(), Session(), "http://127.0.0.1:5000", "/api/orders/{id}", "1", "2")
    assert len(calls) == 12
    assert {method for method, _ in calls} == {"GET", "HEAD", "OPTIONS"}
    assert result["findings"] == []


def test_head_bypass_is_detected():
    class Response:
        def __init__(self, status, body=b""):
            self.content = body
            self.status_code = status
            self.headers = {"Content-Type": "application/json"}

    class Session:
        def __init__(self, owner):
            self.owner = owner

        def request(self, method, url, **kwargs):
            object_id = url.rsplit("/", 1)[-1]
            if method == "GET":
                return Response(200, object_id.encode()) if object_id == self.owner else Response(403, b"denied")
            if method == "HEAD":
                return Response(200, object_id.encode())
            return Response(204, b"")

    result = compare_methods(Session("1"), Session("2"), "http://127.0.0.1:5000", "/api/orders/{id}", "1", "2")
    assert result["head_authorization_bypass"] == {"a_to_b": True, "b_to_a": True}
    assert len(result["findings"]) == 1


def test_same_object_ids_are_rejected():
    class Session:
        pass

    try:
        compare_methods(Session(), Session(), "http://127.0.0.1:5000", "/api/orders/{id}", "1", "1")
    except ValueError:
        return
    raise AssertionError("same object IDs should fail")
