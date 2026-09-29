from scanners.authenticated_parameter_diff import _build_url, compare_parameter


def test_build_url_locks_to_origin():
    assert _build_url(
        "http://127.0.0.1:5000",
        "/api/orders?owner={owner}",
        "owner",
        "alice",
    ) == "http://127.0.0.1:5000/api/orders?owner=alice"


def test_build_url_requires_placeholder():
    try:
        _build_url("http://127.0.0.1:5000", "/api/orders/1", "id", "2")
    except ValueError:
        return
    raise AssertionError("missing placeholder should fail")


def test_parameter_differential_uses_get_only():
    calls = []

    class Response:
        def __init__(self, body, status=200):
            self.content = body
            self.status_code = status
            self.headers = {"Content-Type": "application/json"}

    class Session:
        def __init__(self, bodies):
            self.bodies = bodies

        def get(self, url, **kwargs):
            calls.append(("GET", url))
            return Response(self.bodies[url])

        def post(self, *args, **kwargs):
            raise AssertionError("parameter differential must not POST")

    base = "http://127.0.0.1:5000"
    urls = [
        f"{base}/api/orders?owner=alice",
        f"{base}/api/orders?owner=bob",
    ]
    session_a = Session({urls[0]: b"A", urls[1]: b"B"})
    session_b = Session({urls[0]: b"A", urls[1]: b"B"})
    result = compare_parameter(
        session_a, session_b, base, "/api/orders?owner={owner}", "owner", "alice", "bob"
    )
    assert len(calls) == 4
    assert all(method == "GET" for method, _ in calls)
    assert result["cross_account_match"] == {"a_to_b": True, "b_to_a": True}


def test_parameter_differential_requires_different_values():
    class Session:
        pass

    try:
        compare_parameter(Session(), Session(), "http://127.0.0.1:5000",
                          "/api/orders?owner={owner}", "owner", "same", "same")
    except ValueError:
        return
    raise AssertionError("same values should fail")
