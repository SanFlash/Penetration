import json as jsonlib

from scanners.api_surface import ApiSurfaceEngine


def test_api_surface_exact_origin():
    engine = ApiSurfaceEngine("https://example.com")
    assert engine.same_origin("https://example.com/api")
    assert not engine.same_origin("https://example.com.evil.invalid/api")
    assert not engine.same_origin("https://other.example.com/api")


def test_openapi_parser_inventory():
    engine = ApiSurfaceEngine("https://example.com")
    payload = {
        "openapi": "3.0.3",
        "info": {"title": "Demo"},
        "security": [{"bearerAuth": []}],
        "paths": {
            "/users": {
                "get": {"operationId": "listUsers"},
                "post": {"operationId": "createUser"},
                "delete": {
                    "operationId": "deleteUser",
                    "deprecated": True,
                    "security": [],
                },
            }
        },
    }

    class Response:
        headers = {"Content-Type": "application/json"}

        def json(self):
            return payload

        status_code = 200
        content = jsonlib.dumps(payload).encode()

    engine.parse_spec("https://example.com/openapi.json", Response())

    assert len(engine.specs) == 1
    assert len(engine.endpoints) == 3
    assert any(x["category"] == "API Authorization" for x in engine.findings)
    assert any(x["category"] == "API Inventory" for x in engine.findings)



def test_api_surface_includes_passive_route_discovery(monkeypatch):
    monkeypatch.setattr(
        "scanners.api_surface.run_route_discovery",
        lambda *args, **kwargs: {
            "schema": "route-discovery-1.0",
            "summary": {
                "pages": 2,
                "assets": 1,
                "routes": 4,
                "api_like_routes": 2,
                "state_changing_candidates": 1,
            },
        },
    )

    engine = ApiSurfaceEngine("https://example.com")

    class Response:
        headers = {"Content-Type": "text/html"}
        status_code = 404
        content = b""
        text = ""

    monkeypatch.setattr(engine, "request", lambda url: Response())
    result = engine.run()

    assert result["route_discovery"]["schema"] == "route-discovery-1.0"
    assert result["route_discovery"]["summary"]["state_changing_candidates"] == 1
