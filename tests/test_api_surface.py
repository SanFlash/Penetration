import json

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
        content = json.dumps(payload).encode()

    engine.parse_spec("https://example.com/openapi.json", Response())

    assert len(engine.specs) == 1
    assert len(engine.endpoints) == 3
    assert any(x["category"] == "API Authorization" for x in engine.findings)
    assert any(x["category"] == "API Inventory" for x in engine.findings)
