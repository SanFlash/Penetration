import json

import pytest

from scanners.intrusive import IntrusiveConfigurationError, load_plan


def test_intrusive_plan_requires_exact_target_and_rollback(tmp_path):
    path = tmp_path / "plan.json"
    path.write_text(json.dumps({
        "target_origin": "https://example.com",
        "operations": [{
            "name": "create",
            "method": "POST",
            "url": "/api/test-records",
            "rollback": {"method": "DELETE", "url": "/api/test-records/{resource_id}"}
        }]
    }), encoding="utf-8")
    assert load_plan(str(path), "https://example.com")


def test_intrusive_plan_rejects_cross_origin(tmp_path):
    path = tmp_path / "plan.json"
    path.write_text(json.dumps({
        "target_origin": "https://example.com",
        "operations": [{
            "method": "POST",
            "url": "https://evil.example/api",
            "rollback": {"method": "DELETE", "url": "/api/test/{resource_id}"}
        }]
    }), encoding="utf-8")
    with pytest.raises(IntrusiveConfigurationError):
        load_plan(str(path), "https://example.com")


def test_intrusive_update_requires_restore_body(tmp_path):
    path = tmp_path / "plan.json"
    path.write_text(json.dumps({
        "target_origin": "https://example.com",
        "operations": [{
            "method": "PATCH",
            "url": "/api/test/1",
            "json": {"name": "changed"},
            "rollback": {"method": "PATCH", "url": "/api/test/1"}
        }]
    }), encoding="utf-8")
    with pytest.raises(IntrusiveConfigurationError):
        load_plan(str(path), "https://example.com")
