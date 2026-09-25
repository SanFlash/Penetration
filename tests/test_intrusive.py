import json

import pytest

from scanners.intrusive import IntrusiveConfigurationError, load_plan


def test_intrusive_plan_requires_exact_target_and_rollback(tmp_path):
    path = tmp_path / "plan.json"
    path.write_text(json.dumps({
        "mode": "controlled-destructive-v1",
        "destructive_ack": "I_UNDERSTAND_CONTROLLED_DATA_CHANGE",
        "target_origin": "https://example.com",
        "operations": [{
            "name": "create",
            "method": "POST",
            "url": "/api/test-records",
            "disposable_resource": True,
            "id_path": "id",
            "rollback": {"method": "DELETE", "url": "/api/test-records/{resource_id}"}
        }]
    }), encoding="utf-8")
    assert load_plan(str(path), "https://example.com")


def test_intrusive_plan_rejects_cross_origin(tmp_path):
    path = tmp_path / "plan.json"
    path.write_text(json.dumps({
        "mode": "controlled-destructive-v1",
        "destructive_ack": "I_UNDERSTAND_CONTROLLED_DATA_CHANGE",
        "target_origin": "https://example.com",
        "operations": [{
            "method": "POST",
            "url": "https://evil.example/api",
            "disposable_resource": True,
            "id_path": "id",
            "rollback": {"method": "DELETE", "url": "/api/test/{resource_id}"}
        }]
    }), encoding="utf-8")
    with pytest.raises(IntrusiveConfigurationError):
        load_plan(str(path), "https://example.com")


def test_intrusive_update_requires_restore_body(tmp_path):
    path = tmp_path / "plan.json"
    path.write_text(json.dumps({
        "mode": "controlled-destructive-v1",
        "destructive_ack": "I_UNDERSTAND_CONTROLLED_DATA_CHANGE",
        "target_origin": "https://example.com",
        "operations": [{
            "method": "PATCH",
            "url": "/api/test/1",
            "disposable_resource": True,
            "json": {"name": "changed"},
            "rollback": {"method": "PATCH", "url": "/api/test/1"}
        }]
    }), encoding="utf-8")
    with pytest.raises(IntrusiveConfigurationError):
        load_plan(str(path), "https://example.com")


def test_intrusive_plan_rejects_template_placeholders(tmp_path):
    path = tmp_path / "plan.json"
    path.write_text(json.dumps({
        "mode": "controlled-destructive-v1",
        "destructive_ack": "I_UNDERSTAND_CONTROLLED_DATA_CHANGE",
        "target_origin": "https://example.com",
        "operations": [{
            "method": "POST",
            "url": "/REPLACE_WITH_TEST_CREATE_ENDPOINT",
            "disposable_resource": True,
            "id_path": "id",
            "rollback": {"method": "DELETE", "url": "/api/test/{resource_id}"}
        }]
    }), encoding="utf-8")
    with pytest.raises(IntrusiveConfigurationError, match="template placeholder"):
        load_plan(str(path), "https://example.com")


def test_intrusive_plan_requires_id_path_for_resource_rollback(tmp_path):
    path = tmp_path / "plan.json"
    path.write_text(json.dumps({
        "mode": "controlled-destructive-v1",
        "destructive_ack": "I_UNDERSTAND_CONTROLLED_DATA_CHANGE",
        "target_origin": "https://example.com",
        "operations": [{
            "method": "POST",
            "url": "/api/test-records",
            "disposable_resource": True,
            "rollback": {"method": "DELETE", "url": "/api/test-records/{resource_id}"}
        }]
    }), encoding="utf-8")
    with pytest.raises(IntrusiveConfigurationError, match="id_path"):
        load_plan(str(path), "https://example.com")


def test_controlled_destructive_plan_requires_ack_and_disposable_resource(tmp_path):
    path = tmp_path / "plan.json"
    path.write_text(json.dumps({
        "mode": "controlled-destructive-v1",
        "target_origin": "https://example.com",
        "operations": [{
            "method": "POST",
            "url": "/api/test-records",
            "rollback": {"method": "DELETE", "url": "/api/test-records/{resource_id}"},
            "id_path": "id",
            "disposable_resource": True
        }]
    }), encoding="utf-8")
    with pytest.raises(IntrusiveConfigurationError, match="destructive_ack"):
        load_plan(str(path), "https://example.com")


def test_controlled_destructive_plan_rejects_non_disposable_operation(tmp_path):
    path = tmp_path / "plan.json"
    path.write_text(json.dumps({
        "mode": "controlled-destructive-v1",
        "destructive_ack": "I_UNDERSTAND_CONTROLLED_DATA_CHANGE",
        "target_origin": "https://example.com",
        "operations": [{
            "method": "POST",
            "url": "/api/test-records",
            "rollback": {"method": "DELETE", "url": "/api/test-records/{resource_id}"},
            "id_path": "id"
        }]
    }), encoding="utf-8")
    with pytest.raises(IntrusiveConfigurationError, match="disposable_resource"):
        load_plan(str(path), "https://example.com")


def test_controlled_destructive_plan_rejects_standalone_delete_action(tmp_path):
    path = tmp_path / "plan.json"
    path.write_text(json.dumps({
        "mode": "controlled-destructive-v1",
        "destructive_ack": "I_UNDERSTAND_CONTROLLED_DATA_CHANGE",
        "target_origin": "https://example.com",
        "operations": [{
            "method": "DELETE",
            "url": "/api/test-records/123",
            "disposable_resource": True,
            "rollback": {"method": "POST", "url": "/api/test-records"}
        }]
    }), encoding="utf-8")
    with pytest.raises(IntrusiveConfigurationError, match="unsupported method DELETE"):
        load_plan(str(path), "https://example.com")
