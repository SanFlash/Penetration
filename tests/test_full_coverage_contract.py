import main
import web


def test_main_has_json_support_for_configured_zap_result_loading():
    # Full Pentest reads the ZAP JSON artifact before merging alerts into the
    # final combined report. This catches a NameError that only occurs when
    # the optional integration is configured.
    assert main.json.loads('{"alerts": []}') == {"alerts": []}


def test_full_pentest_advertises_all_builtin_engines_and_optional_zap():
    capabilities = web.PROFILE_CAPABILITIES["pentest"]
    required = {
        "recon", "ui_responsive", "accessibility", "functional_testing",
        "security_headers", "active_security", "deep_security", "api_surface",
        "route_discovery", "input_validation", "input_stress",
        "information_disclosure", "attack_surface", "security_evidence",
    }
    assert required.issubset(set(capabilities["engines"]))
    assert any("ZAP" in item for item in capabilities["external_integrations"])


def test_focused_profiles_are_supported_and_not_mislabeled_as_full_pentest():
    expected = {"security", "uiux", "functional", "input", "api", "disclosure", "crawler", "zap", "core"}
    assert expected.issubset(set(web.ALLOWED_PROFILES))
    assert web.PROFILE_CAPABILITIES["uiux"]["engines"] != web.PROFILE_CAPABILITIES["pentest"]["engines"]
