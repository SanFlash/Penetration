import unittest
from unittest.mock import Mock
from integrations.zap_runner import ZapRunner, ZapError, origin, _same_origin, validate_api_url


class ZapRunnerSafetyTests(unittest.TestCase):
    def test_origin_normalizes_default_port_and_path(self):
        self.assertEqual(origin("https://Example.com:443/app?q=1"), "https://example.com")

    def test_rejects_non_http_target(self):
        with self.assertRaises(ValueError):
            origin("file:///etc/passwd")

    def test_rejects_embedded_credentials(self):
        with self.assertRaises(ValueError):
            origin("https://user:pass@example.com")

    def test_zap_api_must_be_loopback(self):
        with self.assertRaises(ValueError):
            validate_api_url("http://example.com:8080")

    def test_same_origin_rejects_lookalike_host(self):
        self.assertTrue(_same_origin("https://example.com", "https://example.com/path"))
        self.assertFalse(_same_origin("https://example.com", "https://example.com.attacker.test/"))

    def test_context_is_required_before_api_request(self):
        session = Mock()
        runner = ZapRunner(session=session)
        with self.assertRaises(ValueError):
            runner.run("https://example.com", confirm_authorized=True)
        session.get.assert_not_called()

    def test_authorization_gate_blocks_before_api_request(self):
        session = Mock()
        runner = ZapRunner(session=session, context_name="Authorized staging")
        with self.assertRaises(PermissionError):
            runner.run("https://example.com")
        session.get.assert_not_called()

    def test_active_scan_requires_second_confirmation(self):
        session = Mock()
        runner = ZapRunner(session=session, context_name="Authorized staging")
        with self.assertRaises(PermissionError):
            runner.run("https://example.com", confirm_authorized=True, active=True)
        session.get.assert_not_called()

    def test_api_key_uses_header_not_query_parameter(self):
        response = Mock()
        response.raise_for_status.return_value = None
        response.json.return_value = {"scan": "1"}
        session = Mock()
        session.get.return_value = response
        runner = ZapRunner(session=session, api_key="secret", context_name="Authorized staging")
        runner._get("spider", "action", "scan")
        kwargs = session.get.call_args.kwargs
        self.assertEqual(kwargs["headers"], {"X-ZAP-API-Key": "secret"})
        self.assertNotIn("apikey", kwargs["params"])

    def test_non_json_api_response_is_rejected(self):
        response = Mock()
        response.raise_for_status.return_value = None
        response.json.side_effect = ValueError("invalid json")
        session = Mock()
        session.get.return_value = response
        runner = ZapRunner(session=session, context_name="Authorized staging")
        with self.assertRaises(ZapError):
            runner._get("spider", "action", "scan")


if __name__ == "__main__":
    unittest.main()
