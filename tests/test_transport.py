"""
Tests for the shared request handling every call passes through.
"""

import unittest
import warnings
from unittest.mock import MagicMock, patch

import requests

from akips import AKIPS, AkipsError


class TransportTest(unittest.TestCase):
    @patch("requests.Session.get")
    def test_akips_error(self, session_mock: MagicMock):
        r_text = "ERROR: api-db invalid username/password"

        session_mock.return_value.ok = True
        session_mock.return_value.status_code = 200
        session_mock.return_value.text = r_text
        self.assertIsInstance(session_mock, MagicMock)

        api = AKIPS("127.0.0.1", ro_password="ro-secret")

        self.assertFalse(session_mock.called)
        self.assertRaises(AkipsError, api.get_devices)
        self.assertTrue(session_mock.called)

    @patch("requests.Session.get")
    def test_http_error_propagates(self, session_mock: MagicMock):
        session_mock.return_value.raise_for_status.side_effect = (
            requests.exceptions.HTTPError("500 Server Error")
        )

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        with self.assertRaises(requests.exceptions.HTTPError):
            api.get_devices()

    @patch("requests.Session.get")
    def test_connection_error_propagates(self, session_mock: MagicMock):
        session_mock.side_effect = requests.exceptions.ConnectionError("refused")

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        with self.assertRaises(requests.exceptions.ConnectionError):
            api.get_devices()

    @patch("requests.Session.get")
    def test_timeout_propagates(self, session_mock: MagicMock):
        session_mock.side_effect = requests.exceptions.Timeout("timed out")

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        with self.assertRaises(requests.exceptions.Timeout):
            api.get_devices()

    @patch("requests.Session.get")
    def test_request_exception_propagates(self, session_mock: MagicMock):
        session_mock.side_effect = requests.exceptions.RequestException("broken")

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        with self.assertRaises(requests.exceptions.RequestException):
            api.get_devices()

    @patch("requests.Session.get")
    def test_request_carries_credentials_and_timeout(self, session_mock: MagicMock):
        session_mock.return_value.text = ""

        api = AKIPS("akips.example.com", username="api-rw", password="secret")
        api.get_devices()
        args, kwargs = session_mock.call_args
        self.assertEqual(args[0], "https://akips.example.com/api-db")
        self.assertEqual(kwargs["params"]["username"], "api-rw")
        self.assertEqual(kwargs["params"]["password"], "secret")
        self.assertEqual(kwargs["timeout"], 30)
        self.assertTrue(kwargs["verify"])

    @patch("requests.Session.get")
    def test_verify_false_is_passed_through(self, session_mock: MagicMock):
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", ro_password="ro-secret", verify=False)
        api.get_devices()
        self.assertFalse(session_mock.call_args.kwargs["verify"])

    def test_redaction_hides_sensitive_values(self):
        api = AKIPS("127.0.0.1", password="secret")
        redacted = api._redact_sensitive_params(
            {
                "username": "api-ro",
                "password": "secret",
                "SNMP.community": "private",
                "cmds": "mget * * * *",
            }
        )
        self.assertEqual(redacted["password"], "****")
        self.assertEqual(redacted["SNMP.community"], "****")
        self.assertEqual(redacted["username"], "api-ro")
        self.assertEqual(redacted["cmds"], "mget * * * *")

    def test_parse_enum(self):
        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        entry = api._parse_enum("8,full,1581605551,1706545348,core-uplink")
        self.assertEqual(entry["number"], "8")
        self.assertEqual(entry["value"], "full")
        self.assertEqual(entry["description"], "core-uplink")
        self.assertEqual(entry["created"].year, 2020)
        self.assertEqual(entry["modified"].year, 2024)

    def test_parse_enum_with_empty_description(self):
        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        entry = api._parse_enum("2,up,1581605551,1706545348,")
        self.assertEqual(entry["value"], "up")
        self.assertEqual(entry["description"], "")

    def test_parse_enum_rejects_other_values(self):
        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        with self.assertRaises(AkipsError):
            api._parse_enum("not an enum value")

    def test_parse_enum_with_spaces_in_description(self):
        # Child descriptions routinely contain spaces, e.g. "Ethernet 1", so
        # the trailing field takes the rest of the line
        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        entry = api._parse_enum("8,full,1581605551,1706545348,uplink to core")
        self.assertEqual(entry["value"], "full")
        self.assertEqual(entry["description"], "uplink to core")

    @patch("requests.Session.get")
    def test_get_does_not_mutate_the_callers_params(self, session_mock: MagicMock):
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", password="secret")
        caller_params = {"cmds": "mget * * * *"}
        api._get(params=caller_params)
        # Credentials belong on the request, not in the dictionary the caller
        # still holds and may log or reuse
        self.assertEqual(caller_params, {"cmds": "mget * * * *"})
        self.assertEqual(session_mock.call_args.kwargs["params"]["password"], "secret")

    @patch("requests.Session.get")
    def test_get_accepts_no_params(self, session_mock: MagicMock):
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        # params is documented as optional, so omitting it must not raise
        self.assertEqual(api._get(section="api-db"), "")
        self.assertIn("username", session_mock.call_args.kwargs["params"])

    @patch("requests.Session.get")
    def test_verify_true_leaves_the_warning_filter_alone(self, session_mock: MagicMock):
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        before = list(warnings.filters)
        api.get_devices()
        self.assertEqual(list(warnings.filters), before)

    @patch("requests.Session.get")
    def test_verify_false_restores_the_warning_filter(self, session_mock: MagicMock):
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", ro_password="ro-secret", verify=False)
        before = list(warnings.filters)
        api.get_devices()
        # Suppression is scoped to the request; constructing a client with
        # verify=False must not silence urllib3 for the whole process
        self.assertEqual(list(warnings.filters), before)

    @patch("requests.Session.get")
    def test_default_timeout_is_thirty_seconds(self, session_mock: MagicMock):
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        api.get_devices()
        self.assertEqual(session_mock.call_args.kwargs["timeout"], 30)

    @patch("requests.Session.get")
    def test_timeout_is_configurable_at_construction(self, session_mock: MagicMock):
        session_mock.return_value.text = ""

        api = AKIPS(
            "127.0.0.1", ro_password="ro-secret", rw_password="rw-secret", timeout=5
        )
        # applies to every section, not just api-db
        api.get_devices()
        self.assertEqual(session_mock.call_args.kwargs["timeout"], 5)
        api.get_msg()
        self.assertEqual(session_mock.call_args.kwargs["timeout"], 5)
        api.get_device_by_ip(ipaddr="10.0.0.1")
        self.assertEqual(session_mock.call_args.kwargs["timeout"], 5)
        api.get_group_availability()
        self.assertEqual(session_mock.call_args.kwargs["timeout"], 5)

    @patch("requests.Session.get")
    def test_timeout_can_be_changed_on_an_existing_client(
        self, session_mock: MagicMock
    ):
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        api.get_devices()
        self.assertEqual(session_mock.call_args.kwargs["timeout"], 30)
        api.timeout = 120
        api.get_devices()
        self.assertEqual(session_mock.call_args.kwargs["timeout"], 120)

    @patch("requests.Session.get")
    def test_request_failures_do_not_leak_the_password(self, session_mock: MagicMock):
        # AKiPS authenticates by query string and requests reports the URL it
        # was fetching, so an unscrubbed exception carries the password into
        # the log and into any traceback the caller renders
        secret = "SuperSecret123"
        message = (
            "HTTPSConnectionPool(host='akips.example.com', port=443): "
            "Max retries exceeded with url: "
            f"/api-db?cmds=mget&username=api-ro&password={secret}"
        )
        session_mock.side_effect = requests.exceptions.ConnectionError(message)

        api = AKIPS("akips.example.com", ro_password=secret)
        with self.assertLogs("akips", level="ERROR") as logged:
            with self.assertRaises(requests.exceptions.ConnectionError) as caught:
                api.get_devices()

        self.assertNotIn(secret, "\n".join(logged.output))
        self.assertNotIn(secret, str(caught.exception))
        self.assertIn("password=****", str(caught.exception))
        # the exception type survives scrubbing, so existing handlers still work
        self.assertIsInstance(caught.exception, requests.exceptions.ConnectionError)

    @patch("requests.Session.get")
    def test_a_url_encoded_password_is_scrubbed_too(self, session_mock: MagicMock):
        # requests percent encodes the query, so the literal password does not
        # appear; matching on the parameter catches it whatever it looks like
        secret = "p@ss word/99"
        session_mock.side_effect = requests.exceptions.ConnectionError(
            "Max retries exceeded with url: /api-db?password=p%40ss+word%2F99&cmds=x"
        )

        api = AKIPS("akips.example.com", ro_password=secret)
        with self.assertLogs("akips", level="ERROR") as logged:
            with self.assertRaises(requests.exceptions.ConnectionError):
                api.get_devices()
        self.assertNotIn("p%40ss", "\n".join(logged.output))
        self.assertIn("password=****", "\n".join(logged.output))

    @patch("requests.Session.get")
    def test_an_error_with_no_credentials_is_left_intact(self, session_mock: MagicMock):
        # Nothing to scrub means the exception keeps its original structure
        session_mock.side_effect = requests.exceptions.Timeout("timed out")

        api = AKIPS("akips.example.com", ro_password="secret")
        with self.assertLogs("akips", level="ERROR"):
            with self.assertRaises(requests.exceptions.Timeout) as caught:
                api.get_devices()
        self.assertEqual(str(caught.exception), "timed out")
