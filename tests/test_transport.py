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

        api = AKIPS("127.0.0.1")

        self.assertFalse(session_mock.called)
        self.assertRaises(AkipsError, api.get_devices)
        self.assertTrue(session_mock.called)

    @patch("requests.Session.get")
    def test_http_error_propagates(self, session_mock: MagicMock):
        session_mock.return_value.raise_for_status.side_effect = (
            requests.exceptions.HTTPError("500 Server Error")
        )

        api = AKIPS("127.0.0.1")
        with self.assertRaises(requests.exceptions.HTTPError):
            api.get_devices()

    @patch("requests.Session.get")
    def test_connection_error_propagates(self, session_mock: MagicMock):
        session_mock.side_effect = requests.exceptions.ConnectionError("refused")

        api = AKIPS("127.0.0.1")
        with self.assertRaises(requests.exceptions.ConnectionError):
            api.get_devices()

    @patch("requests.Session.get")
    def test_timeout_propagates(self, session_mock: MagicMock):
        session_mock.side_effect = requests.exceptions.Timeout("timed out")

        api = AKIPS("127.0.0.1")
        with self.assertRaises(requests.exceptions.Timeout):
            api.get_devices()

    @patch("requests.Session.get")
    def test_request_exception_propagates(self, session_mock: MagicMock):
        session_mock.side_effect = requests.exceptions.RequestException("broken")

        api = AKIPS("127.0.0.1")
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

        api = AKIPS("127.0.0.1", verify=False)
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
        api = AKIPS("127.0.0.1")
        entry = api._parse_enum("8,full,1581605551,1706545348,core-uplink")
        self.assertEqual(entry["number"], "8")
        self.assertEqual(entry["value"], "full")
        self.assertEqual(entry["description"], "core-uplink")
        self.assertEqual(entry["created"].year, 2020)
        self.assertEqual(entry["modified"].year, 2024)

    def test_parse_enum_with_empty_description(self):
        api = AKIPS("127.0.0.1")
        entry = api._parse_enum("2,up,1581605551,1706545348,")
        self.assertEqual(entry["value"], "up")
        self.assertEqual(entry["description"], "")

    def test_parse_enum_rejects_other_values(self):
        api = AKIPS("127.0.0.1")
        with self.assertRaises(AkipsError):
            api._parse_enum("not an enum value")

    def test_parse_enum_with_spaces_in_description(self):
        # Child descriptions routinely contain spaces, e.g. "Ethernet 1", so
        # the trailing field takes the rest of the line
        api = AKIPS("127.0.0.1")
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

        api = AKIPS("127.0.0.1")
        # params is documented as optional, so omitting it must not raise
        self.assertEqual(api._get(section="api-db"), "")
        self.assertIn("username", session_mock.call_args.kwargs["params"])

    @patch("requests.Session.get")
    def test_verify_true_leaves_the_warning_filter_alone(self, session_mock: MagicMock):
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1")
        before = list(warnings.filters)
        api.get_devices()
        self.assertEqual(list(warnings.filters), before)

    @patch("requests.Session.get")
    def test_verify_false_restores_the_warning_filter(self, session_mock: MagicMock):
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", verify=False)
        before = list(warnings.filters)
        api.get_devices()
        # Suppression is scoped to the request; constructing a client with
        # verify=False must not silence urllib3 for the whole process
        self.assertEqual(list(warnings.filters), before)

    @patch("requests.Session.get")
    def test_default_timeout_is_thirty_seconds(self, session_mock: MagicMock):
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1")
        api.get_devices()
        self.assertEqual(session_mock.call_args.kwargs["timeout"], 30)

    @patch("requests.Session.get")
    def test_timeout_is_configurable_at_construction(self, session_mock: MagicMock):
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", timeout=5)
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

        api = AKIPS("127.0.0.1")
        api.get_devices()
        self.assertEqual(session_mock.call_args.kwargs["timeout"], 30)
        api.timeout = 120
        api.get_devices()
        self.assertEqual(session_mock.call_args.kwargs["timeout"], 120)
