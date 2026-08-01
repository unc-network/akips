"""
Tests for the api-script section, which is backed by the site scripts
in akips_setup/site_scripting.pl and requires the api-rw user.
"""

import unittest
from unittest.mock import MagicMock, patch

from akips import AKIPS, AkipsError


class ApiScriptTest(unittest.TestCase):
    @patch("requests.Session.get")
    def test_get_device_by_ip(self, session_mock: MagicMock):
        r_text = """IP Address 10.194.200.65 is configured on cisco-sw1
"""  # noqa
        session_mock.return_value.ok = True
        session_mock.return_value.status_code = 200
        session_mock.return_value.text = r_text

        api = AKIPS("127.0.0.1", rw_password="rw-secret")
        device_name = api.get_device_by_ip(ipaddr="10.194.200.65")
        self.assertEqual(device_name, "cisco-sw1")

    @patch("requests.Session.get")
    def test_set_group_membership(self, session_mock: MagicMock):
        r_text = """"""  # noqa
        session_mock.return_value.ok = True
        session_mock.return_value.status_code = 200
        session_mock.return_value.text = r_text

        api = AKIPS("127.0.0.1", rw_password="rw-secret")
        output = api.set_group_membership("10.10.10.146", "test_group", "assign")
        self.assertIsNone(output)

    @patch("requests.Session.get")
    def test_get_device_by_ip_returns_none_when_not_found(
        self, session_mock: MagicMock
    ):
        session_mock.return_value.text = "No device found\n"

        api = AKIPS("127.0.0.1", rw_password="rw-secret")
        self.assertIsNone(api.get_device_by_ip(ipaddr="10.194.200.65"))

    @patch("requests.Session.get")
    def test_get_device_by_ip_sends_site_script_params(self, session_mock: MagicMock):
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", rw_password="rw-secret")
        api.get_device_by_ip(ipaddr="10.194.200.65")
        args, kwargs = session_mock.call_args
        self.assertTrue(args[0].endswith("/api-script"))
        self.assertEqual(kwargs["params"]["function"], "web_find_device_by_ip")
        self.assertEqual(kwargs["params"]["ipaddr"], "10.194.200.65")

    @patch("requests.Session.get")
    def test_set_group_membership_sends_manual_grouping_params(
        self, session_mock: MagicMock
    ):
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", rw_password="rw-secret")
        api.set_group_membership("10.10.10.146", "test_group", "clear")
        params = session_mock.call_args.kwargs["params"]
        self.assertEqual(params["function"], "web_manual_grouping")
        self.assertEqual(params["type"], "device")
        self.assertEqual(params["group"], "test_group")
        self.assertEqual(params["mode"], "clear")
        self.assertEqual(params["device"], "10.10.10.146")

    @patch("requests.Session.get")
    def test_set_group_membership_raises_on_server_output(
        self, session_mock: MagicMock
    ):
        # The site script is silent on success, so any output is a failure
        session_mock.return_value.text = "group does not exist\n"

        api = AKIPS("127.0.0.1", rw_password="rw-secret")
        with self.assertRaises(AkipsError):
            api.set_group_membership("10.10.10.146", "test_group", "assign")

    def test_set_group_membership_validates_arguments(self):
        api = AKIPS("127.0.0.1", rw_password="rw-secret")
        with self.assertRaises(ValueError):
            api.set_group_membership("", "test_group", "assign")
        with self.assertRaises(ValueError):
            api.set_group_membership("10.10.10.146", "", "assign")
        with self.assertRaises(ValueError):
            api.set_group_membership("10.10.10.146", "test_group", "delete")
