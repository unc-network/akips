"""
Tests for the api-script section, which is backed by the site scripts
in akips_setup/site_scripting.pl and requires the api-rw user.
"""

import logging
import unittest
from unittest.mock import MagicMock, patch

from akips import AKIPS, AkipsError


class ApiScriptTest(unittest.TestCase):
    @patch("requests.Session.post")
    def test_get_device_by_ip(self, session_mock: MagicMock):
        r_text = """IP Address 192.0.2.65 is configured on cisco-sw1
"""  # noqa
        session_mock.return_value.ok = True
        session_mock.return_value.status_code = 200
        session_mock.return_value.text = r_text

        api = AKIPS("127.0.0.1", rw_password="rw-secret")
        device_name = api.get_device_by_ip(ipaddr="192.0.2.65")
        self.assertEqual(device_name, "cisco-sw1")

    @patch("requests.Session.post")
    def test_set_group_membership(self, session_mock: MagicMock):
        r_text = """"""  # noqa
        session_mock.return_value.ok = True
        session_mock.return_value.status_code = 200
        session_mock.return_value.text = r_text

        api = AKIPS("127.0.0.1", rw_password="rw-secret")
        output = api.set_group_membership("203.0.113.146", "test_group", "assign")
        self.assertIsNone(output)

    @patch("requests.Session.post")
    def test_get_device_by_ip_returns_none_when_not_found(
        self, session_mock: MagicMock
    ):
        # What akips_setup/site_scripting.pl actually prints when nothing
        # matches, rather than an invented sentence
        session_mock.return_value.text = (
            "IP Address 192.0.2.65 is not configured on any devices\n"
        )

        api = AKIPS("127.0.0.1", rw_password="rw-secret")
        logger = logging.getLogger("akips")
        with patch.object(logger, "warning") as warn:
            self.assertIsNone(api.get_device_by_ip(ipaddr="192.0.2.65"))
        # a real answer, so it must not look like something went wrong
        warn.assert_not_called()

    @patch("requests.Session.post")
    def test_get_device_by_ip_sends_site_script_params(self, session_mock: MagicMock):
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", rw_password="rw-secret")
        api.get_device_by_ip(ipaddr="192.0.2.65")
        args, kwargs = session_mock.call_args
        self.assertTrue(args[0].endswith("/api-script"))
        self.assertEqual(kwargs["params"]["function"], "web_find_device_by_ip")
        self.assertEqual(kwargs["params"]["ipaddr"], "192.0.2.65")

    @patch("requests.Session.post")
    def test_set_group_membership_sends_manual_grouping_params(
        self, session_mock: MagicMock
    ):
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", rw_password="rw-secret")
        api.set_group_membership("203.0.113.146", "test_group", "clear")
        params = session_mock.call_args.kwargs["params"]
        self.assertEqual(params["function"], "web_manual_grouping")
        self.assertEqual(params["type"], "device")
        self.assertEqual(params["group"], "test_group")
        self.assertEqual(params["mode"], "clear")
        self.assertEqual(params["device"], "203.0.113.146")

    @patch("requests.Session.post")
    def test_set_group_membership_raises_on_server_output(
        self, session_mock: MagicMock
    ):
        # The site script is silent on success, so any output is a failure
        session_mock.return_value.text = "group does not exist\n"

        api = AKIPS("127.0.0.1", rw_password="rw-secret")
        with self.assertRaises(AkipsError):
            api.set_group_membership("203.0.113.146", "test_group", "assign")

    def test_set_group_membership_validates_arguments(self):
        api = AKIPS("127.0.0.1", rw_password="rw-secret")
        with self.assertRaises(ValueError):
            api.set_group_membership("", "test_group", "assign")
        with self.assertRaises(ValueError):
            api.set_group_membership("203.0.113.146", "", "assign")
        with self.assertRaises(ValueError):
            api.set_group_membership("203.0.113.146", "test_group", "delete")


class SiteScriptMissingTest(unittest.TestCase):
    """
    These calls need akips_setup/site_scripting.pl installed on the server.
    An unknown function comes back ERROR prefixed and is raised by _get before
    anything here sees it; what is left is every other way the reply can fail
    to be what the script would have written.
    """

    @patch("requests.Session.post")
    def test_an_unexpected_reply_points_at_the_site_script(
        self, session_mock: MagicMock
    ):
        # An HTML error page from something in front of AKiPS, or the script's
        # own complaint about a missing argument, used to read as 'no device
        # has that address' and be believed.
        for reply in (
            "IP address is missing\n",
            "<html><body>404 Not Found</body></html>\n",
        ):
            with self.subTest(reply=reply[:24]):
                session_mock.return_value.text = reply
                api = AKIPS("127.0.0.1", rw_password="rw-secret")
                with self.assertLogs("akips", level="WARNING") as logged:
                    self.assertIsNone(api.get_device_by_ip(ipaddr="192.0.2.65"))
                self.assertIn("site script", logged.output[0])

    @patch("requests.Session.post")
    def test_an_unknown_function_is_raised_not_warned(self, session_mock: MagicMock):
        session_mock.return_value.text = (
            "ERROR: api-script unknown function web_find_device_by_ip\n"
        )
        api = AKIPS("127.0.0.1", rw_password="rw-secret")
        with self.assertRaises(AkipsError):
            api.get_device_by_ip(ipaddr="192.0.2.65")
