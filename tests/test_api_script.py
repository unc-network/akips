"""
Tests for the api-script section, which is backed by the site scripts
in akips_setup/site_scripting.pl and requires the api-rw user.
"""

import unittest
from unittest.mock import MagicMock, patch

from akips import AKIPS


class ApiScriptTest(unittest.TestCase):
    @patch("requests.Session.get")
    def test_get_device_by_ip(self, session_mock: MagicMock):
        r_text = """IP Address 10.194.200.65 is configured on cisco-sw1
"""  # noqa
        session_mock.return_value.ok = True
        session_mock.return_value.status_code = 200
        session_mock.return_value.text = r_text

        api = AKIPS("127.0.0.1")
        device_name = api.get_device_by_ip(ipaddr="10.194.200.65")
        self.assertEqual(device_name, "cisco-sw1")

    @patch("requests.Session.get")
    def test_set_group_membership(self, session_mock: MagicMock):
        r_text = """"""  # noqa
        session_mock.return_value.ok = True
        session_mock.return_value.status_code = 200
        session_mock.return_value.text = r_text

        api = AKIPS("127.0.0.1")
        output = api.set_group_membership("10.10.10.146", "test_group", "assign")
        self.assertIsNone(output)
