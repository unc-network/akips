"""
Tests for the shared request handling every call passes through.
"""

import unittest
from unittest.mock import MagicMock, patch

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
