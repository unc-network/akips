"""
Tests for call(), the general purpose request, and for the response parsers
it shares with the specific methods.
"""

import logging
import unittest
from unittest.mock import MagicMock, patch

from akips import AKIPS


class CallTest(unittest.TestCase):
    @patch("requests.Session.get")
    def test_raw_is_the_default(self, session_mock: MagicMock):
        r_text = "TH840-A sys ip4addr = 192.168.20.15\n"
        session_mock.return_value.text = r_text

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        self.assertEqual(api.call("mget * TH840-A sys ip4addr"), r_text)
        args, kwargs = session_mock.call_args
        self.assertTrue(args[0].endswith("/api-db"))
        self.assertEqual(kwargs["params"]["cmds"], "mget * TH840-A sys ip4addr")

    @patch("requests.Session.get")
    def test_lines_output(self, session_mock: MagicMock):
        session_mock.return_value.text = "first line\n\nsecond line\n\n"

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        self.assertEqual(
            api.call("mget * * * *", output="lines"), ["first line", "second line"]
        )

    @patch("requests.Session.get")
    def test_key_value_output(self, session_mock: MagicMock):
        session_mock.return_value.text = (
            "10.10.10.146 = admin,Cisco,maintenance_mode\n"
            "10.10.20.31 = Security,admin,PaloAlto\n"
        )

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        parsed = api.call("mgroup * *", output="key_value")
        self.assertEqual(parsed["10.10.10.146"], "admin,Cisco,maintenance_mode")
        self.assertEqual(parsed["10.10.20.31"], "Security,admin,PaloAlto")

    @patch("requests.Session.get")
    def test_attributes_output(self, session_mock: MagicMock):
        session_mock.return_value.text = (
            "TH840-A sys SNMPv2-MIB.sysName = TH840-A\n"
            "TH840-A Ethernet1 IF-MIB.ifDescr = Ethernet 1\n"
            "TH840-A Ethernet1 IF-MIB.ifAlias =\n"
        )

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        parsed = api.call("mget * TH840-A * *", output="attributes")
        self.assertEqual(parsed["TH840-A"]["sys"]["SNMPv2-MIB.sysName"], "TH840-A")
        self.assertEqual(parsed["TH840-A"]["Ethernet1"]["IF-MIB.ifDescr"], "Ethernet 1")
        # a value-less attribute is None here, as everywhere else
        self.assertIsNone(parsed["TH840-A"]["Ethernet1"]["IF-MIB.ifAlias"])

    @patch("requests.Session.get")
    def test_csv_output_without_a_header(self, session_mock: MagicMock):
        session_mock.return_value.text = "30,31,30\n29,28,27\n"

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        self.assertEqual(
            api.call("aggregate ...", output="csv"),
            [["30", "31", "30"], ["29", "28", "27"]],
        )

    @patch("requests.Session.get")
    def test_csv_dict_output_uses_the_header_row(self, session_mock: MagicMock):
        session_mock.return_value.text = "parent,child,value\nTH840-A,sys,4\n"

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        rows = api.call("cseries ...", output="csv_dict")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["parent"], "TH840-A")
        self.assertEqual(rows[0]["value"], "4")

    @patch("requests.Session.get")
    def test_reaches_other_sections_with_their_own_parameters(
        self, session_mock: MagicMock
    ):
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        api.call(section="api-msg", params={"time": "last1h", "type": "syslog"})
        args, kwargs = session_mock.call_args
        self.assertTrue(args[0].endswith("/api-msg"))
        self.assertEqual(kwargs["params"]["time"], "last1h")
        self.assertEqual(kwargs["params"]["type"], "syslog")
        # no command string is invented for a section that takes none
        self.assertNotIn("cmds", kwargs["params"])

    @patch("requests.Session.get")
    def test_cmd_and_params_combine(self, session_mock: MagicMock):
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        api.call("mget * * * *", params={"profile": "core"})
        params = session_mock.call_args.kwargs["params"]
        self.assertEqual(params["cmds"], "mget * * * *")
        self.assertEqual(params["profile"], "core")

    @patch("requests.Session.get")
    def test_rejects_an_unknown_output_before_requesting(self, session_mock: MagicMock):
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        with self.assertRaises(ValueError):
            api.call("mget * * * *", output="json")
        self.assertFalse(session_mock.called)

    @patch("requests.Session.get")
    def test_requires_a_cmd_or_params(self, session_mock: MagicMock):
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        with self.assertRaises(ValueError):
            api.call()
        self.assertFalse(session_mock.called)

    @patch("requests.Session.get")
    def test_returns_none_for_an_empty_reply(self, session_mock: MagicMock):
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        for output in AKIPS.OUTPUT_FORMATS:
            self.assertIsNone(api.call("mget * * * *", output=output))

    @patch("requests.Session.get")
    def test_an_unknown_section_warns_but_still_runs(self, session_mock: MagicMock):
        # A typo lands here, and so does a section AKiPS added after this
        # release.  Refusing would mean the second case has to wait for a
        # release, which is what call() exists to avoid.
        session_mock.return_value.text = "some output"

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        with self.assertLogs("akips", level="WARNING") as logged:
            result = api.call(section="api-mgs", params={"time": "last1h"})
        self.assertEqual(result, "some output")
        self.assertIn("api-mgs", logged.output[0])
        # the message lists what is known, so a typo is obvious
        self.assertIn("api-msg", logged.output[0])

    @patch("requests.Session.get")
    def test_an_unknown_section_is_only_warned_about_once(
        self, session_mock: MagicMock
    ):
        # A caller legitimately using a newer section should not have its log
        # filled by a poll loop
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        with self.assertLogs("akips", level="WARNING") as logged:
            for _ in range(5):
                api.call(section="api-brand-new", params={"a": "b"})
        self.assertEqual(len(logged.output), 1)

    @patch("requests.Session.get")
    def test_known_sections_do_not_warn(self, session_mock: MagicMock):
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", ro_password="ro-secret", rw_password="rw-secret")
        logger = logging.getLogger("akips")
        with patch.object(logger, "warning") as warn:
            for section in AKIPS.SECTION_USERS:
                api.call(section=section, params={"a": "b"})
            api.get_devices()
            api.get_msg()
        warn.assert_not_called()


class ParserAgreementTest(unittest.TestCase):
    """
    The point of sharing the parsers is that an ad-hoc query and its dedicated
    method read the same reply the same way.  These pin that down.
    """

    ATTRIBUTES = (
        "TH840-A sys SNMPv2-MIB.sysName = TH840-A\n"
        "TH840-A sys SNMPv2-MIB.sysLocation =\n"
        "TH840-B sys SNMPv2-MIB.sysName = TH840-B\n"
    )

    @patch("requests.Session.get")
    def test_get_attributes_matches_the_attributes_output(
        self, session_mock: MagicMock
    ):
        session_mock.return_value.text = self.ATTRIBUTES

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        self.assertEqual(
            api.get_attributes(), api.call("mget * * * *", output="attributes")
        )

    @patch("requests.Session.get")
    def test_get_group_membership_shares_the_key_value_parser(
        self, session_mock: MagicMock
    ):
        session_mock.return_value.text = "10.10.10.146 = admin,Cisco\n"

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        # get_group_membership splits the value; the raw shape is the same
        self.assertEqual(
            api.get_group_membership(), {"10.10.10.146": ["admin", "Cisco"]}
        )
        self.assertEqual(
            api.call("mgroup * *", output="key_value"),
            {"10.10.10.146": "admin,Cisco"},
        )

    @patch("requests.Session.get")
    def test_get_devices_is_the_attributes_shape_flattened(
        self, session_mock: MagicMock
    ):
        session_mock.return_value.text = self.ATTRIBUTES

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        devices = api.get_devices()
        parsed = api.call("mget * * * *", output="attributes")
        self.assertEqual(set(devices), set(parsed))
        self.assertEqual(
            devices["TH840-A"]["SNMPv2-MIB.sysName"],
            parsed["TH840-A"]["sys"]["SNMPv2-MIB.sysName"],
        )
        self.assertIsNone(devices["TH840-A"]["SNMPv2-MIB.sysLocation"])
        self.assertIsNone(parsed["TH840-A"]["sys"]["SNMPv2-MIB.sysLocation"])

    @patch("requests.Session.get")
    def test_get_device_is_the_parser_shape_for_one_device(
        self, session_mock: MagicMock
    ):
        session_mock.return_value.text = (
            "TH840-A sys ip4addr = 192.168.20.15\n"
            "TH840-A Ethernet1 IF-MIB.ifDescr = Ethernet 1\n"
        )

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        # get_device and get_attributes send the same command and now return
        # the same shape, keyed by device name
        self.assertEqual(
            api.get_device("TH840-A"), api.get_attributes(device="TH840-A")
        )
        self.assertEqual(
            api.get_device("TH840-A"),
            api.call("mget * TH840-A * *", output="attributes"),
        )
