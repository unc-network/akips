"""
Tests for the api-msg section: syslog and trap retrieval.
"""

import unittest
from unittest.mock import MagicMock, patch

from akips import AKIPS


class ApiMsgTest(unittest.TestCase):
    @patch("requests.Session.get")
    def test_get_msg(self, session_mock: MagicMock):
        r_text = """1436232275 syslog 4 198.51.100.26
notice local7 149:Jul 7 11:24:34.476: LINEPROTO-5-UPDOWN: Line protocol on Interface Serial1/6, changed...

1436232275 syslog 4 198.51.100.26
notice local7 150:Jul 7 11:24:34.572: OSPF-5-ADJCHG: Process 1, Nbr 198.51.100.45 onSerial1/6 from LOADING...

1436232275 trap 4 198.51.100.26
SNMPv2-MIB sysUpTime 0 TimeTicks 54003
SNMPv2-MIB snmpTrapOID 0 ObjectIdentifier
OSPF-TRAP-MIB.ospf Nbr StateChange
OSPF-MIB ospfRouterId 198.51.100.20 IPAddress 198.51.100.40
OSPF-MIB ospfNbrIpAddr 198.51.100.20 IPAddress 198.51.100.166
OSPF-MIB ospfNbrAddressLessIndex 198.51.100.20 Integer 0
OSPF-MIB ospfNbrRtrId 198.51.100.20 IPAddress 198.51.100.45
OSPF-MIB ospfNbrState 198.51.100.20 ENUM 8,full

1436232276 trap 4 198.51.100.26
SNMPv2-MIB sysUpTime 0 TimeTicks 54004
SNMPv2-MIB snmpTrapOID 0 ObjectIdentifier
OSPF-TRAP-MIB. ospf OriginateLsa
OSPF-MIB ospfRouterId 198.51.100.20 IPAddress 198.51.100.40
OSPF-MIB ospfLsdbAreaId 198.51.100.20 IPAddress 0.0.0.0
OSPF-MIB ospfLsdbType 198.51.100.20 ENUM 1,routerLink
"""  # noqa
        session_mock.return_value.ok = True
        session_mock.return_value.status_code = 200
        session_mock.return_value.text = r_text

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        messages = api.get_msg(period="today", addr="203.0.113.146")
        self.assertIsNotNone(messages)
        self.assertEqual(messages[2]["time"], "1436232275")
        self.assertEqual(messages[2]["type"], "trap")
        self.assertRegex(messages[2]["message"], r"^SNMPv2-MIB sysUpTime")

    @patch("requests.Session.get")
    def test_get_msg_builds_optional_filters(self, session_mock: MagicMock):
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        api.get_msg(
            period="last4h",
            addr="198.51.100.26",
            msg_type="syslog",
            device="cisco-sw1",
            regex="LINEPROTO",
            limit=25,
        )
        args, kwargs = session_mock.call_args
        self.assertTrue(args[0].endswith("/api-msg"))
        params = kwargs["params"]
        self.assertEqual(params["time"], "last4h")
        self.assertEqual(params["addr"], "198.51.100.26")
        self.assertEqual(params["type"], "syslog")
        self.assertEqual(params["device"], "cisco-sw1")
        self.assertEqual(params["regex"], "LINEPROTO")
        self.assertEqual(params["limit"], "25")

    @patch("requests.Session.get")
    def test_get_msg_refuses_an_unknown_type(self, session_mock: MagicMock):
        # This used to be dropped, so the request went out with no type at all
        # and came back with both syslog and traps while the caller believed it
        # had filtered to one.  Too much data reads as correct, so nothing ever
        # revealed the typo.
        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        for wrong in ("netflow", "traps", "Syslog", ""):
            with self.assertRaises(ValueError) as caught:
                api.get_msg(msg_type=wrong)
            self.assertIn("syslog, trap", str(caught.exception))
        self.assertFalse(session_mock.called)

    @patch("requests.Session.get")
    def test_get_msg_without_a_type_asks_for_both(self, session_mock: MagicMock):
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        api.get_msg()
        self.assertNotIn("type", session_mock.call_args.kwargs["params"])

    @patch("requests.Session.get")
    def test_get_msg_joins_multi_line_messages(self, session_mock: MagicMock):
        r_text = """1436232275 trap 4 198.51.100.26
SNMPv2-MIB sysUpTime 0 TimeTicks 54003
OSPF-MIB ospfNbrState 198.51.100.20 ENUM 8,full
"""  # noqa
        session_mock.return_value.text = r_text

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        messages = api.get_msg()
        self.assertEqual(len(messages), 1)
        self.assertEqual(
            messages[0]["message"],
            "SNMPv2-MIB sysUpTime 0 TimeTicks 54003\n"
            "OSPF-MIB ospfNbrState 198.51.100.20 ENUM 8,full",
        )
        self.assertEqual(messages[0]["ip_ver"], "4")
        self.assertEqual(messages[0]["ip_addr"], "198.51.100.26")

    @patch("requests.Session.get")
    def test_get_msg_returns_none_for_empty_response(self, session_mock: MagicMock):
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        self.assertIsNone(api.get_msg())

    @patch("requests.Session.get")
    def test_get_msg_skips_a_record_with_no_header(self, session_mock: MagicMock):
        # A reply starting mid record, so the first block has no header line.
        # It is skipped rather than failing the call or being spliced onto the
        # next record.
        r_text = """continuation of something we never saw the header for

1436232275 syslog 4 198.51.100.26
notice local7 149: LINEPROTO-5-UPDOWN
"""  # noqa
        session_mock.return_value.text = r_text

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        with self.assertLogs("akips", level="WARNING") as logged:
            messages = api.get_msg()
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0]["ip_addr"], "198.51.100.26")
        self.assertEqual(
            messages[0]["message"], "notice local7 149: LINEPROTO-5-UPDOWN"
        )
        # the skipped record is reported rather than silently lost
        self.assertIn("Could not parse 1 of 2", logged.output[0])

    @patch("requests.Session.get")
    def test_a_body_line_shaped_like_a_header_stays_in_the_message(
        self, session_mock: MagicMock
    ):
        # This trap body contains a line matching the header pattern.  Records
        # are split on blank lines, so it stays part of the message instead of
        # starting a second record with an empty body.
        r_text = """1436232275 trap 4 198.51.100.26
OSPF-MIB ospfNbrState 4 full
OSPF-MIB ospfRouterId 198.51.100.20 IPAddress 198.51.100.40
"""  # noqa
        session_mock.return_value.text = r_text

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        messages = api.get_msg()
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0]["type"], "trap")
        self.assertEqual(
            messages[0]["message"],
            "OSPF-MIB ospfNbrState 4 full\n"
            "OSPF-MIB ospfRouterId 198.51.100.20 IPAddress 198.51.100.40",
        )

    @patch("requests.Session.get")
    def test_ip_version_accepts_only_four_or_six(self, session_mock: MagicMock):
        # The character class used to be [4|6], which also matched a literal
        # pipe, so a body line with one in that position looked like a header
        r_text = """1436232275 syslog | 198.51.100.26
"""  # noqa
        session_mock.return_value.text = r_text

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        with self.assertLogs("akips", level="WARNING"):
            # a reply that parses to nothing is None, the same answer an empty
            # reply gives, rather than an empty list
            self.assertIsNone(api.get_msg())

    @patch("requests.Session.get")
    def test_blank_padding_between_records_is_ignored(self, session_mock: MagicMock):
        # Extra blank lines around records produce empty blocks, which are
        # not malformed records and must not be counted as unparsed
        r_text = """

1436232275 syslog 4 198.51.100.26
first message


1436232276 syslog 4 198.51.100.27
second message

"""  # noqa
        session_mock.return_value.text = r_text

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        messages = api.get_msg()
        self.assertEqual(len(messages), 2)
        self.assertEqual(messages[0]["message"], "first message")
        self.assertEqual(messages[1]["ip_addr"], "198.51.100.27")


class NamedMessageTypeTest(unittest.TestCase):
    """
    get_syslog and get_traps exist so the type does not have to be spelled
    correctly to take effect.  A caller cannot mistype an enum it never types.
    """

    @patch("requests.Session.get")
    def test_get_syslog_asks_for_syslog(self, session_mock: MagicMock):
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        api.get_syslog()
        params = session_mock.call_args.kwargs["params"]
        self.assertEqual(params["type"], "syslog")
        self.assertEqual(params["time"], "last1h")

    @patch("requests.Session.get")
    def test_get_traps_asks_for_traps(self, session_mock: MagicMock):
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        api.get_traps()
        self.assertEqual(session_mock.call_args.kwargs["params"]["type"], "trap")

    @patch("requests.Session.get")
    def test_every_filter_reaches_the_wrapped_call(self, session_mock: MagicMock):
        # A wrapper that dropped filters would be a downgrade from get_msg,
        # so both forward all of them.
        session_mock.return_value.text = ""
        api = AKIPS("127.0.0.1", ro_password="ro-secret")

        for method, expected in ((api.get_syslog, "syslog"), (api.get_traps, "trap")):
            method(
                period="last1d",
                addr="192.0.2.1",
                device="switch-1",
                regex="link down",
                limit=25,
            )
            params = session_mock.call_args.kwargs["params"]
            self.assertEqual(params["type"], expected)
            self.assertEqual(params["time"], "last1d")
            self.assertEqual(params["addr"], "192.0.2.1")
            self.assertEqual(params["device"], "switch-1")
            self.assertEqual(params["regex"], "link down")
            self.assertEqual(params["limit"], "25")

    @patch("requests.Session.get")
    def test_the_wrappers_parse_the_same_way(self, session_mock: MagicMock):
        session_mock.return_value.text = "1436232275 syslog 4 192.0.2.26\nlink down\n"

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        rows = api.get_syslog()
        self.assertEqual(rows[0]["type"], "syslog")
        self.assertEqual(rows[0]["ip_addr"], "192.0.2.26")
        self.assertEqual(rows[0]["message"], "link down")

    @patch("requests.Session.get")
    def test_the_wrappers_return_none_for_an_empty_reply(self, session_mock: MagicMock):
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        self.assertIsNone(api.get_syslog())
        self.assertIsNone(api.get_traps())
