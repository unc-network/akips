"""
Tests for the api-msg section: syslog and trap retrieval.
"""

import unittest
from unittest.mock import MagicMock, patch

from akips import AKIPS


class ApiMsgTest(unittest.TestCase):
    @patch("requests.Session.get")
    def test_get_msg(self, session_mock: MagicMock):
        r_text = """1436232275 syslog 4 10.4.2.26
notice local7 149:Jul 7 11:24:34.476: LINEPROTO-5-UPDOWN: Line protocol on Interface Serial1/6, changed...

1436232275 syslog 4 10.4.2.26
notice local7 150:Jul 7 11:24:34.572: OSPF-5-ADJCHG: Process 1, Nbr 10.4.45.1 onSerial1/6 from LOADING...

1436232275 trap 4 10.4.2.26
SNMPv2-MIB sysUpTime 0 TimeTicks 54003
SNMPv2-MIB snmpTrapOID 0 ObjectIdentifier
OSPF-TRAP-MIB.ospf Nbr StateChange
OSPF-MIB ospfRouterId 10.4.2.20 IPAddress 10.4.40.1
OSPF-MIB ospfNbrIpAddr 10.4.2.20 IPAddress 10.4.2.166
OSPF-MIB ospfNbrAddressLessIndex 10.4.2.20 Integer 0
OSPF-MIB ospfNbrRtrId 10.4.2.20 IPAddress 10.4.45.1
OSPF-MIB ospfNbrState 10.4.2.20 ENUM 8,full

1436232276 trap 4 10.4.2.26
SNMPv2-MIB sysUpTime 0 TimeTicks 54004
SNMPv2-MIB snmpTrapOID 0 ObjectIdentifier
OSPF-TRAP-MIB. ospf OriginateLsa
OSPF-MIB ospfRouterId 10.4.2.20 IPAddress 10.4.40.1
OSPF-MIB ospfLsdbAreaId 10.4.2.20 IPAddress 0.0.0.0
OSPF-MIB ospfLsdbType 10.4.2.20 ENUM 1,routerLink
"""  # noqa
        session_mock.return_value.ok = True
        session_mock.return_value.status_code = 200
        session_mock.return_value.text = r_text

        api = AKIPS("127.0.0.1")
        messages = api.get_msg(time="today", addr="10.10.10.146")
        self.assertIsNotNone(messages)
        self.assertEqual(messages[2]["time"], "1436232275")
        self.assertEqual(messages[2]["type"], "trap")
        self.assertRegex(messages[2]["message"], r"^SNMPv2-MIB sysUpTime")

    @patch("requests.Session.get")
    def test_get_msg_builds_optional_filters(self, session_mock: MagicMock):
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1")
        api.get_msg(
            time="last4h",
            addr="10.4.2.26",
            type="syslog",
            device="cisco-sw1",
            regex="LINEPROTO",
            limit=25,
        )
        args, kwargs = session_mock.call_args
        self.assertTrue(args[0].endswith("/api-msg"))
        params = kwargs["params"]
        self.assertEqual(params["time"], "last4h")
        self.assertEqual(params["addr"], "10.4.2.26")
        self.assertEqual(params["type"], "syslog")
        self.assertEqual(params["device"], "cisco-sw1")
        self.assertEqual(params["regex"], "LINEPROTO")
        self.assertEqual(params["limit"], "25")

    @patch("requests.Session.get")
    def test_get_msg_ignores_unknown_type(self, session_mock: MagicMock):
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1")
        api.get_msg(type="netflow")
        self.assertNotIn("type", session_mock.call_args.kwargs["params"])

    @patch("requests.Session.get")
    def test_get_msg_joins_multi_line_messages(self, session_mock: MagicMock):
        r_text = """1436232275 trap 4 10.4.2.26
SNMPv2-MIB sysUpTime 0 TimeTicks 54003
OSPF-MIB ospfNbrState 10.4.2.20 ENUM 8,full
"""  # noqa
        session_mock.return_value.text = r_text

        api = AKIPS("127.0.0.1")
        messages = api.get_msg()
        self.assertEqual(len(messages), 1)
        self.assertEqual(
            messages[0]["message"],
            "SNMPv2-MIB sysUpTime 0 TimeTicks 54003\n"
            "OSPF-MIB ospfNbrState 10.4.2.20 ENUM 8,full",
        )
        self.assertEqual(messages[0]["ip_ver"], "4")
        self.assertEqual(messages[0]["ip_addr"], "10.4.2.26")

    @patch("requests.Session.get")
    def test_get_msg_returns_none_for_empty_response(self, session_mock: MagicMock):
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1")
        self.assertIsNone(api.get_msg())
