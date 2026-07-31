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
