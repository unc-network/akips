"""
Tests for the api-db section: entities, groups, events and time series.
"""

import logging
import unittest
from unittest.mock import MagicMock, patch

from akips import AKIPS


class ApiDbTest(unittest.TestCase):
    @patch("requests.Session.post")
    def test_get_devices(self, session_mock: MagicMock):
        r_text = """203.0.113.29 sys ip4addr = 203.0.113.29
203.0.113.29 sys SNMPv2-MIB.sysDescr = VMware ESXi 6.5.0 build-8294253 VMware Inc. x86_64
203.0.113.29 sys SNMPv2-MIB.sysName = server.example.com
203.0.113.30 sys ip4addr = 203.0.113.30
"""  # noqa

        session_mock.return_value.ok = True
        session_mock.return_value.status_code = 200
        session_mock.return_value.text = r_text

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        devices = api.get_devices()
        self.assertEqual(devices["203.0.113.29"]["ip4addr"], "203.0.113.29")
        self.assertEqual(
            devices["203.0.113.29"]["SNMPv2-MIB.sysDescr"],
            "VMware ESXi 6.5.0 build-8294253 VMware Inc. x86_64",
        )
        self.assertEqual(
            devices["203.0.113.29"]["SNMPv2-MIB.sysName"], "server.example.com"
        )
        self.assertEqual(devices["203.0.113.30"]["ip4addr"], "203.0.113.30")

    @patch("requests.Session.post")
    def test_get_unreachable(self, session_mock: MagicMock):
        r_text = """203.0.113.54 ping4 PING.icmpState = 1,down,1484685257,1657029502,203.0.113.54
203.0.113.54 sys SNMP.snmpState = 1,down,1484685257,1657029499,
CrN-082-AP ping4 PING.icmpState = 1,down,1605595895,1656331597,203.0.113.63
CrN-082-AP ping4 PING.icmpState = 1,down,1641624705,1646101757,203.0.113.112
"""  # noqa
        session_mock.return_value.ok = True
        session_mock.return_value.status_code = 200
        session_mock.return_value.text = r_text

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        devices = api.get_unreachable()
        self.assertEqual(devices["203.0.113.54"]["snmp_state"], "down")
        self.assertEqual(devices["203.0.113.54"]["ping_state"], "down")
        # child is the matched string; it used to be a one element tuple,
        # the only field in the structure with a surprising type.  For a device
        # down on both checks the ping line wins, so it does not depend on
        # which line the server happened to send last.
        self.assertEqual(devices["203.0.113.54"]["child"], "ping4")
        self.assertEqual(devices["CrN-082-AP"]["child"], "ping4")
        self.assertEqual(devices["203.0.113.54"]["index"], "1")

    @patch("requests.Session.post")
    def test_get_unreachable_names_the_children_it_searches(
        self, session_mock: MagicMock
    ):
        # A wildcard here makes AKiPS walk every child of every device, which
        # is most of the cost of the query.  ping6 is in the list even where
        # nothing is monitored over IPv6, since missing a device that is down
        # is far worse than an alternative that matches nothing.
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        api.get_unreachable()
        self.assertEqual(
            session_mock.call_args.kwargs["params"]["cmds"],
            "mget * * /ping4|ping6|sys/ /PING.icmpState|SNMP.snmpState/ value /down/",
        )

    @patch("requests.Session.post")
    def test_get_unreachable_can_search_every_child(self, session_mock: MagicMock):
        # For a site whose children are named differently.  '*' is the
        # wildcard rather than a pattern, so it must reach AKiPS bare: wrapped
        # in slashes it would be a regex with nothing to repeat.
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        api.get_unreachable(children="*")
        self.assertEqual(
            session_mock.call_args.kwargs["params"]["cmds"],
            "mget * * * /PING.icmpState|SNMP.snmpState/ value /down/",
        )

    @patch("requests.Session.post")
    def test_get_unreachable_takes_a_custom_child_pattern(
        self, session_mock: MagicMock
    ):
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        api.get_unreachable(children="icmp|sys")
        self.assertEqual(
            session_mock.call_args.kwargs["params"]["cmds"],
            "mget * * /icmp|sys/ /PING.icmpState|SNMP.snmpState/ value /down/",
        )

    @patch("requests.Session.post")
    def test_get_attributes(self, session_mock: MagicMock):
        r_text = """TH840-F cpu A10-AX-MIB.axSysAverageControlCpuUsage = 1
TH840-F cpu A10-AX-MIB.axSysAverageCpuUsage = 1
TH840-F cpu A10-AX-MIB.axSysAverageDataCpuUsage = 1
TH840-F cpu.0.5 A10-AX-MIB.axSysCpuUsageValueAtPeriod = 1
TH840-F cpu.1 HOST-RESOURCES-MIB.hrDeviceDescr = Control CPU
TH840-F cpu.1 HOST-RESOURCES-MIB.hrProcessorLoad = 1
TH840-F cpu.1.5 A10-AX-MIB.axSysCpuUsageValueAtPeriod = 1
TH840-F cpu.2 HOST-RESOURCES-MIB.hrDeviceDescr = Data CPU1
TH840-F cpu.2 HOST-RESOURCES-MIB.hrProcessorLoad = 1
TH840-F cpu.2.5 A10-AX-MIB.axSysCpuUsageValueAtPeriod = 1
TH840-F Ethernet1 IF-MIB.ifAdminStatus = 1,up,1581605551,1581605551,
TH840-F Ethernet1 IF-MIB.ifAlias =
TH840-F Ethernet1 IF-MIB.ifDescr = Ethernet 1
TH840-F Ethernet1 IF-MIB.ifHCInBroadcastPkts = 1
TH840-F Ethernet1 IF-MIB.ifHCInMulticastPkts = 1
TH840-F Ethernet1 IF-MIB.ifPhysAddress = 001fa008d411
"""  # noqa
        session_mock.return_value.ok = True
        session_mock.return_value.status_code = 200
        session_mock.return_value.text = r_text

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        attr = api.get_attributes(device="TH840-F")
        self.assertEqual(
            attr["TH840-F"]["cpu"]["A10-AX-MIB.axSysAverageDataCpuUsage"], "1"
        )
        self.assertEqual(
            attr["TH840-F"]["cpu.2"]["HOST-RESOURCES-MIB.hrDeviceDescr"], "Data CPU1"
        )
        self.assertIsNone(attr["TH840-F"]["Ethernet1"]["IF-MIB.ifAlias"])

    @patch("requests.Session.post")
    def test_get_group_membership(self, session_mock: MagicMock):
        r_text = """203.0.113.146 = admin,Cisco,maintenance_mode,Not-Core,OpsCenter,poll_oid_10,user
203.0.113.31 = Security,admin,maintenance_mode,Not-Core,OpsCenter,PaloAlto,user
203.0.113.26 = admin,Brocade,maintenance_mode,Not-Core,OpsCenter,Ungrouped,user
"""  # noqa
        session_mock.return_value.ok = True
        session_mock.return_value.status_code = 200
        session_mock.return_value.text = r_text

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        list = api.get_group_membership(groups=["maintenance_mode"])
        self.assertEqual(list["203.0.113.146"][0], "admin")

    @patch("requests.Session.post")
    def test_get_series(self, session_mock: MagicMock):
        r_text = """parent,child,child description,attribute,2024-02-21 09:10,2024-02-21 09:11,2024-02-21 09:12,2024-02-21 09:13,2024-02-21 09:14,2024-02-21 09:15,2024-02-21 09:16,2024-02-21 09:17,2024-02-21 09:18,2024-02-21 09:19,2024-02-21 09:20,2024-02-21 09:21,2024-02-21 09:22,2024-02-21 09:23,2024-02-21 09:24,2024-02-21 09:25,2024-02-21 09:26,2024-02-21 09:27,2024-02-21 09:28,2024-02-21 09:29,2024-02-21 09:30,2024-02-21 09:31,2024-02-21 09:32,2024-02-21 09:33,2024-02-21 09:34,2024-02-21 09:35,2024-02-21 09:36,2024-02-21 09:37,2024-02-21 09:38,2024-02-21 09:39,2024-02-21 09:40,2024-02-21 09:41,2024-02-21 09:42,2024-02-21 09:43,2024-02-21 09:44,2024-02-21 09:45,2024-02-21 09:46,2024-02-21 09:47,2024-02-21 09:48,2024-02-21 09:49,2024-02-21 09:50,2024-02-21 09:51,2024-02-21 09:52,2024-02-21 09:53,2024-02-21 09:54,2024-02-21 09:55,2024-02-21 09:56,2024-02-21 09:57,2024-02-21 09:58,2024-02-21 09:59,2024-02-21 10:00,2024-02-21 10:01,2024-02-21 10:02,2024-02-21 10:03,2024-02-21 10:04,2024-02-21 10:05,2024-02-21 10:06,2024-02-21 10:07,2024-02-21 10:08,2024-02-21 10:09,2024-02-21 10:10
CrN-638-AP_110,radio.56.23.195.198.156.238.1,,WLSX-WLAN-MIB.wlanAPRadioNumAssociatedClients,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
CrN-638-AP_111B,radio.0.11.134.253.238.238.1,,WLSX-WLAN-MIB.wlanAPRadioNumAssociatedClients,2,2,2,2,2,2,2,1,3,4,3,2,2,2,1,1,1,2,3,3,3,3,3,3,1,2,1,1,1,1,1,1,0,0,0,0,0,0,0,0,0,0,0,0,1,1,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0
"""  # noqa
        session_mock.return_value.ok = True
        session_mock.return_value.status_code = 200
        session_mock.return_value.text = r_text

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        series = api.get_series(
            attribute="WLSX-WLAN-MIB.wlanAPRadioNumAssociatedClients"
        )
        self.assertEqual(series[0]["2024-02-21 09:10"], "0")
        self.assertEqual(series[1]["2024-02-21 09:10"], "2")

    @patch("requests.Session.post")
    def test_get_aggregate(self, session_mock: MagicMock):
        r_text = """30,31,30,27,27,28,28,28,30,29,29,28,27,29,30,29,28,28,27,28,26,25,25,25,25,26,24,24,24,21,23,24,23,24,22,23,25,29,30,31,34,34,34,34,36,33,31,31,32,32,33,29,29,30,29,28,27,31,31,31,30,28,28,29,28,26,26,25,26,26,25,25,24,23,23,22,20,13,12,12,11,11,13,12,11,11,11,9,9,8,8,10,10,10,9,9,7,7,8,10,10,8,9,11,12,12,8,8,8,8,9,7,7,7,6,6,7,7,7,8,7,7,8,8,6,6,6,6,6,7,7,7,6,7,6,6,6,6,6,6,6,6,7,7,7,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,8,7,7,6,6,6,6,6,6,6,6,7,7,7,7,6,7,7,7,7,6,6,7,6,7,6,6,7,6,6,6,6,7,7,7,7,6,6,6,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,6,6,6,6,6,6,6,6,7,7,7,6,7,7,7,7,6,6,6,6,6,6,6,6,7,7,7,7,7,7,7,12,13,12,13,14,14,15,14,14,14,19,21,22,22,23,23,25,24,23,23,23,23
"""  # noqa
        session_mock.return_value.ok = True
        session_mock.return_value.status_code = 200
        session_mock.return_value.text = r_text

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        series = api.get_aggregate(
            attribute="WLSX-WLAN-MIB.wlanAPRadioNumAssociatedClients"
        )
        self.assertEqual(series[1], "31")

    @patch("requests.Session.post")
    def test_get_device(self, session_mock: MagicMock):
        r_text = """TH840-A sys SNMPv2-MIB.sysName = TH840-A
TH840-A sys SNMPv2-MIB.sysLocation = Datacenter A
TH840-A Ethernet1 IF-MIB.ifDescr = Ethernet 1
TH840-A Ethernet1 IF-MIB.ifAlias =
"""  # noqa
        session_mock.return_value.text = r_text

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        device = api.get_device("TH840-A")
        # The one device's children, not a dictionary keyed by the name that
        # was just passed in.  get_attributes keys by device because it can
        # match several; this cannot.
        self.assertEqual(sorted(device), ["Ethernet1", "sys"])
        self.assertEqual(device["sys"]["SNMPv2-MIB.sysName"], "TH840-A")
        self.assertEqual(device["sys"]["SNMPv2-MIB.sysLocation"], "Datacenter A")
        self.assertEqual(device["Ethernet1"]["IF-MIB.ifDescr"], "Ethernet 1")
        # An attribute with nothing after the equals has no value, reported
        # as None consistently across get_device, get_attributes and
        # get_devices
        self.assertIsNone(device["Ethernet1"]["IF-MIB.ifAlias"])
        # every value is a dictionary of attributes; nothing else is mixed in
        for attributes in device.values():
            self.assertIsInstance(attributes, dict)

    @patch("requests.Session.post")
    def test_get_device_returns_none_for_empty_response(self, session_mock: MagicMock):
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        self.assertIsNone(api.get_device("TH840-A"))

    @patch("requests.Session.post")
    def test_get_device_with_unparsable_response(self, session_mock: MagicMock):
        session_mock.return_value.text = "no attribute lines here\n"

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        # A response that parses to nothing is not found, and is reported the
        # same way as an empty response rather than as a dict holding only the
        # name that was asked for
        self.assertIsNone(api.get_device("TH840-A"))

    @patch("requests.Session.post")
    def test_get_events(self, session_mock: MagicMock):
        r_text = """1706545348 TH840-A sys SNMP.snmpState Threshold Alert snmp state changed
1706545350 TH840-B ping4 PING.icmpState Uptime Warning device unreachable
"""  # noqa
        session_mock.return_value.text = r_text

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        events = api.get_events()
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0]["epoch"], "1706545348")
        self.assertEqual(events[0]["parent"], "TH840-A")
        self.assertEqual(events[0]["child"], "sys")
        self.assertEqual(events[0]["attribute"], "SNMP.snmpState")
        self.assertEqual(events[0]["type"], "Threshold")
        self.assertEqual(events[0]["flags"], "Alert")
        self.assertEqual(events[0]["details"], "snmp state changed")
        self.assertEqual(events[1]["parent"], "TH840-B")

    @patch("requests.Session.post")
    def test_get_events_builds_group_filter(self, session_mock: MagicMock):
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        api.get_events(event_type="critical", period="last4h", groups=["a10", "core"])
        cmds = session_mock.call_args.kwargs["params"]["cmds"]
        self.assertEqual(
            cmds, "mget event critical time last4h * * * any group a10 core"
        )

    @patch("requests.Session.post")
    def test_get_devices_builds_group_filter(self, session_mock: MagicMock):
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        api.get_devices(group_filter="not", groups=["a10"])
        cmds = session_mock.call_args.kwargs["params"]["cmds"]
        self.assertTrue(cmds.endswith(" not group a10"))

    @patch("requests.Session.post")
    def test_get_attributes_builds_value_and_group_filter(
        self, session_mock: MagicMock
    ):
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        api.get_attributes(
            device="TH840-A", child="sys", value="/down/", groups=["a10"]
        )
        cmds = session_mock.call_args.kwargs["params"]["cmds"]
        self.assertEqual(cmds, "mget * TH840-A sys * value /down/ any group a10")

    @patch("requests.Session.post")
    def test_get_series_honours_interval(self, session_mock: MagicMock):
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        api.get_series(time_interval=300, period="last8h")
        cmds = session_mock.call_args.kwargs["params"]["cmds"]
        self.assertTrue(cmds.startswith("cseries interval avg 300 time last8h "))

    @patch("requests.Session.post")
    def test_get_series_as_lists(self, session_mock: MagicMock):
        r_text = """parent,child,child description,attribute,2024-02-21 09:10
CrN-638-AP_110,radio.1,,WLSX-WLAN-MIB.wlanAPRadioNumAssociatedClients,4
"""  # noqa
        session_mock.return_value.text = r_text

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        rows = api.get_series(get_dict=False)
        # The header is kept, because its column headings are the timestamps
        # for the values beneath them.  Drop it and the readings have no time
        # axis at all.
        self.assertEqual(rows[0][0], "parent")
        self.assertEqual(rows[0][4], "2024-02-21 09:10")
        self.assertEqual(rows[1][4], "4")

    @patch("requests.Session.post")
    def test_get_aggregate_honours_operator(self, session_mock: MagicMock):
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        api.get_aggregate(operator="total", time_interval=600)
        cmds = session_mock.call_args.kwargs["params"]["cmds"]
        self.assertTrue(cmds.startswith("aggregate interval total 600 "))

    @patch("requests.Session.post")
    def test_empty_responses_return_none(self, session_mock: MagicMock):
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        self.assertIsNone(api.get_devices())
        self.assertIsNone(api.get_unreachable())
        self.assertIsNone(api.get_attributes())
        self.assertIsNone(api.get_group_membership())
        self.assertIsNone(api.get_events())
        self.assertIsNone(api.get_series())
        self.assertIsNone(api.get_aggregate())
        self.assertIsNone(api.call("mget * * * *"))

    @patch("requests.Session.post")
    def test_cmd_still_works_but_warns(self, session_mock: MagicMock):
        r_text = "TH840-A sys ip4addr = 203.0.113.15\n"
        session_mock.return_value.text = r_text

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        with self.assertWarns(DeprecationWarning):
            self.assertEqual(api.cmd("mget * TH840-A sys ip4addr"), r_text)
        self.assertEqual(
            session_mock.call_args.kwargs["params"]["cmds"],
            "mget * TH840-A sys ip4addr",
        )

    @patch("requests.Session.post")
    def test_cmd_rejects_unknown_output_format(self, session_mock: MagicMock):
        session_mock.return_value.text = "some output\n"

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        with self.assertWarns(DeprecationWarning), self.assertRaises(ValueError):
            api.cmd("mget * * * *", output="json")
        # cmd only ever supported raw; call() is where the other formats live
        self.assertFalse(session_mock.called)

    @patch("requests.Session.post")
    def test_empty_attribute_values_are_none_everywhere(self, session_mock: MagicMock):
        # The same value-less line through all three parsers, which used to
        # disagree: "" from get_device, None from get_attributes, and dropped
        # entirely by get_devices
        r_text = "TH840-A sys SNMPv2-MIB.sysLocation =\n"
        session_mock.return_value.text = r_text

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        self.assertIsNone(api.get_device("TH840-A")["sys"]["SNMPv2-MIB.sysLocation"])
        self.assertIsNone(
            api.get_attributes(device="TH840-A")["TH840-A"]["sys"][
                "SNMPv2-MIB.sysLocation"
            ]
        )
        devices = api.get_devices()
        # the device is listed rather than dropped
        self.assertIn("TH840-A", devices)
        self.assertIsNone(devices["TH840-A"]["SNMPv2-MIB.sysLocation"])

    @patch("requests.Session.post")
    def test_get_series_builds_group_filter(self, session_mock: MagicMock):
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        api.get_series(groups=["a10", "core"], group_filter="all")
        cmds = session_mock.call_args.kwargs["params"]["cmds"]
        self.assertTrue(cmds.endswith(" all group a10 core"))

    @patch("requests.Session.post")
    def test_get_aggregate_builds_group_filter(self, session_mock: MagicMock):
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        api.get_aggregate(groups=["a10"])
        cmds = session_mock.call_args.kwargs["params"]["cmds"]
        self.assertTrue(cmds.endswith(" any group a10"))

    @patch("requests.Session.post")
    def test_get_unreachable_keeps_the_earliest_event_start(
        self, session_mock: MagicMock
    ):
        # Two states down for one device with different start times; the
        # earlier one is what the outage began at
        r_text = """dev-1 ping4 PING.icmpState = 1,down,1484685257,1657029502,192.0.2.101
dev-1 sys SNMP.snmpState = 1,down,1484685257,1657029400,
"""  # noqa
        session_mock.return_value.text = r_text

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        devices = api.get_unreachable()
        self.assertEqual(devices["dev-1"]["event_start"].timestamp(), 1657029400)

        # and the same regardless of the order the lines arrive in
        session_mock.return_value.text = "\n".join(reversed(r_text.strip().split("\n")))
        devices = api.get_unreachable()
        self.assertEqual(devices["dev-1"]["event_start"].timestamp(), 1657029400)

    @patch("requests.Session.post")
    def test_get_unreachable_warns_about_lines_it_cannot_parse(
        self, session_mock: MagicMock
    ):
        # A device reported down that this cannot read must not vanish:
        # under reporting an outage is the worst thing this call can do
        r_text = """dev1 ping4 PING.icmpState = 1,down,1690000000,1753970052
dev2 ping4 PING.icmpState = 1,down here,1690000000,1753970052,192.0.2.102
dev3 ping4 PING.icmpState = 1,down,1690000000,1753970052,192.0.2.103
"""  # noqa
        session_mock.return_value.text = r_text

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        with self.assertLogs("akips", level="WARNING") as logged:
            devices = api.get_unreachable()
        self.assertEqual(list(devices), ["dev3"])
        self.assertIn("Could not parse 2 of 3", logged.output[0])
        # the warning carries a sample so the cause is diagnosable
        self.assertIn("dev1 ping4", logged.output[0])

    @patch("requests.Session.post")
    def test_get_unreachable_fields_do_not_depend_on_line_order(
        self, session_mock: MagicMock
    ):
        ping = "dev1 ping4 PING.icmpState = 1,down,1690000000,1753970052,192.0.2.101\n"
        snmp = "dev1 sys SNMP.snmpState = 2,down,1690000000,1753970052,\n"

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        seen = []
        for text in (ping + snmp, snmp + ping):
            session_mock.return_value.text = text
            entry = api.get_unreachable()["dev1"]
            seen.append(
                (entry["ip4addr"], entry["child"], entry["index"], entry["ping_state"])
            )
        # the ping line carries the address, so it wins the shared fields
        # whichever order the server sent them in
        self.assertEqual(seen[0], seen[1])
        self.assertEqual(seen[0], ("192.0.2.101", "ping4", "1", "down"))

    @patch("requests.Session.post")
    def test_get_devices_keeps_attributes_beyond_the_requested_set(
        self, session_mock: MagicMock
    ):
        # The four requested keys are always present; anything else the server
        # sends is kept rather than dropped
        r_text = """dev1 sys ip4addr = 192.0.2.101
dev1 sys SNMPv2-MIB.sysContact = Networking
"""  # noqa
        session_mock.return_value.text = r_text

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        entry = api.get_devices()["dev1"]
        for requested in (
            "ip4addr",
            "SNMPv2-MIB.sysName",
            "SNMPv2-MIB.sysDescr",
            "SNMPv2-MIB.sysLocation",
        ):
            self.assertIn(requested, entry)
        self.assertEqual(entry["SNMPv2-MIB.sysContact"], "Networking")


class LabeledAggregateTest(unittest.TestCase):
    """
    An aggregate arrives as bare numbers, so labeling one means asking the
    server where the window was rather than working it out from the clock here.
    """

    # Captured bounds for last1h: 3600 seconds, so 13 fenceposts at 300
    WINDOW = "1785682928,1785686528\n"
    VALUES = "4,5,6,7,8,9,10,11,12,13,14,15,16\n"

    def _api_returning(self, *replies: str):
        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        remaining = iter(replies)

        def reply(*args, **kwargs):
            response = MagicMock()
            response.text = next(remaining)
            response.ok = True
            response.status_code = 200
            return response

        return api, reply

    def test_unlabeled_is_unchanged_and_asks_once(self):
        api, reply = self._api_returning(self.VALUES)
        with patch.object(api.session, "post", side_effect=reply) as session_mock:
            values = api.get_aggregate()
        self.assertEqual(values[0], "4")
        self.assertEqual(len(values), 13)
        # no second request for the window when it is not needed
        self.assertEqual(session_mock.call_count, 1)

    def test_labeled_puts_a_time_against_each_value(self):
        api, reply = self._api_returning(self.VALUES, self.WINDOW)
        with patch.object(api.session, "post", side_effect=reply) as session_mock:
            points = api.get_aggregate(labeled=True)
        self.assertEqual(session_mock.call_count, 2)
        self.assertEqual(
            session_mock.call_args.kwargs["params"]["cmds"], "tf pairs last1h"
        )
        self.assertEqual(len(points), 13)
        self.assertEqual(points[0]["value"], 4.0)
        # fenceposts, so the last value lands on the end of the window itself
        self.assertEqual(points[0]["time"].timestamp(), 1785682928)
        self.assertEqual(points[-1]["time"].timestamp(), 1785686528)
        self.assertIsNotNone(points[0]["time"].tzinfo)

    def test_the_axis_is_evenly_spaced_by_the_interval(self):
        api, reply = self._api_returning(self.VALUES, self.WINDOW)
        with patch.object(api.session, "post", side_effect=reply):
            points = api.get_aggregate(labeled=True)
        gaps = {
            int(b["time"].timestamp() - a["time"].timestamp())
            for a, b in zip(points, points[1:])
        }
        self.assertEqual(gaps, {300})

    def test_a_period_of_several_ranges_is_refused(self):
        # A discontinuous filter is not one axis, and pretending otherwise
        # would draw five weekday windows as though they ran together
        api, reply = self._api_returning(
            self.VALUES, "1785124800,1785168000\n1785211200,1785254400\n"
        )
        with patch.object(api.session, "post", side_effect=reply):
            with self.assertRaises(ValueError) as caught:
                api.get_aggregate(period="lastweek", labeled=True)
        self.assertIn("2 separate ranges", str(caught.exception))

    def test_an_unreadable_window_is_refused(self):
        api, reply = self._api_returning(self.VALUES, "not,epochs\n")
        with patch.object(api.session, "post", side_effect=reply):
            with self.assertRaises(ValueError) as caught:
                api.get_aggregate(labeled=True)
        self.assertIn("epoch seconds", str(caught.exception))

    def test_empty_intervals_are_padding_not_anomalies(self):
        # A calendar relative period covers the whole day, so every interval
        # after the current moment comes back empty.  That is the period doing
        # what it says, and warning about it would fire on every such call all
        # day until a consumer silenced the logger.
        api, reply = self._api_returning("4,5,,,\n", self.WINDOW)
        logger = logging.getLogger("akips")
        with patch.object(api.session, "post", side_effect=reply):
            with patch.object(logger, "warning") as warn:
                points = api.get_aggregate(labeled=True)
        warn.assert_not_called()
        self.assertEqual([p["value"] for p in points], [4.0, 5.0, None, None, None])
        # the empty ones keep their place on the axis
        self.assertEqual(int(points[4]["time"].timestamp()), 1785682928 + 4 * 300)

    def test_an_unreadable_value_is_quoted_in_the_warning(self):
        # The value that provoked the warning has to appear in it.  An empty
        # string used to be reported as 'First:' followed by nothing at all.
        api, reply = self._api_returning("4,not-a-number,6\n", self.WINDOW)
        with patch.object(api.session, "post", side_effect=reply):
            with self.assertLogs("akips", level="WARNING") as logged:
                api.get_aggregate(labeled=True)
        self.assertIn("'not-a-number'", logged.output[0])

    def test_a_value_that_is_not_a_number_keeps_its_place(self):
        # Dropping it would shift every later point along the axis
        api, reply = self._api_returning("4,nan-ish,6\n", self.WINDOW)
        with patch.object(api.session, "post", side_effect=reply):
            with self.assertLogs("akips", level="WARNING") as logged:
                points = api.get_aggregate(labeled=True)
        self.assertEqual(len(points), 3)
        self.assertIsNone(points[1]["value"])
        self.assertEqual(points[2]["value"], 6.0)
        self.assertEqual(int(points[2]["time"].timestamp()), 1785682928 + 600)
        self.assertIn("nan-ish", logged.output[0])


class InventoryAttributesTest(unittest.TestCase):
    """
    get_devices asks for the values the AKiPS device edit page shows read
    only, being what SNMP reported rather than what an operator set.
    """

    @patch("requests.Session.post")
    def test_it_asks_for_the_six_polled_values(self, session_mock: MagicMock):
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        api.get_devices()
        self.assertEqual(
            session_mock.call_args.kwargs["params"]["cmds"],
            "mget text * sys /ip4addr|SNMPv2-MIB.sysName|SNMPv2-MIB.sysDescr"
            "|SNMPv2-MIB.sysObjectID|SNMPv2-MIB.sysLocation"
            "|SNMPv2-MIB.sysContact/",
        )

    @patch("requests.Session.post")
    def test_every_device_carries_every_field(self, session_mock: MagicMock):
        # The point of a fixed list: a device that reported only its name
        # still comes back with all six keys, so a listing needs no per-key
        # check.  A device reporting nothing for a field gets None.
        session_mock.return_value.text = (
            "dev-full sys ip4addr = 192.0.2.1\n"
            "dev-full sys SNMPv2-MIB.sysName = dev-full\n"
            "dev-full sys SNMPv2-MIB.sysObjectID = ARUBA-MIB.ap225\n"
            "dev-full sys SNMPv2-MIB.sysContact = Networking\n"
            "dev-bare sys SNMPv2-MIB.sysName = dev-bare\n"
        )

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        devices = api.get_devices()
        expected = {
            "ip4addr",
            "SNMPv2-MIB.sysName",
            "SNMPv2-MIB.sysDescr",
            "SNMPv2-MIB.sysObjectID",
            "SNMPv2-MIB.sysLocation",
            "SNMPv2-MIB.sysContact",
        }
        for name, entry in devices.items():
            with self.subTest(device=name):
                self.assertEqual(set(entry), expected)
        self.assertEqual(
            devices["dev-full"]["SNMPv2-MIB.sysObjectID"], "ARUBA-MIB.ap225"
        )
        self.assertEqual(devices["dev-full"]["SNMPv2-MIB.sysContact"], "Networking")
        # the sparse device still has the keys, valued None
        self.assertIsNone(devices["dev-bare"]["SNMPv2-MIB.sysObjectID"])
        self.assertIsNone(devices["dev-bare"]["ip4addr"])

    @patch("requests.Session.post")
    def test_no_credential_attribute_is_requested(self, session_mock: MagicMock):
        # AKiPS keeps SNMP credentials on the same child, so an inventory that
        # widened its pattern carelessly would hand them back
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        api.get_devices()
        cmds = session_mock.call_args.kwargs["params"]["cmds"]
        for secret in ("community", "auth_password", "priv_password", "SNMP.user"):
            self.assertNotIn(secret, cmds)


class PingStateTest(unittest.TestCase):
    """The ping enum for every device, not only the ones that are down."""

    R_TEXT = (
        "dev-up sys PING.icmpState = 2,up,1560316757,1783095098,\n"
        "dev-down sys PING.icmpState = 1,down,1531240705,1787339442,\n"
    )

    @patch("requests.Session.post")
    def test_it_asks_for_every_state_by_default(self, session_mock: MagicMock):
        # get_unreachable filters to down; this one must not, or it cannot
        # answer anything about a healthy device
        session_mock.return_value.text = self.R_TEXT

        api = AKIPS("akips.example.com", ro_password="ro-secret")
        result = api.get_ping_state()
        sent = session_mock.call_args.kwargs["params"]["cmds"]
        self.assertNotIn("value", sent)
        self.assertIn("PING.icmpState", sent)
        self.assertIn("ping4", sent)
        self.assertEqual(set(result), {"dev-up", "dev-down"})

    @patch("requests.Session.post")
    def test_both_epochs_are_parsed_datetimes(self, session_mock: MagicMock):
        # The raw attribute holds two integers; a caller should not have to
        # know that, nor which epoch is which
        session_mock.return_value.text = self.R_TEXT

        api = AKIPS("akips.example.com", ro_password="ro-secret")
        entry = api.get_ping_state()["dev-up"]
        self.assertEqual(entry["value"], "up")
        # 'created' is when AKiPS started polling, so the device was added
        self.assertEqual(entry["created"].year, 2019)
        # 'modified' is when the state last changed
        self.assertEqual(entry["modified"].year, 2026)
        self.assertIsNotNone(entry["created"].tzinfo)
        self.assertIsNotNone(entry["modified"].tzinfo)

    @patch("requests.Session.post")
    def test_states_can_still_be_filtered(self, session_mock: MagicMock):
        session_mock.return_value.text = self.R_TEXT

        api = AKIPS("akips.example.com", ro_password="ro-secret")
        api.get_ping_state(states=("down",))
        self.assertIn("value /down/", session_mock.call_args.kwargs["params"]["cmds"])
