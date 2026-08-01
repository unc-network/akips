"""
Tests for the api-db section: entities, groups, events and time series.
"""

import unittest
from unittest.mock import MagicMock, patch

from akips import AKIPS


class ApiDbTest(unittest.TestCase):
    @patch("requests.Session.get")
    def test_get_devices(self, session_mock: MagicMock):
        r_text = """192.168.1.29 sys ip4addr = 192.168.1.29
192.168.1.29 sys SNMPv2-MIB.sysDescr = VMware ESXi 6.5.0 build-8294253 VMware Inc. x86_64
192.168.1.29 sys SNMPv2-MIB.sysName = server.example.com
192.168.1.30 sys ip4addr = 192.168.1.30
"""  # noqa

        session_mock.return_value.ok = True
        session_mock.return_value.status_code = 200
        session_mock.return_value.text = r_text

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        devices = api.get_devices()
        self.assertEqual(devices["192.168.1.29"]["ip4addr"], "192.168.1.29")
        self.assertEqual(
            devices["192.168.1.29"]["SNMPv2-MIB.sysDescr"],
            "VMware ESXi 6.5.0 build-8294253 VMware Inc. x86_64",
        )
        self.assertEqual(
            devices["192.168.1.29"]["SNMPv2-MIB.sysName"], "server.example.com"
        )
        self.assertEqual(devices["192.168.1.30"]["ip4addr"], "192.168.1.30")

    @patch("requests.Session.get")
    def test_get_unreachable(self, session_mock: MagicMock):
        r_text = """192.168.248.54 ping4 PING.icmpState = 1,down,1484685257,1657029502,192.168.248.54
192.168.248.54 sys SNMP.snmpState = 1,down,1484685257,1657029499,
CrN-082-AP ping4 PING.icmpState = 1,down,1605595895,1656331597,192.168.94.63
CrN-082-AP ping4 PING.icmpState = 1,down,1641624705,1646101757,192.168.94.112
"""  # noqa
        session_mock.return_value.ok = True
        session_mock.return_value.status_code = 200
        session_mock.return_value.text = r_text

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        devices = api.get_unreachable()
        self.assertEqual(devices["192.168.248.54"]["snmp_state"], "down")
        self.assertEqual(devices["192.168.248.54"]["ping_state"], "down")
        # child is the matched string; it used to be a one element tuple,
        # the only field in the structure with a surprising type
        self.assertEqual(devices["192.168.248.54"]["child"], "sys")
        self.assertEqual(devices["CrN-082-AP"]["child"], "ping4")
        self.assertEqual(devices["192.168.248.54"]["index"], "1")

    @patch("requests.Session.get")
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

    @patch("requests.Session.get")
    def test_get_group_membership(self, session_mock: MagicMock):
        r_text = """10.10.10.146 = admin,Cisco,maintenance_mode,Not-Core,OpsCenter,poll_oid_10,user
10.10.20.31 = Security,admin,maintenance_mode,Not-Core,OpsCenter,PaloAlto,user
10.10.30.26 = admin,Brocade,maintenance_mode,Not-Core,OpsCenter,Ungrouped,user
"""  # noqa
        session_mock.return_value.ok = True
        session_mock.return_value.status_code = 200
        session_mock.return_value.text = r_text

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        list = api.get_group_membership(groups=["maintenance_mode"])
        self.assertEqual(list["10.10.10.146"][0], "admin")

    @patch("requests.Session.get")
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

    @patch("requests.Session.get")
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

    @patch("requests.Session.get")
    def test_get_device(self, session_mock: MagicMock):
        r_text = """TH840-A sys SNMPv2-MIB.sysName = TH840-A
TH840-A sys SNMPv2-MIB.sysLocation = Datacenter A
TH840-A Ethernet1 IF-MIB.ifDescr = Ethernet 1
TH840-A Ethernet1 IF-MIB.ifAlias =
"""  # noqa
        session_mock.return_value.text = r_text

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        device = api.get_device("TH840-A")
        # Keyed by device name, keeping the parent, child and attribute levels
        # AKiPS stores.  Asking for one device gives one key rather than a
        # differently shaped result.
        self.assertEqual(list(device), ["TH840-A"])
        self.assertEqual(device["TH840-A"]["sys"]["SNMPv2-MIB.sysName"], "TH840-A")
        self.assertEqual(
            device["TH840-A"]["sys"]["SNMPv2-MIB.sysLocation"], "Datacenter A"
        )
        self.assertEqual(device["TH840-A"]["Ethernet1"]["IF-MIB.ifDescr"], "Ethernet 1")
        # An attribute with nothing after the equals has no value, reported
        # as None consistently across get_device, get_attributes and
        # get_devices
        self.assertIsNone(device["TH840-A"]["Ethernet1"]["IF-MIB.ifAlias"])
        # every value is a dictionary of children; nothing else is mixed in
        for children in device.values():
            for attributes in children.values():
                self.assertIsInstance(attributes, dict)

    @patch("requests.Session.get")
    def test_get_device_returns_none_for_empty_response(self, session_mock: MagicMock):
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        self.assertIsNone(api.get_device("TH840-A"))

    @patch("requests.Session.get")
    def test_get_device_with_unparsable_response(self, session_mock: MagicMock):
        session_mock.return_value.text = "no attribute lines here\n"

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        # A response that parses to nothing is not found, and is reported the
        # same way as an empty response rather than as a dict holding only the
        # name that was asked for
        self.assertIsNone(api.get_device("TH840-A"))

    @patch("requests.Session.get")
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

    @patch("requests.Session.get")
    def test_get_events_builds_group_filter(self, session_mock: MagicMock):
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        api.get_events(event_type="critical", period="last4h", groups=["a10", "core"])
        cmds = session_mock.call_args.kwargs["params"]["cmds"]
        self.assertEqual(
            cmds, "mget event critical time last4h * * * any group a10 core"
        )

    @patch("requests.Session.get")
    def test_get_devices_builds_group_filter(self, session_mock: MagicMock):
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        api.get_devices(group_filter="not", groups=["a10"])
        cmds = session_mock.call_args.kwargs["params"]["cmds"]
        self.assertTrue(cmds.endswith(" not group a10"))

    @patch("requests.Session.get")
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

    @patch("requests.Session.get")
    def test_get_series_honours_interval(self, session_mock: MagicMock):
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        api.get_series(time_interval=300, period="last8h")
        cmds = session_mock.call_args.kwargs["params"]["cmds"]
        self.assertTrue(cmds.startswith("cseries interval avg 300 time last8h "))

    @patch("requests.Session.get")
    def test_get_series_as_lists(self, session_mock: MagicMock):
        r_text = """parent,child,child description,attribute,2024-02-21 09:10
CrN-638-AP_110,radio.1,,WLSX-WLAN-MIB.wlanAPRadioNumAssociatedClients,4
"""  # noqa
        session_mock.return_value.text = r_text

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        rows = api.get_series(get_dict=False)
        self.assertEqual(rows[0][0], "parent")
        self.assertEqual(rows[1][4], "4")

    @patch("requests.Session.get")
    def test_get_aggregate_honours_operator(self, session_mock: MagicMock):
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        api.get_aggregate(operator="total", interval="600")
        cmds = session_mock.call_args.kwargs["params"]["cmds"]
        self.assertTrue(cmds.startswith("aggregate interval total 600 "))

    @patch("requests.Session.get")
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

    @patch("requests.Session.get")
    def test_cmd_still_works_but_warns(self, session_mock: MagicMock):
        r_text = "TH840-A sys ip4addr = 192.168.20.15\n"
        session_mock.return_value.text = r_text

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        with self.assertWarns(DeprecationWarning):
            self.assertEqual(api.cmd("mget * TH840-A sys ip4addr"), r_text)
        self.assertEqual(
            session_mock.call_args.kwargs["params"]["cmds"],
            "mget * TH840-A sys ip4addr",
        )

    @patch("requests.Session.get")
    def test_cmd_rejects_unknown_output_format(self, session_mock: MagicMock):
        session_mock.return_value.text = "some output\n"

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        with self.assertWarns(DeprecationWarning), self.assertRaises(ValueError):
            api.cmd("mget * * * *", output="json")
        # cmd only ever supported raw; call() is where the other formats live
        self.assertFalse(session_mock.called)

    @patch("requests.Session.get")
    def test_empty_attribute_values_are_none_everywhere(self, session_mock: MagicMock):
        # The same value-less line through all three parsers, which used to
        # disagree: "" from get_device, None from get_attributes, and dropped
        # entirely by get_devices
        r_text = "TH840-A sys SNMPv2-MIB.sysLocation =\n"
        session_mock.return_value.text = r_text

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        self.assertIsNone(
            api.get_device("TH840-A")["TH840-A"]["sys"]["SNMPv2-MIB.sysLocation"]
        )
        self.assertIsNone(
            api.get_attributes(device="TH840-A")["TH840-A"]["sys"][
                "SNMPv2-MIB.sysLocation"
            ]
        )
        devices = api.get_devices()
        # the device is listed rather than dropped
        self.assertIn("TH840-A", devices)
        self.assertIsNone(devices["TH840-A"]["SNMPv2-MIB.sysLocation"])

    @patch("requests.Session.get")
    def test_get_series_builds_group_filter(self, session_mock: MagicMock):
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        api.get_series(groups=["a10", "core"], group_filter="all")
        cmds = session_mock.call_args.kwargs["params"]["cmds"]
        self.assertTrue(cmds.endswith(" all group a10 core"))

    @patch("requests.Session.get")
    def test_get_aggregate_builds_group_filter(self, session_mock: MagicMock):
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        api.get_aggregate(groups=["a10"])
        cmds = session_mock.call_args.kwargs["params"]["cmds"]
        self.assertTrue(cmds.endswith(" any group a10"))

    @patch("requests.Session.get")
    def test_get_unreachable_keeps_the_earliest_event_start(
        self, session_mock: MagicMock
    ):
        # Two states down for one device with different start times; the
        # earlier one is what the outage began at
        r_text = """dev-1 ping4 PING.icmpState = 1,down,1484685257,1657029502,10.0.0.1
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
