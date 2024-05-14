import unittest
from unittest.mock import MagicMock, patch
from akips import AKIPS, AkipsError


class AkipsTest(unittest.TestCase):

    @patch('requests.Session.get')
    def test_akips_error(self, session_mock: MagicMock):
        r_text = "ERROR: api-db invalid username/password"

        session_mock.return_value.ok = True
        session_mock.return_value.status_code = 200
        session_mock.return_value.text = r_text
        self.assertIsInstance(session_mock, MagicMock)

        api = AKIPS('127.0.0.1')

        self.assertFalse(session_mock.called)
        self.assertRaises(AkipsError, api.get_devices)
        self.assertTrue(session_mock.called)

    @patch('requests.Session.get')
    def test_get_devices(self, session_mock: MagicMock):
        r_text = """192.168.1.29 sys ip4addr = 192.168.1.29
192.168.1.29 sys SNMPv2-MIB.sysDescr = VMware ESXi 6.5.0 build-8294253 VMware Inc. x86_64
192.168.1.29 sys SNMPv2-MIB.sysName = server.example.com
192.168.1.30 sys ip4addr = 192.168.1.30
""" # noqa

        session_mock.return_value.ok = True
        session_mock.return_value.status_code = 200
        session_mock.return_value.text = r_text

        api = AKIPS('127.0.0.1')
        devices = api.get_devices()
        self.assertEqual(devices['192.168.1.29']['ip4addr'], '192.168.1.29')
        self.assertEqual(devices['192.168.1.29']['SNMPv2-MIB.sysDescr'], 'VMware ESXi 6.5.0 build-8294253 VMware Inc. x86_64')
        self.assertEqual(devices['192.168.1.29']['SNMPv2-MIB.sysName'], 'server.example.com')
        self.assertEqual(devices['192.168.1.30']['ip4addr'], '192.168.1.30')

    @patch('requests.Session.get')
    def test_get_unreachable(self, session_mock: MagicMock):
        r_text = """192.168.248.54 ping4 PING.icmpState = 1,down,1484685257,1657029502,192.168.248.54
192.168.248.54 sys SNMP.snmpState = 1,down,1484685257,1657029499,
CrN-082-AP ping4 PING.icmpState = 1,down,1605595895,1656331597,192.168.94.63
CrN-082-AP ping4 PING.icmpState = 1,down,1641624705,1646101757,192.168.94.112
""" # noqa
        session_mock.return_value.ok = True
        session_mock.return_value.status_code = 200
        session_mock.return_value.text = r_text

        api = AKIPS('127.0.0.1')
        devices = api.get_unreachable()
        self.assertEqual(devices['192.168.248.54']['snmp_state'], 'down')

    @patch('requests.Session.get')
    def test_get_series(self, session_mock: MagicMock):
        r_text = """parent,child,child description,attribute,2024-02-21 09:10,2024-02-21 09:11,2024-02-21 09:12,2024-02-21 09:13,2024-02-21 09:14,2024-02-21 09:15,2024-02-21 09:16,2024-02-21 09:17,2024-02-21 09:18,2024-02-21 09:19,2024-02-21 09:20,2024-02-21 09:21,2024-02-21 09:22,2024-02-21 09:23,2024-02-21 09:24,2024-02-21 09:25,2024-02-21 09:26,2024-02-21 09:27,2024-02-21 09:28,2024-02-21 09:29,2024-02-21 09:30,2024-02-21 09:31,2024-02-21 09:32,2024-02-21 09:33,2024-02-21 09:34,2024-02-21 09:35,2024-02-21 09:36,2024-02-21 09:37,2024-02-21 09:38,2024-02-21 09:39,2024-02-21 09:40,2024-02-21 09:41,2024-02-21 09:42,2024-02-21 09:43,2024-02-21 09:44,2024-02-21 09:45,2024-02-21 09:46,2024-02-21 09:47,2024-02-21 09:48,2024-02-21 09:49,2024-02-21 09:50,2024-02-21 09:51,2024-02-21 09:52,2024-02-21 09:53,2024-02-21 09:54,2024-02-21 09:55,2024-02-21 09:56,2024-02-21 09:57,2024-02-21 09:58,2024-02-21 09:59,2024-02-21 10:00,2024-02-21 10:01,2024-02-21 10:02,2024-02-21 10:03,2024-02-21 10:04,2024-02-21 10:05,2024-02-21 10:06,2024-02-21 10:07,2024-02-21 10:08,2024-02-21 10:09,2024-02-21 10:10
CrN-638-AP_110,radio.56.23.195.198.156.238.1,,WLSX-WLAN-MIB.wlanAPRadioNumAssociatedClients,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
CrN-638-AP_111B,radio.0.11.134.253.238.238.1,,WLSX-WLAN-MIB.wlanAPRadioNumAssociatedClients,2,2,2,2,2,2,2,1,3,4,3,2,2,2,1,1,1,2,3,3,3,3,3,3,1,2,1,1,1,1,1,1,0,0,0,0,0,0,0,0,0,0,0,0,1,1,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0
""" # noqa
        session_mock.return_value.ok = True
        session_mock.return_value.status_code = 200
        session_mock.return_value.text = r_text

        api = AKIPS('127.0.0.1')
        series = api.get_series(attribute='WLSX-WLAN-MIB.wlanAPRadioNumAssociatedClients')
        self.assertEqual(series[0]['2024-02-21 09:10'], '0')
        self.assertEqual(series[1]['2024-02-21 09:10'], '2')

    @patch('requests.Session.get')
    def test_get_aggregate(self, session_mock: MagicMock):
        r_text = """30,31,30,27,27,28,28,28,30,29,29,28,27,29,30,29,28,28,27,28,26,25,25,25,25,26,24,24,24,21,23,24,23,24,22,23,25,29,30,31,34,34,34,34,36,33,31,31,32,32,33,29,29,30,29,28,27,31,31,31,30,28,28,29,28,26,26,25,26,26,25,25,24,23,23,22,20,13,12,12,11,11,13,12,11,11,11,9,9,8,8,10,10,10,9,9,7,7,8,10,10,8,9,11,12,12,8,8,8,8,9,7,7,7,6,6,7,7,7,8,7,7,8,8,6,6,6,6,6,7,7,7,6,7,6,6,6,6,6,6,6,6,7,7,7,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,8,7,7,6,6,6,6,6,6,6,6,7,7,7,7,6,7,7,7,7,6,6,7,6,7,6,6,7,6,6,6,6,7,7,7,7,6,6,6,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,6,6,6,6,6,6,6,6,7,7,7,6,7,7,7,7,6,6,6,6,6,6,6,6,7,7,7,7,7,7,7,12,13,12,13,14,14,15,14,14,14,19,21,22,22,23,23,25,24,23,23,23,23
""" # noqa
        session_mock.return_value.ok = True
        session_mock.return_value.status_code = 200
        session_mock.return_value.text = r_text

        api = AKIPS('127.0.0.1')
        series = api.get_aggregate(attribute='WLSX-WLAN-MIB.wlanAPRadioNumAssociatedClients')
        self.assertEqual(series[1], '31')

    @patch('requests.Session.get')
    def test_get_device_by_ip(self, session_mock: MagicMock):
        r_text = """IP Address 10.194.200.65 is configured on cisco-sw1
""" # noqa
        session_mock.return_value.ok = True
        session_mock.return_value.status_code = 200
        session_mock.return_value.text = r_text

        api = AKIPS('127.0.0.1')
        device_name = api.get_device_by_ip(ipaddr='10.194.200.65')
        self.assertEqual(device_name, 'cisco-sw1')

    @patch('requests.Session.get')
    def test_get_group_membership(self, session_mock: MagicMock):
        r_text = """10.10.10.146 = admin,Cisco,maintenance_mode,Not-Core,OpsCenter,poll_oid_10,user
10.10.20.31 = Security,admin,maintenance_mode,Not-Core,OpsCenter,PaloAlto,user
10.10.30.26 = admin,Brocade,maintenance_mode,Not-Core,OpsCenter,Ungrouped,user
""" # noqa
        session_mock.return_value.ok = True
        session_mock.return_value.status_code = 200
        session_mock.return_value.text = r_text

        api = AKIPS('127.0.0.1')
        list = api.get_group_membership(groups=['maintenance_mode'])
        self.assertEqual(list['10.10.10.146'][0], 'admin')
