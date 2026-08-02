"""
Tests for the api-availability section: availability statistics.
"""

import logging
import unittest
from unittest.mock import MagicMock, patch

from akips import AKIPS


class ApiAvailabilityTest(unittest.TestCase):
    @patch("requests.Session.get")
    def test_get_group_availability(self, session_mock: MagicMock):
        # This endpoint returns no header row, so the parser supplies the
        # column names itself.
        r_text = """ping4,PING.icmpState,1-Building-4,11688115,11687711,9990,last1w
ping4,PING.icmpState,1-Fraser,8213270,8213190,9990,last1w
ping4,PING.icmpState,1-Building-16,44541195,44540002,9990,last1w
"""  # noqa
        session_mock.return_value.text = r_text

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        rows = api.get_group_availability()
        self.assertEqual(len(rows), 3)
        self.assertEqual(rows[0]["child"], "ping4")
        self.assertEqual(rows[0]["attr"], "PING.icmpState")
        self.assertEqual(rows[0]["group name"], "1-Building-4")
        self.assertEqual(rows[0]["total time"], "11688115")
        self.assertEqual(rows[0]["match time"], "11687711")
        self.assertEqual(rows[0]["group target"], "9990")
        self.assertEqual(rows[0]["tf"], "last1w")
        self.assertEqual(rows[2]["group name"], "1-Building-16")

    @patch("requests.Session.get")
    def test_get_group_availability_keeps_schedule_in_time_filter(
        self, session_mock: MagicMock
    ):
        # A group with a business hours target carries its schedule in the
        # final field, separated from the time filter by a semicolon. The
        # schedule itself may contain further semicolons.
        r_text = """ping4,PING.icmpState,Accedian,1766635,1766635,9890,last1w;mon to sat 6:00 to 20:00
ping4,PING.icmpState,Aerohive,589475,589475,9999,last1w;mon to fri 7:00 to 19:00; sat 8:00 to 18:00
"""  # noqa
        session_mock.return_value.text = r_text

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        rows = api.get_group_availability(period="last1w")
        self.assertEqual(rows[0]["tf"], "last1w;mon to sat 6:00 to 20:00")
        self.assertEqual(
            rows[1]["tf"], "last1w;mon to fri 7:00 to 19:00; sat 8:00 to 18:00"
        )
        # The schedule must not bleed into the preceding column
        self.assertEqual(rows[1]["group target"], "9999")

    @patch("requests.Session.get")
    def test_get_group_availability_sends_expected_request(
        self, session_mock: MagicMock
    ):
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        api.get_group_availability(
            period="last1w", report="snmp,ping4", group="Accedian"
        )
        args, kwargs = session_mock.call_args
        self.assertTrue(args[0].endswith("/api-availability"))
        params = kwargs["params"]
        self.assertEqual(params["mode"], "group")
        self.assertEqual(params["maintenance"], "off")
        self.assertEqual(params["time"], "last1w")
        self.assertEqual(params["report"], "snmp,ping4")
        self.assertEqual(params["group"], "Accedian")

    @patch("requests.Session.get")
    def test_get_group_availability_defaults(self, session_mock: MagicMock):
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        api.get_group_availability()
        params = session_mock.call_args.kwargs["params"]
        self.assertEqual(params["time"], "last1d")
        self.assertEqual(params["report"], "ping4")
        # No group means no filter; requests drops a None valued parameter
        self.assertIsNone(params["group"])

    @patch("requests.Session.get")
    def test_get_group_availability_returns_none_for_empty_response(
        self, session_mock: MagicMock
    ):
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        self.assertIsNone(api.get_group_availability())


class DeviceAvailabilityTest(unittest.TestCase):
    @patch("requests.Session.get")
    def test_get_device_availability(self, session_mock: MagicMock):
        # Six fields and no header row, and a device checked by both ping and
        # SNMP reports one row for each.
        r_text = """accedian-131-2-7,ping4,PING.icmpState,136020,136020,9890
accedian-131-2-7,sys,SNMP.snmpState,136020,135900,9890
"""  # noqa
        session_mock.return_value.text = r_text

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        rows = api.get_device_availability(group="Accedian")
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["parent"], "accedian-131-2-7")
        self.assertEqual(rows[0]["child"], "ping4")
        self.assertEqual(rows[0]["attr"], "PING.icmpState")
        self.assertEqual(rows[0]["total time"], "136020")
        self.assertEqual(rows[0]["match time"], "136020")
        # basis points, so 9890 is a 98.90% target
        self.assertEqual(rows[0]["group target"], "9890")
        self.assertEqual(rows[1]["child"], "sys")
        self.assertEqual(rows[1]["match time"], "135900")

    @patch("requests.Session.get")
    def test_get_device_availability_sends_expected_request(
        self, session_mock: MagicMock
    ):
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        api.get_device_availability(
            period="last1w", report="snmp,ping4", device="accedian-131-2-7"
        )
        args, kwargs = session_mock.call_args
        self.assertTrue(args[0].endswith("/api-availability"))
        params = kwargs["params"]
        self.assertEqual(params["mode"], "device")
        self.assertEqual(params["maintenance"], "off")
        self.assertEqual(params["time"], "last1w")
        self.assertEqual(params["report"], "snmp,ping4")
        self.assertEqual(params["entity"], "accedian-131-2-7")
        self.assertIsNone(params["group"])

    @patch("requests.Session.get")
    def test_get_device_availability_needs_a_scope(self, session_mock: MagicMock):
        # AKiPS answers an unscoped device mode call with an empty body rather
        # than an error, which would reach the caller as None and read as
        # 'nothing to report'.  Refuse it before the request instead.
        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        with self.assertRaises(ValueError) as caught:
            api.get_device_availability()
        self.assertIn("device or a group", str(caught.exception))
        self.assertFalse(session_mock.called)

    @patch("requests.Session.get")
    def test_get_device_availability_returns_none_for_empty_response(
        self, session_mock: MagicMock
    ):
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        self.assertIsNone(api.get_device_availability(device="accedian-131-2-7"))


class EventAvailabilityTest(unittest.TestCase):
    @patch("requests.Session.get")
    def test_get_event_availability(self, session_mock: MagicMock):
        r_text = """cisco-131-16-1,ping4,1603822871,1603822916,2389764,2388341
cisco-131-16-1,ping4,1603088563,1603089823,2389764,2388341
"""  # noqa
        session_mock.return_value.text = r_text

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        rows = api.get_event_availability(device="cisco-131-16-1")
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["parent"], "cisco-131-16-1")
        self.assertEqual(rows[0]["child"], "ping4")
        self.assertEqual(rows[0]["down"], "1603822871")
        self.assertEqual(rows[0]["up"], "1603822916")
        self.assertEqual(rows[0]["total time"], "2389764")
        self.assertEqual(rows[0]["match time"], "2388341")

    @patch("requests.Session.get")
    def test_get_event_availability_keeps_a_device_with_no_event_pair(
        self, session_mock: MagicMock
    ):
        # A device that stayed up has no pair, so down and up come back empty
        # while the totals are still populated.  Those two empty fields are
        # why events mode cannot share group mode's column names, which would
        # label 'total time' as 'attr'.
        session_mock.return_value.text = "192.0.2.113,sys,,,32017,32017\n"

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        rows = api.get_event_availability(device="192.0.2.113")
        self.assertEqual(rows[0]["down"], "")
        self.assertEqual(rows[0]["up"], "")
        self.assertEqual(rows[0]["total time"], "32017")
        self.assertEqual(rows[0]["match time"], "32017")

    @patch("requests.Session.get")
    def test_get_event_availability_sends_expected_request(
        self, session_mock: MagicMock
    ):
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        api.get_event_availability(period="last1M", device="cisco-131-16-1")
        params = session_mock.call_args.kwargs["params"]
        self.assertEqual(params["mode"], "events")
        self.assertEqual(params["time"], "last1M")
        self.assertEqual(params["entity"], "cisco-131-16-1")

    @patch("requests.Session.get")
    def test_get_event_availability_warns_when_unscoped_and_empty(
        self, session_mock: MagicMock
    ):
        # Whether events mode needs a scope the way device mode does has not
        # been confirmed against a server, so this says something rather than
        # returning None as though there were no outages.
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        with self.assertLogs("akips", level="WARNING") as logged:
            self.assertIsNone(api.get_event_availability())
        self.assertIn("device or group", logged.output[0])

    @patch("requests.Session.get")
    def test_get_event_availability_stays_quiet_when_scoped(
        self, session_mock: MagicMock
    ):
        # A scoped call returning nothing is a real answer: no outages.
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        logger = logging.getLogger("akips")
        with patch.object(logger, "warning") as warn:
            self.assertIsNone(api.get_event_availability(device="cisco-131-16-1"))
        warn.assert_not_called()
