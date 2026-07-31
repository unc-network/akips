"""
Tests for the api-availability section: availability statistics.
"""

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

        api = AKIPS("127.0.0.1")
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

        api = AKIPS("127.0.0.1")
        rows = api.get_group_availability(time="last1w")
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

        api = AKIPS("127.0.0.1")
        api.get_group_availability(time="last1w", report="snmp,ping4", group="Accedian")
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

        api = AKIPS("127.0.0.1")
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

        api = AKIPS("127.0.0.1")
        self.assertIsNone(api.get_group_availability())
