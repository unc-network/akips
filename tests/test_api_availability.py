"""
Tests for the api-availability section: availability statistics.
"""

import unittest
from unittest.mock import MagicMock, patch

from akips import AKIPS


class ApiAvailabilityTest(unittest.TestCase):
    @patch("requests.Session.post")
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

    @patch("requests.Session.post")
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

    @patch("requests.Session.post")
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

    @patch("requests.Session.post")
    def test_get_group_availability_defaults(self, session_mock: MagicMock):
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        api.get_group_availability()
        params = session_mock.call_args.kwargs["params"]
        # A rolling 24 hours, not 'last1d'.  AKiPS reads 'lastNd' as N-1 whole
        # days plus today so far, so the default would measure five minutes at
        # 00:05 and report it as a confident 100%.
        self.assertEqual(params["time"], "last24h")
        self.assertEqual(params["report"], "ping4")
        # No group means no filter; requests drops a None valued parameter
        self.assertIsNone(params["group"])

    @patch("requests.Session.post")
    def test_get_group_availability_returns_none_for_empty_response(
        self, session_mock: MagicMock
    ):
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        self.assertIsNone(api.get_group_availability())


class DeviceAvailabilityTest(unittest.TestCase):
    @patch("requests.Session.post")
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

    @patch("requests.Session.post")
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

    @patch("requests.Session.post")
    def test_get_device_availability_needs_a_scope(self, session_mock: MagicMock):
        # AKiPS answers an unscoped device mode call with an empty body rather
        # than an error, which would reach the caller as None and read as
        # 'nothing to report'.  Refuse it before the request instead.
        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        with self.assertRaises(ValueError) as caught:
            api.get_device_availability()
        self.assertIn("device or a group", str(caught.exception))
        self.assertFalse(session_mock.called)

    @patch("requests.Session.post")
    def test_get_device_availability_returns_none_for_empty_response(
        self, session_mock: MagicMock
    ):
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        self.assertIsNone(api.get_device_availability(device="accedian-131-2-7"))


class EventAvailabilityTest(unittest.TestCase):
    @patch("requests.Session.post")
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

    @patch("requests.Session.post")
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

    @patch("requests.Session.post")
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

    @patch("requests.Session.post")
    def test_get_event_availability_needs_a_scope(self, session_mock: MagicMock):
        # Confirmed against a server to behave the same way device mode does:
        # an unscoped call comes back empty rather than erroring, which would
        # reach the caller as None and read as 'no outages'.
        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        with self.assertRaises(ValueError) as caught:
            api.get_event_availability()
        self.assertIn("device or a group", str(caught.exception))
        self.assertFalse(session_mock.called)

    @patch("requests.Session.post")
    def test_get_event_availability_returns_none_for_empty_response(
        self, session_mock: MagicMock
    ):
        # A scoped call returning nothing is a real answer: no outages.
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        self.assertIsNone(api.get_event_availability(device="cisco-131-16-1"))

    @patch("requests.Session.post")
    def test_get_event_availability_reports_each_outage_separately(
        self, session_mock: MagicMock
    ):
        # Shaped after a live reply.  Two flaps on one device are two rows,
        # and both carry the same totals: 'total time' is the measurement
        # window, and 'match time' is that less the time spent down.  A
        # device that stayed up has no pair and the two are equal.
        #
        # Reading 'total time' as the length of the outage on its row would
        # report the whole window, a day and a half here, for a 44 second flap.
        session_mock.return_value.text = (
            "ap-a,ping4,1785658160,1785658204,120324,120234\n"
            "ap-a,ping4,1785589638,1785589684,120324,120234\n"
            "ap-b,ping4,,,120324,120324\n"
        )

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        rows = api.get_event_availability(group="4-Some-Building")
        self.assertEqual(len(rows), 3)

        flapped = [row for row in rows if row["parent"] == "ap-a"]
        durations = [int(row["up"]) - int(row["down"]) for row in flapped]
        self.assertEqual(durations, [44, 46])
        # the totals repeat across the device's rows rather than tracking them
        self.assertEqual(flapped[0]["total time"], flapped[1]["total time"])
        # and the shortfall in match time is the downtime, not one row's worth
        self.assertEqual(
            int(flapped[0]["total time"]) - int(flapped[0]["match time"]),
            sum(durations),
        )

        stayed_up = rows[2]
        self.assertEqual(stayed_up["down"], "")
        self.assertEqual(stayed_up["total time"], stayed_up["match time"])
        # every device in one reply is measured over the same window
        self.assertEqual(stayed_up["total time"], flapped[0]["total time"])


class AvailabilityPeriodTest(unittest.TestCase):
    def test_all_three_methods_default_to_a_rolling_window(self):
        # AKiPS reads 'lastNd' as N-1 whole days plus today so far, measured
        # against a live server: at 09:50 'last1d' was 35,458s rather than
        # 86,400s, and 'last7d' was 553,860s, six whole days plus today.  An
        # availability percentage over a window that shrinks to minutes after
        # midnight reads as a reliable 100% every night, so the default is the
        # rolling form that means what its name says.
        self.assertEqual(AKIPS.AVAILABILITY_PERIOD, "last24h")

    @patch("requests.Session.post")
    def test_the_default_reaches_every_availability_method(
        self, session_mock: MagicMock
    ):
        session_mock.return_value.text = ""
        api = AKIPS("127.0.0.1", ro_password="ro-secret")

        for call in (
            lambda: api.get_group_availability(),
            lambda: api.get_device_availability(group="4-Some-Building"),
            lambda: api.get_event_availability(group="4-Some-Building"),
        ):
            call()
            self.assertEqual(session_mock.call_args.kwargs["params"]["time"], "last24h")
