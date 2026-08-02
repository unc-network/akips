"""
Tests for reading the most recent value of a numeric attribute.

Numeric attributes keep their readings in the time series database rather than
alongside the enum and text attributes, so these go through cseries.
"""

import logging
import unittest
from unittest.mock import MagicMock, patch

from akips import AKIPS

# Captured from an AKiPS command console.  Note the final interval is still
# being filled and comes back empty, which is normal rather than an error.
BATTERY_VOLTAGE = (
    "parent,child,child description,attribute,2026-08-01 12:44,"
    "2026-08-01 12:49,2026-08-01 12:54,2026-08-01 12:59\n"
    "172.29.214.24,battery,,UPS-MIB.upsBatteryVoltage,53,53,53,\n"
)


class LatestValuesTest(unittest.TestCase):
    @patch("requests.Session.get")
    def test_the_last_completed_interval_is_the_answer(self, session_mock: MagicMock):
        session_mock.return_value.text = BATTERY_VOLTAGE

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        result = api.get_latest_values(
            "UPS-MIB.upsBatteryVoltage", device="172.29.214.24", child="battery"
        )
        self.assertEqual(
            session_mock.call_args.kwargs["params"]["cmds"],
            "cseries interval avg 300 time last1h * 172.29.214.24 battery "
            "UPS-MIB.upsBatteryVoltage",
        )
        entry = result["172.29.214.24"]["battery"]
        # the trailing empty column is the interval in progress, not the value
        self.assertEqual(entry["value"], 53.0)
        self.assertEqual(entry["time"].strftime("%Y-%m-%d %H:%M"), "2026-08-01 12:54")
        self.assertEqual(entry["attribute"], "UPS-MIB.upsBatteryVoltage")

    @patch("requests.Session.get")
    def test_the_reading_is_timezone_aware(self, session_mock: MagicMock):
        session_mock.return_value.text = BATTERY_VOLTAGE

        api = AKIPS("127.0.0.1", ro_password="ro-secret", timezone="America/New_York")
        entry = api.get_latest_values("UPS-MIB.upsBatteryVoltage")["172.29.214.24"][
            "battery"
        ]
        # the column heading carries no offset, so it is read in the server's
        # timezone rather than whatever the caller happens to run in
        self.assertIsNotNone(entry["time"].tzinfo)
        self.assertIn("EDT", entry["time"].strftime("%Z"))

    @patch("requests.Session.get")
    def test_a_device_with_no_reading_is_kept_with_none(self, session_mock: MagicMock):
        # A device polled but with nothing recorded in the window is a
        # different answer from a device that was not asked about, so it is
        # reported rather than dropped
        session_mock.return_value.text = (
            "parent,child,child description,attribute,2026-08-01 12:54,2026-08-01 12:59\n"
            "ups-1,battery,,UPS-MIB.upsBatteryVoltage,53,\n"
            "ups-2,battery,,UPS-MIB.upsBatteryVoltage,,\n"
        )

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        result = api.get_latest_values("UPS-MIB.upsBatteryVoltage")
        self.assertEqual(result["ups-1"]["battery"]["value"], 53.0)
        self.assertIsNone(result["ups-2"]["battery"]["value"])
        self.assertIsNone(result["ups-2"]["battery"]["time"])

    @patch("requests.Session.get")
    def test_several_children_on_one_device_are_all_kept(self, session_mock: MagicMock):
        # Keyed by device and child, because an attribute like interface
        # utilization has one reading per interface and a flat key would keep
        # only the last
        session_mock.return_value.text = (
            "parent,child,child description,attribute,2026-08-01 12:54,2026-08-01 12:59\n"
            "switch-1,eth0,,IF-MIB.ifInUtil,12,\n"
            "switch-1,eth1,,IF-MIB.ifInUtil,7,\n"
        )

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        result = api.get_latest_values("IF-MIB.ifInUtil")
        self.assertEqual(sorted(result["switch-1"]), ["eth0", "eth1"])
        self.assertEqual(result["switch-1"]["eth0"]["value"], 12.0)
        self.assertEqual(result["switch-1"]["eth1"]["value"], 7.0)

    @patch("requests.Session.get")
    def test_a_value_that_is_not_a_number_is_reported_not_dropped(
        self, session_mock: MagicMock
    ):
        session_mock.return_value.text = (
            "parent,child,child description,attribute,2026-08-01 12:54,2026-08-01 12:59\n"
            "ups-1,battery,,UPS-MIB.upsBatteryVoltage,53,\n"
            "ups-2,battery,,UPS-MIB.upsBatteryVoltage,not-a-number,\n"
        )

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        with self.assertLogs("akips", level="WARNING") as logged:
            result = api.get_latest_values("UPS-MIB.upsBatteryVoltage")
        self.assertEqual(list(result), ["ups-1"])
        self.assertIn("ups-2", logged.output[0])

    @patch("requests.Session.get")
    def test_group_filtering_and_interval(self, session_mock: MagicMock):
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        api.get_latest_values(
            "UPS-MIB.upsBatteryVoltage",
            period="last30m",
            time_interval=60,
            groups=["datacenter"],
            group_filter="all",
        )
        cmds = session_mock.call_args.kwargs["params"]["cmds"]
        self.assertTrue(cmds.startswith("cseries interval avg 60 time last30m "))
        self.assertTrue(cmds.endswith(" all group datacenter"))

    @patch("requests.Session.get")
    def test_nothing_returned_is_none(self, session_mock: MagicMock):
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        self.assertIsNone(api.get_latest_values("UPS-MIB.upsBatteryVoltage"))

    @patch("requests.Session.get")
    def test_an_unreadable_column_heading_keeps_the_value(
        self, session_mock: MagicMock
    ):
        # Losing the reading because its timestamp was in an unexpected shape
        # would be a poor trade
        session_mock.return_value.text = (
            "parent,child,child description,attribute,not a timestamp\n"
            "ups-1,battery,,UPS-MIB.upsBatteryVoltage,53\n"
        )

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        logger = logging.getLogger("akips")
        with patch.object(logger, "warning") as warn:
            entry = api.get_latest_values("UPS-MIB.upsBatteryVoltage")["ups-1"][
                "battery"
            ]
        self.assertEqual(entry["value"], 53.0)
        self.assertIsNone(entry["time"])
        warn.assert_not_called()

    @patch("requests.Session.get")
    def test_a_row_with_no_device_is_skipped(self, session_mock: MagicMock):
        # A blank leading field would otherwise key the result under an empty
        # string, which is worse than leaving the row out
        session_mock.return_value.text = (
            "parent,child,child description,attribute,2026-08-01 12:54\n"
            ",,,UPS-MIB.upsBatteryVoltage,53\n"
            "ups-1,battery,,UPS-MIB.upsBatteryVoltage,53\n"
        )

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        result = api.get_latest_values("UPS-MIB.upsBatteryVoltage")
        self.assertEqual(list(result), ["ups-1"])
