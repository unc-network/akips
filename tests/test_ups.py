"""
Tests for the UPS helpers.

Both read an enum typed attribute, so the interesting parts are the command
sent, the parsed value, and what happens to a device reporting something the
enum parser does not understand.
"""

import logging
import unittest
from unittest.mock import MagicMock, patch

from akips import AKIPS

# Taken from an AKiPS command console
OUTPUT_SOURCE = (
    "192.0.2.24 ups UPS-MIB.upsOutputSource = 4,bypass,1469649711,1782896221,\n"  # noqa
)
BATTERY_TEST = """192.0.2.121 battery LIEBERT-GP-POWER-MIB.lgpPwrBatteryTestResult = 2,passed,1420596219,1782274020,
192.0.2.128 battery LIEBERT-GP-POWER-MIB.lgpPwrBatteryTestResult = 2,passed,1420596219,1784088362,
"""  # noqa


class UpsOutputSourceTest(unittest.TestCase):
    def test_the_default_states_cover_every_value_but_normal(self):
        # UPS-MIB numbers upsOutputSource other(1) none(2) normal(3) bypass(4)
        # battery(5) booster(6) reducer(7).  Anything missing from this list is
        # a state no caller ever hears about, so pin the whole thing rather
        # than trust it to be maintained alongside the MIB.
        self.assertEqual(
            AKIPS.UPS_ABNORMAL_OUTPUT_SOURCES,
            ("other", "none", "bypass", "battery", "booster", "reducer"),
        )

    @patch("requests.Session.get")
    def test_defaults_to_the_states_worth_looking_at(self, session_mock: MagicMock):
        session_mock.return_value.text = OUTPUT_SOURCE

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        devices = api.get_ups_output_source()
        self.assertEqual(
            session_mock.call_args.kwargs["params"]["cmds"],
            "mget * * ups UPS-MIB.upsOutputSource "
            "value /other|none|bypass|battery|booster|reducer/",
        )
        entry = devices["192.0.2.24"]
        self.assertEqual(entry["value"], "bypass")
        self.assertEqual(entry["number"], "4")
        self.assertEqual(entry["child"], "ups")
        self.assertEqual(entry["name"], "192.0.2.24")
        # modified is when the UPS moved to this source
        self.assertEqual(entry["modified"].year, 2026)
        self.assertEqual(entry["created"].year, 2016)

    @patch("requests.Session.get")
    def test_no_states_means_every_ups(self, session_mock: MagicMock):
        session_mock.return_value.text = OUTPUT_SOURCE

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        api.get_ups_output_source(states=None)
        self.assertEqual(
            session_mock.call_args.kwargs["params"]["cmds"],
            "mget * * ups UPS-MIB.upsOutputSource",
        )

    @patch("requests.Session.get")
    def test_a_narrower_state_list(self, session_mock: MagicMock):
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        api.get_ups_output_source(states=["battery"])
        self.assertTrue(
            session_mock.call_args.kwargs["params"]["cmds"].endswith(
                "UPS-MIB.upsOutputSource value /battery/"
            )
        )

    @patch("requests.Session.get")
    def test_group_filtering(self, session_mock: MagicMock):
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        api.get_ups_output_source(groups=["datacenter"], group_filter="all")
        self.assertTrue(
            session_mock.call_args.kwargs["params"]["cmds"].endswith(
                " all group datacenter"
            )
        )

    @patch("requests.Session.get")
    def test_nothing_reported_is_none(self, session_mock: MagicMock):
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        self.assertIsNone(api.get_ups_output_source())


class LiebertBatteryTestTest(unittest.TestCase):
    @patch("requests.Session.get")
    def test_defaults_to_failures_only(self, session_mock: MagicMock):
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        api.get_liebert_battery_test()
        self.assertEqual(
            session_mock.call_args.kwargs["params"]["cmds"],
            "mget * * battery LIEBERT-GP-POWER-MIB.lgpPwrBatteryTestResult "
            "value /failed/",
        )

    @patch("requests.Session.get")
    def test_no_results_filter_returns_every_test(self, session_mock: MagicMock):
        session_mock.return_value.text = BATTERY_TEST

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        devices = api.get_liebert_battery_test(results=None)
        self.assertEqual(
            session_mock.call_args.kwargs["params"]["cmds"],
            "mget * * battery LIEBERT-GP-POWER-MIB.lgpPwrBatteryTestResult",
        )
        self.assertEqual(len(devices), 2)
        self.assertEqual(devices["192.0.2.121"]["value"], "passed")
        self.assertEqual(devices["192.0.2.128"]["child"], "battery")

    @patch("requests.Session.get")
    def test_another_vendor_attribute_can_be_given(self, session_mock: MagicMock):
        # The Liebert attribute is a default, not a limit.  A fleet from
        # another vendor should be able to ask rather than get an empty
        # result and read it as good news.
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        api.get_liebert_battery_test(
            attribute="PowerNet-MIB.upsAdvBatteryReplaceIndicator"
        )
        self.assertIn(
            "PowerNet-MIB.upsAdvBatteryReplaceIndicator",
            session_mock.call_args.kwargs["params"]["cmds"],
        )


class EnumAttributeParsingTest(unittest.TestCase):
    @patch("requests.Session.get")
    def test_a_value_that_is_not_an_enum_is_reported_not_dropped(
        self, session_mock: MagicMock
    ):
        # One device reporting something unexpected must not cost the answer
        # for every other device, nor vanish without trace
        session_mock.return_value.text = (
            "ups-1 ups UPS-MIB.upsOutputSource = 4,bypass,1469649711,1782896221,\n"
            "ups-2 ups UPS-MIB.upsOutputSource = not-an-enum\n"
        )

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        with self.assertLogs("akips", level="WARNING") as logged:
            devices = api.get_ups_output_source()
        self.assertEqual(list(devices), ["ups-1"])
        self.assertIn("Could not parse 1 of 2", logged.output[0])
        self.assertIn("ups-2", logged.output[0])

    @patch("requests.Session.get")
    def test_a_device_reporting_on_two_children_is_reported(
        self, session_mock: MagicMock
    ):
        # The result is keyed by device, so a second child would otherwise be
        # silently discarded
        session_mock.return_value.text = (
            "ups-1 ups UPS-MIB.upsOutputSource = 4,bypass,1469649711,1782896221,\n"
            "ups-1 ups2 UPS-MIB.upsOutputSource = 3,battery,1469649711,1782896221,\n"
        )

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        with self.assertLogs("akips", level="WARNING") as logged:
            devices = api.get_ups_output_source()
        self.assertEqual(devices["ups-1"]["child"], "ups")
        self.assertIn("more than one child", logged.output[0])

    @patch("requests.Session.get")
    def test_an_attribute_with_no_value_is_skipped(self, session_mock: MagicMock):
        # A device that reports the attribute but no value for it is not an
        # unreadable enum, it simply has nothing to say
        session_mock.return_value.text = (
            "ups-1 ups UPS-MIB.upsOutputSource = 4,bypass,1469649711,1782896221,\n"
            "ups-2 ups UPS-MIB.upsOutputSource =\n"
        )

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        logger = logging.getLogger("akips")
        with patch.object(logger, "warning") as warn:
            devices = api.get_ups_output_source()
        self.assertEqual(list(devices), ["ups-1"])
        warn.assert_not_called()


class UpsBatteryStatusTest(unittest.TestCase):
    @patch("requests.Session.get")
    def test_defaults_to_the_states_worth_looking_at(self, session_mock: MagicMock):
        session_mock.return_value.text = (
            "192.0.2.24 battery UPS-MIB.upsBatteryStatus "
            "= 3,batteryLow,1469649711,1785575463,\n"
        )

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        devices = api.get_ups_battery_status()
        self.assertEqual(
            session_mock.call_args.kwargs["params"]["cmds"],
            "mget * * battery UPS-MIB.upsBatteryStatus "
            "value /unknown|batteryLow|batteryDepleted/",
        )
        entry = devices["192.0.2.24"]
        self.assertEqual(entry["value"], "batteryLow")
        self.assertEqual(entry["child"], "battery")

    @patch("requests.Session.get")
    def test_no_states_means_every_ups(self, session_mock: MagicMock):
        # Taken from an AKiPS command console
        session_mock.return_value.text = (
            "192.0.2.24 battery UPS-MIB.upsBatteryStatus "
            "= 2,batteryNormal,1469649711,1469649711,\n"
        )

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        devices = api.get_ups_battery_status(states=None)
        self.assertEqual(
            session_mock.call_args.kwargs["params"]["cmds"],
            "mget * * battery UPS-MIB.upsBatteryStatus",
        )
        self.assertEqual(devices["192.0.2.24"]["value"], "batteryNormal")

    @patch("requests.Session.get")
    def test_it_is_separate_from_the_output_source(self, session_mock: MagicMock):
        # A UPS can be on battery while its battery reports normal, and can
        # have a failing battery while running on mains, so these are two
        # questions rather than one
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        api.get_ups_battery_status()
        battery = session_mock.call_args.kwargs["params"]["cmds"]
        api.get_ups_output_source()
        source = session_mock.call_args.kwargs["params"]["cmds"]
        self.assertIn("UPS-MIB.upsBatteryStatus", battery)
        self.assertIn("UPS-MIB.upsOutputSource", source)
        self.assertNotEqual(battery, source)
