"""
Every method answers 'nothing found' the same way, with None.

AKiPS normally sends an empty body when nothing matches, which every method
already turned into None.  A reply with content that parses to no rows is the
awkward case: it used to give an empty dict or list from most methods and None
from get_device, so the promise each docstring makes was true on one path and
not the other.
"""

import unittest
import warnings
from unittest.mock import MagicMock, patch

from akips import AKIPS

# Content that yields no parseable rows, such as a status line on its own.
NOTHING_PARSEABLE = "ok: some command that matched nothing\n"


class NothingFoundTest(unittest.TestCase):
    def setUp(self):
        self.api = AKIPS("127.0.0.1", ro_password="ro-secret", rw_password="rw-secret")
        # get_msg and get_unreachable warn about lines they cannot read, which
        # is the point of them and not what is under test here
        warnings.simplefilter("ignore")

    def _all_calls(self):
        api = self.api
        return {
            "get_devices": lambda: api.get_devices(),
            "get_device": lambda: api.get_device("some-device"),
            "get_unreachable": lambda: api.get_unreachable(),
            "get_attributes": lambda: api.get_attributes(),
            "get_ups_battery_status": lambda: api.get_ups_battery_status(),
            "get_ups_output_source": lambda: api.get_ups_output_source(),
            "get_liebert_battery_test": lambda: api.get_liebert_battery_test(),
            "get_group_membership": lambda: api.get_group_membership(),
            "get_events": lambda: api.get_events(),
            "get_series": lambda: api.get_series(),
            "get_series_as_lists": lambda: api.get_series(get_dict=False),
            "get_latest_values": lambda: api.get_latest_values("SOME-MIB.thing"),
            "get_msg": lambda: api.get_msg(),
            "get_syslog": lambda: api.get_syslog(),
            "get_traps": lambda: api.get_traps(),
        }

    @patch("requests.Session.post")
    def test_an_empty_reply_is_none(self, session_mock: MagicMock):
        session_mock.return_value.text = ""
        for name, call in self._all_calls().items():
            with self.subTest(method=name):
                self.assertIsNone(call())

    @patch("requests.Session.post")
    def test_a_reply_that_parses_to_nothing_is_also_none(self, session_mock: MagicMock):
        # The case that used to differ.  An empty container here reads as
        # 'nothing to report' while the server actually said something this
        # module could not read, and it disagreed with the same method's
        # answer to an empty reply.
        session_mock.return_value.text = NOTHING_PARSEABLE
        with self.assertLogs("akips", level="WARNING"):
            for name, call in self._all_calls().items():
                with self.subTest(method=name):
                    self.assertIsNone(call())


class DeviceIsAttributesTest(unittest.TestCase):
    """
    get_device is get_attributes with the filters left alone, and calls it
    rather than building the same command twice.
    """

    REPLY = (
        "TH840-F cpu HOST-RESOURCES-MIB.hrProcessorLoad = 1\n"
        "TH840-F Ethernet1 IF-MIB.ifDescr = Ethernet 1\n"
    )

    @patch("requests.Session.post")
    def test_it_sends_the_same_command(self, session_mock: MagicMock):
        session_mock.return_value.text = self.REPLY
        api = AKIPS("127.0.0.1", ro_password="ro-secret")

        api.get_device("TH840-F")
        via_device = session_mock.call_args.kwargs["params"]["cmds"]
        api.get_attributes(device="TH840-F")
        via_attributes = session_mock.call_args.kwargs["params"]["cmds"]
        self.assertEqual(via_device, via_attributes)

    @patch("requests.Session.post")
    def test_it_returns_the_same_thing(self, session_mock: MagicMock):
        session_mock.return_value.text = self.REPLY
        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        self.assertEqual(
            api.get_device("TH840-F"),
            api.get_attributes(device="TH840-F")["TH840-F"],
        )

    @patch("requests.Session.post")
    def test_the_device_argument_is_named_device(self, session_mock: MagicMock):
        # It was 'name', the only method in the API not calling this 'device'
        session_mock.return_value.text = self.REPLY
        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        self.assertIsNotNone(api.get_device(device="TH840-F"))


class SeriesShapesAgreeTest(unittest.TestCase):
    REPLY = (
        "parent,child,child description,attribute,2024-02-21 09:10,2024-02-21 09:15\n"
        "ap-1,radio.1,,SOME-MIB.clients,4,5\n"
        "ap-2,radio.1,,SOME-MIB.clients,6,7\n"
    )

    @patch("requests.Session.post")
    def test_the_list_form_keeps_its_time_axis(self, session_mock: MagicMock):
        # The list form is one row longer, and that row is the point of it:
        # the column headings are the timestamps for the readings underneath.
        # The dictionary form does not need it separately because those
        # headings became its keys.
        api = AKIPS("127.0.0.1", ro_password="ro-secret")

        session_mock.return_value.text = self.REPLY
        as_lists = api.get_series(get_dict=False)
        session_mock.return_value.text = self.REPLY
        as_dicts = api.get_series(get_dict=True)

        self.assertEqual(len(as_lists), len(as_dicts) + 1)
        self.assertEqual(as_lists[0][4], "2024-02-21 09:10")
        self.assertEqual(as_lists[1][0], "ap-1")
        self.assertEqual(as_dicts[0]["parent"], "ap-1")
        # both forms can put a reading against the time it was taken
        self.assertEqual(as_lists[1][4], as_dicts[0]["2024-02-21 09:10"])

    @patch("requests.Session.post")
    def test_a_header_with_no_data_rows_is_nothing_found(self, session_mock: MagicMock):
        # Dropping the header can empty the list form, and an empty list is
        # not the answer this module gives for nothing found
        session_mock.return_value.text = (
            "parent,child,child description,attribute,2024-02-21 09:10\n"
        )
        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        self.assertIsNone(api.get_series(get_dict=False))
        self.assertIsNone(api.get_series(get_dict=True))
