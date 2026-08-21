"""
Tests for choosing which AKiPS account a request authenticates as.

AKiPS ships two API accounts and its sections do not all accept the same one,
so the client holds both passwords and picks per section.
"""

import unittest
from unittest.mock import MagicMock, patch

from akips import AKIPS
from akips.exceptions import AkipsCredentialError, AkipsError


class CredentialTest(unittest.TestCase):
    @patch("requests.Session.get")
    @patch("requests.Session.post")
    def sent(self, api, call, post_mock: MagicMock, get_mock: MagicMock):
        """Run a call and return the credentials that reached the request."""
        post_mock.return_value.text = ""
        get_mock.return_value.text = ""
        call(api)
        # Which verb carried it depends on the section: api-script cannot
        # take a POST, so its password is in the query string instead.
        mock = post_mock if post_mock.called else get_mock
        kwargs = mock.call_args.kwargs
        username = kwargs["params"]["username"]
        if kwargs.get("data"):
            return username, kwargs["data"]["password"]
        return username, kwargs["params"]["password"]

    def test_read_only_sections_use_the_ro_account(self):
        api = AKIPS("127.0.0.1", ro_password="ro-secret", rw_password="rw-secret")
        self.assertEqual(self.sent(api, lambda a: a.get_msg()), ("api-ro", "ro-secret"))

    def test_site_script_sections_use_the_rw_account(self):
        api = AKIPS("127.0.0.1", ro_password="ro-secret", rw_password="rw-secret")
        self.assertEqual(
            self.sent(api, lambda a: a.set_group_membership("d", "g", "assign")),
            ("api-rw", "rw-secret"),
        )
        self.assertEqual(
            self.sent(api, lambda a: a.get_device_by_ip(ipaddr="192.0.2.101")),
            ("api-rw", "rw-secret"),
        )

    def test_either_sections_prefer_the_lesser_privileged_account(self):
        api = AKIPS("127.0.0.1", ro_password="ro-secret", rw_password="rw-secret")
        self.assertEqual(
            self.sent(api, lambda a: a.get_devices()), ("api-ro", "ro-secret")
        )

    def test_either_sections_fall_back_to_rw_when_that_is_all_there_is(self):
        api = AKIPS("127.0.0.1", rw_password="rw-secret")
        self.assertEqual(
            self.sent(api, lambda a: a.get_devices()), ("api-rw", "rw-secret")
        )

    @patch("requests.Session.post")
    def test_a_section_needing_an_account_without_a_password_says_so(
        self, session_mock: MagicMock
    ):
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        with self.assertRaises(AkipsCredentialError) as caught:
            api.set_group_membership("device", "group", "assign")
        message = str(caught.exception)
        self.assertIn("api-script", message)
        self.assertIn("api-rw", message)
        self.assertIn("rw_password", message)
        # and it fails before reaching the server
        self.assertFalse(session_mock.called)

    def test_construction_without_any_password_is_refused(self):
        with self.assertRaises(AkipsCredentialError) as caught:
            AKIPS("127.0.0.1")
        self.assertIn("ro_password", str(caught.exception))

    def test_credential_errors_can_be_caught_three_ways(self):
        # Specifically, as anything this library raises, or as the ValueError
        # a bad argument has always been, so existing handlers keep working
        for expected in (AkipsCredentialError, AkipsError, ValueError):
            with self.assertRaises(expected):
                AKIPS("127.0.0.1")

    def test_an_unknown_account_is_a_plain_bad_argument(self):
        # Not a credential problem: nothing is missing, the caller asked for
        # an account that does not exist
        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        with self.assertRaises(ValueError) as caught:
            api.call("mget * * * *", user="admin")
        self.assertNotIsInstance(caught.exception, AkipsCredentialError)

    def test_legacy_username_and_password_fill_the_matching_account(self):
        api = AKIPS("127.0.0.1", username="api-ro", password="secret")
        self.assertEqual(api.ro_password, "secret")
        self.assertEqual(self.sent(api, lambda a: a.get_msg()), ("api-ro", "secret"))

        api = AKIPS("127.0.0.1", username="api-rw", password="secret")
        self.assertEqual(api.rw_password, "secret")
        self.assertEqual(
            self.sent(api, lambda a: a.get_device_by_ip(ipaddr="192.0.2.101")),
            ("api-rw", "secret"),
        )

    def test_a_custom_username_is_used_for_every_section(self):
        # AKiPS has no custom API accounts yet; this is the path for when it
        # does, and for anyone already passing their own username
        api = AKIPS("127.0.0.1", username="monitoring", password="secret")
        for call in (
            lambda a: a.get_devices(),
            lambda a: a.get_msg(),
            lambda a: a.get_device_by_ip(ipaddr="192.0.2.101"),
            lambda a: a.get_group_availability(),
        ):
            self.assertEqual(self.sent(api, call), ("monitoring", "secret"))

    def test_call_can_force_an_account(self):
        api = AKIPS("127.0.0.1", ro_password="ro-secret", rw_password="rw-secret")
        # a section not in the table gets the preferred account by default
        self.assertEqual(
            self.sent(api, lambda a: a.call(section="api-spm", params={"a": "b"})),
            ("api-ro", "ro-secret"),
        )
        # unless the caller knows it needs more rights
        self.assertEqual(
            self.sent(
                api,
                lambda a: a.call(section="api-spm", params={"a": "b"}, user="rw"),
            ),
            ("api-rw", "rw-secret"),
        )

    @patch("requests.Session.post")
    def test_call_rejects_an_unknown_account(self, session_mock: MagicMock):
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        with self.assertRaises(ValueError):
            api.call("mget * * * *", user="admin")
        self.assertFalse(session_mock.called)

    def test_the_section_table_matches_the_akips_documentation(self):
        # Taken from the server's own Web API settings page rather than
        # inferred.  Every section takes api-ro except api-script, which
        # requires api-rw, and api-db, which takes either.
        self.assertEqual(
            AKIPS.SECTION_USERS,
            {
                "api-availability": "api-ro",
                "api-config-viewer": "api-ro",
                "api-db": None,
                "api-flow": "api-ro",
                "api-flow-timeseries": "api-ro",
                "api-http-log": "api-ro",
                "api-msg": "api-ro",
                "api-script": "api-rw",
                "api-spm": "api-ro",
                "api-unused-interfaces": "api-ro",
            },
        )

    @patch("requests.Session.post")
    def test_a_read_write_only_client_is_told_what_it_needs(
        self, session_mock: MagicMock
    ):
        # Only api-db and api-script accept api-rw, so a client holding just
        # that password cannot reach the rest.  Saying so beforehand beats
        # letting AKiPS reject the request.
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", rw_password="rw-secret")
        with self.assertRaises(AkipsCredentialError) as caught:
            api.get_group_availability()
        self.assertIn("api-availability", str(caught.exception))
        self.assertIn("ro_password", str(caught.exception))
        self.assertFalse(session_mock.called)
        # api-db and api-script still work on the rw password alone
        api.get_devices()
        self.assertEqual(session_mock.call_args.kwargs["params"]["username"], "api-rw")
