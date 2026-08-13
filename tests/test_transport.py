"""
Tests for the shared request handling every call passes through.
"""

import unittest
import warnings
from unittest.mock import MagicMock, patch

import requests
import traceback
import urllib3

from akips import AKIPS, AkipsError
from akips.exceptions import AkipsAuthenticationError, AkipsSectionDisabledError


class TransportTest(unittest.TestCase):
    @patch("requests.Session.post")
    def test_akips_error(self, session_mock: MagicMock):
        r_text = "ERROR: api-db invalid username/password"

        session_mock.return_value.ok = True
        session_mock.return_value.status_code = 200
        session_mock.return_value.text = r_text
        self.assertIsInstance(session_mock, MagicMock)

        api = AKIPS("127.0.0.1", ro_password="ro-secret")

        self.assertFalse(session_mock.called)
        self.assertRaises(AkipsError, api.get_devices)
        self.assertTrue(session_mock.called)

    @patch("requests.Session.post")
    def test_http_error_propagates(self, session_mock: MagicMock):
        session_mock.return_value.raise_for_status.side_effect = (
            requests.exceptions.HTTPError("500 Server Error")
        )

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        with self.assertRaises(requests.exceptions.HTTPError):
            api.get_devices()

    @patch("requests.Session.post")
    def test_connection_error_propagates(self, session_mock: MagicMock):
        session_mock.side_effect = requests.exceptions.ConnectionError("refused")

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        with self.assertRaises(requests.exceptions.ConnectionError):
            api.get_devices()

    @patch("requests.Session.post")
    def test_timeout_propagates(self, session_mock: MagicMock):
        session_mock.side_effect = requests.exceptions.Timeout("timed out")

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        with self.assertRaises(requests.exceptions.Timeout):
            api.get_devices()

    @patch("requests.Session.post")
    def test_request_exception_propagates(self, session_mock: MagicMock):
        session_mock.side_effect = requests.exceptions.RequestException("broken")

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        with self.assertRaises(requests.exceptions.RequestException):
            api.get_devices()

    @patch("requests.Session.post")
    def test_request_carries_credentials_and_timeout(self, session_mock: MagicMock):
        session_mock.return_value.text = ""

        api = AKIPS("akips.example.com", username="api-rw", password="secret")
        api.get_devices()
        args, kwargs = session_mock.call_args
        self.assertEqual(args[0], "https://akips.example.com/api-db")
        self.assertEqual(kwargs["params"]["username"], "api-rw")
        # The password goes in the body, never the query string, so that it
        # cannot reach anything that records a URL
        self.assertNotIn("password", kwargs["params"])
        self.assertEqual(kwargs["data"], {"password": "secret"})
        self.assertEqual(kwargs["timeout"], 30)
        self.assertTrue(kwargs["verify"])

    @patch("requests.Session.post")
    def test_verify_false_is_passed_through(self, session_mock: MagicMock):
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", ro_password="ro-secret", verify=False)
        api.get_devices()
        self.assertFalse(session_mock.call_args.kwargs["verify"])

    def test_redaction_hides_sensitive_values(self):
        api = AKIPS("127.0.0.1", password="secret")
        redacted = api._redact_sensitive_params(
            {
                "username": "api-ro",
                "password": "secret",
                "SNMP.community": "private",
                "cmds": "mget * * * *",
            }
        )
        self.assertEqual(redacted["password"], "****")
        self.assertEqual(redacted["SNMP.community"], "****")
        self.assertEqual(redacted["username"], "api-ro")
        self.assertEqual(redacted["cmds"], "mget * * * *")

    def test_parse_enum(self):
        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        entry = api._parse_enum("8,full,1581605551,1706545348,core-uplink")
        self.assertEqual(entry["number"], "8")
        self.assertEqual(entry["value"], "full")
        self.assertEqual(entry["description"], "core-uplink")
        self.assertEqual(entry["created"].year, 2020)
        self.assertEqual(entry["modified"].year, 2024)

    def test_parse_enum_with_empty_description(self):
        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        entry = api._parse_enum("2,up,1581605551,1706545348,")
        self.assertEqual(entry["value"], "up")
        self.assertEqual(entry["description"], "")

    def test_parse_enum_rejects_other_values(self):
        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        with self.assertRaises(AkipsError):
            api._parse_enum("not an enum value")

    def test_parse_enum_with_spaces_in_description(self):
        # Child descriptions routinely contain spaces, e.g. "Ethernet 1", so
        # the trailing field takes the rest of the line
        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        entry = api._parse_enum("8,full,1581605551,1706545348,uplink to core")
        self.assertEqual(entry["value"], "full")
        self.assertEqual(entry["description"], "uplink to core")

    @patch("requests.Session.post")
    def test_get_does_not_mutate_the_callers_params(self, session_mock: MagicMock):
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", password="secret")
        caller_params = {"cmds": "mget * * * *"}
        api._get(params=caller_params)
        # Credentials belong on the request, not in the dictionary the caller
        # still holds and may log or reuse
        self.assertEqual(caller_params, {"cmds": "mget * * * *"})
        self.assertEqual(session_mock.call_args.kwargs["data"], {"password": "secret"})

    @patch("requests.Session.post")
    def test_get_accepts_no_params(self, session_mock: MagicMock):
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        # params is documented as optional, so omitting it must not raise
        self.assertEqual(api._get(section="api-db"), "")
        self.assertIn("username", session_mock.call_args.kwargs["params"])

    @patch("requests.Session.post")
    def test_verify_true_leaves_the_warning_filter_alone(self, session_mock: MagicMock):
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        before = list(warnings.filters)
        api.get_devices()
        self.assertEqual(list(warnings.filters), before)

    @patch("requests.Session.post")
    def test_verify_false_restores_the_warning_filter(self, session_mock: MagicMock):
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", ro_password="ro-secret", verify=False)
        before = list(warnings.filters)
        api.get_devices()
        # Suppression is scoped to the request; constructing a client with
        # verify=False must not silence urllib3 for the whole process
        self.assertEqual(list(warnings.filters), before)

    @patch("requests.Session.post")
    def test_default_timeout_is_thirty_seconds(self, session_mock: MagicMock):
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        api.get_devices()
        self.assertEqual(session_mock.call_args.kwargs["timeout"], 30)

    @patch("requests.Session.post")
    def test_timeout_is_configurable_at_construction(self, session_mock: MagicMock):
        session_mock.return_value.text = ""

        api = AKIPS(
            "127.0.0.1", ro_password="ro-secret", rw_password="rw-secret", timeout=5
        )
        # applies to every section, not just api-db
        api.get_devices()
        self.assertEqual(session_mock.call_args.kwargs["timeout"], 5)
        api.get_msg()
        self.assertEqual(session_mock.call_args.kwargs["timeout"], 5)
        api.get_device_by_ip(ipaddr="192.0.2.101")
        self.assertEqual(session_mock.call_args.kwargs["timeout"], 5)
        api.get_group_availability()
        self.assertEqual(session_mock.call_args.kwargs["timeout"], 5)

    @patch("requests.Session.post")
    def test_timeout_can_be_changed_on_an_existing_client(
        self, session_mock: MagicMock
    ):
        session_mock.return_value.text = ""

        api = AKIPS("127.0.0.1", ro_password="ro-secret")
        api.get_devices()
        self.assertEqual(session_mock.call_args.kwargs["timeout"], 30)
        api.timeout = 120
        api.get_devices()
        self.assertEqual(session_mock.call_args.kwargs["timeout"], 120)

    @patch("requests.Session.post")
    def test_request_failures_do_not_leak_the_password(self, session_mock: MagicMock):
        # AKiPS authenticates by query string and requests reports the URL it
        # was fetching, so an unscrubbed exception carries the password into
        # the log and into any traceback the caller renders
        secret = "SuperSecret123"
        message = (
            "HTTPSConnectionPool(host='akips.example.com', port=443): "
            "Max retries exceeded with url: "
            f"/api-db?cmds=mget&username=api-ro&password={secret}"
        )
        session_mock.side_effect = requests.exceptions.ConnectionError(message)

        api = AKIPS("akips.example.com", ro_password=secret)
        with self.assertLogs("akips", level="ERROR") as logged:
            with self.assertRaises(requests.exceptions.ConnectionError) as caught:
                api.get_devices()

        self.assertNotIn(secret, "\n".join(logged.output))
        self.assertNotIn(secret, str(caught.exception))
        self.assertIn("password=****", str(caught.exception))
        # the exception type survives scrubbing, so existing handlers still work
        self.assertIsInstance(caught.exception, requests.exceptions.ConnectionError)

    @patch("requests.Session.post")
    def test_a_url_encoded_password_is_scrubbed_too(self, session_mock: MagicMock):
        # requests percent encodes the query, so the literal password does not
        # appear; matching on the parameter catches it whatever it looks like
        secret = "p@ss word/99"
        session_mock.side_effect = requests.exceptions.ConnectionError(
            "Max retries exceeded with url: /api-db?password=p%40ss+word%2F99&cmds=x"
        )

        api = AKIPS("akips.example.com", ro_password=secret)
        with self.assertLogs("akips", level="ERROR") as logged:
            with self.assertRaises(requests.exceptions.ConnectionError):
                api.get_devices()
        self.assertNotIn("p%40ss", "\n".join(logged.output))
        self.assertIn("password=****", "\n".join(logged.output))

    @patch("requests.Session.post")
    def test_an_error_with_no_credentials_is_left_intact(self, session_mock: MagicMock):
        # Nothing to scrub means the exception keeps its original structure
        session_mock.side_effect = requests.exceptions.Timeout("timed out")

        api = AKIPS("akips.example.com", ro_password="secret")
        with self.assertLogs("akips", level="ERROR"):
            with self.assertRaises(requests.exceptions.Timeout) as caught:
                api.get_devices()
        self.assertEqual(str(caught.exception), "timed out")

    @patch("requests.Session.post")
    def test_the_whole_exception_chain_is_scrubbed(self, session_mock: MagicMock):
        # requests raises its error from the urllib3 one that caused it, and
        # that inner exception holds the same URL.  Anything rendering a full
        # traceback renders the chain, which is where tracebacks get stored.
        secret = "SuperSecret123"
        inner = urllib3.exceptions.HTTPError(
            f"Max retries exceeded with url: /api-db?password={secret}"
        )
        inner.url = f"/api-db?password={secret}"
        outer = requests.exceptions.ConnectionError(
            f"HTTPSConnectionPool: url: /api-db?password={secret}"
        )
        outer.__cause__ = inner
        session_mock.side_effect = outer

        api = AKIPS("akips.example.com", ro_password=secret)
        with self.assertLogs("akips", level="ERROR"):
            with self.assertRaises(requests.exceptions.ConnectionError) as caught:
                api.get_devices()

        err = caught.exception
        rendered = "".join(
            traceback.format_exception(type(err), err, err.__traceback__)
        )
        self.assertNotIn(secret, rendered)
        # the inner exception is reached, message and url attribute both
        self.assertNotIn(secret, str(err.__cause__))
        self.assertNotIn(secret, err.__cause__.url)

    @patch("requests.Session.post")
    def test_the_response_url_on_an_http_error_is_scrubbed(
        self, session_mock: MagicMock
    ):
        # Error reporters read response.url separately from the message
        secret = "SuperSecret123"
        response = requests.Response()
        response.status_code = 500
        response.url = f"https://akips.example.com/api-db?password={secret}"
        response.reason = "Server Error"
        session_mock.return_value = response

        api = AKIPS("akips.example.com", ro_password=secret)
        with self.assertLogs("akips", level="ERROR"):
            with self.assertRaises(requests.exceptions.HTTPError) as caught:
                api.get_devices()
        self.assertNotIn(secret, str(caught.exception))
        self.assertNotIn(secret, caught.exception.response.url)

    @patch("requests.Session.post")
    def test_an_error_reply_body_is_redacted_without_mangling_data(
        self, session_mock: MagicMock
    ):
        # The query parameter form is removed from the body, but the password
        # is never replaced as a literal there: a short one would rewrite
        # matching characters anywhere in a device reply
        session_mock.return_value.text = (
            "ERROR: api-db rejected ?username=api-ro&password=up for up"
        )

        api = AKIPS("akips.example.com", ro_password="up")
        with self.assertRaises(AkipsError) as caught:
            api.get_devices()
        self.assertIn("password=****", str(caught.exception))
        # the trailing 'up' is data, not a credential, and survives
        self.assertTrue(str(caught.exception).endswith("for up"))

    @patch("requests.Session.post")
    def test_verify_accepts_a_ca_bundle_path(self, session_mock: MagicMock):
        # A server missing an intermediate can be trusted with its own bundle
        # rather than by turning verification off
        session_mock.return_value.text = ""

        api = AKIPS("akips.example.com", ro_password="secret", verify="/etc/ca.pem")
        api.get_devices()
        self.assertEqual(session_mock.call_args.kwargs["verify"], "/etc/ca.pem")

    @patch("requests.Session.post")
    def test_scrubbing_never_masks_the_original_failure(self, session_mock: MagicMock):
        # Some exception could expose url as a read only property.  Scrubbing
        # must not turn that into an AttributeError raised in place of the
        # error the caller was about to receive.
        class StubbornError(requests.exceptions.ConnectionError):
            @property
            def url(self):  # type: ignore[override]
                return "/api-db?password=SuperSecret123"

        class StubbornResponse:
            @property
            def url(self):
                return "/api-db?password=SuperSecret123"

        err = StubbornError("connection failed for /api-db?password=SuperSecret123")
        err.response = StubbornResponse()  # type: ignore[assignment]
        session_mock.side_effect = err

        api = AKIPS("akips.example.com", ro_password="SuperSecret123")
        with self.assertLogs("akips", level="ERROR"):
            with self.assertRaises(requests.exceptions.ConnectionError) as caught:
                api.get_devices()
        # the message is still scrubbed even though the attributes could not be
        self.assertNotIn("SuperSecret123", str(caught.exception))

    @patch("requests.Session.post")
    def test_snmp_credentials_are_not_logged(self, session_mock: MagicMock):
        # AKiPS keeps SNMP credentials as ordinary device attributes, so a
        # reply to something as innocent as get_device carries the community
        # string and the v3 auth and priv passwords
        session_mock.return_value.text = (
            "dev1 sys ip4addr = 192.0.2.101\n"
            "dev1 sys SNMP.community = not-a-real-community\n"
            "dev1 sys SNMP.auth_password = not-a-real-auth-password\n"
            "dev1 sys SNMP.priv_password = not-a-real-priv-password\n"
            "dev1 sys SNMPv2-MIB.sysName = ups-1\n"
        )

        api = AKIPS("akips.example.com", ro_password="secret")
        with self.assertLogs("akips", level="DEBUG") as logged:
            device = api.get_device("dev1")
        written = "\n".join(logged.output)

        for secret in (
            "not-a-real-community",
            "not-a-real-auth-password",
            "not-a-real-priv-password",
        ):
            self.assertNotIn(secret, written)
        # anything not a credential is still there to debug with
        self.assertIn("ups-1", written)
        # and the caller still gets what it asked for
        self.assertEqual(device["sys"]["SNMP.community"], "not-a-real-community")

    @patch("requests.Session.post")
    def test_a_parsed_device_is_not_dumped_into_the_log(self, session_mock: MagicMock):
        # get_device used to log the whole parsed structure, which is how the
        # credentials reached the log even once the reply itself was filtered
        session_mock.return_value.text = "dev1 sys SNMP.community = secret-string\n"

        api = AKIPS("akips.example.com", ro_password="secret")
        with self.assertLogs("akips", level="DEBUG") as logged:
            api.get_device("dev1")
        self.assertNotIn("secret-string", "\n".join(logged.output))


class RequestMethodTest(unittest.TestCase):
    """The password travels in a POST body unless a caller opts out."""

    @patch("requests.Session.get")
    @patch("requests.Session.post")
    def test_post_is_the_default(self, post_mock: MagicMock, get_mock: MagicMock):
        post_mock.return_value.text = ""

        api = AKIPS("akips.example.com", ro_password="ro-secret")
        api.get_devices()

        self.assertTrue(post_mock.called)
        self.assertFalse(get_mock.called)

    @patch("requests.Session.get")
    @patch("requests.Session.post")
    def test_the_password_never_reaches_the_query_string(
        self, post_mock: MagicMock, get_mock: MagicMock
    ):
        # The point of the whole exercise.  A URL reaches access logs,
        # exception messages and client history; a request body does not
        post_mock.return_value.text = ""

        api = AKIPS("akips.example.com", ro_password="ro-secret")
        api.get_devices()

        kwargs = post_mock.call_args.kwargs
        self.assertNotIn("password", kwargs["params"])
        self.assertEqual(kwargs["data"], {"password": "ro-secret"})
        self.assertNotIn("ro-secret", str(kwargs["params"]))

    @patch("requests.Session.get")
    @patch("requests.Session.post")
    def test_use_post_false_sends_the_old_get_form(
        self, post_mock: MagicMock, get_mock: MagicMock
    ):
        get_mock.return_value.text = ""

        api = AKIPS("akips.example.com", ro_password="ro-secret", use_post=False)
        api.get_devices()

        self.assertTrue(get_mock.called)
        self.assertFalse(post_mock.called)
        kwargs = get_mock.call_args.kwargs
        self.assertEqual(kwargs["params"]["password"], "ro-secret")
        # A GET carries no body, and sending one anyway would be a way for the
        # password to travel twice
        self.assertNotIn("data", kwargs)

    @patch("requests.Session.post")
    def test_the_password_is_not_logged_in_either_form(self, session_mock: MagicMock):
        session_mock.return_value.text = ""

        api = AKIPS("akips.example.com", ro_password="ro-secret")
        with self.assertLogs("akips", level="DEBUG") as logged:
            api.get_devices()
        self.assertNotIn("ro-secret", "\n".join(logged.output))


class ErrorClassificationTest(unittest.TestCase):
    """AKiPS reports two failures that are nothing to do with the call."""

    def _raises(self, reply: str, expected: type[BaseException]):
        with patch("requests.Session.post") as session_mock:
            session_mock.return_value.text = reply
            api = AKIPS("akips.example.com", ro_password="ro-secret")
            with self.assertRaises(expected) as caught:
                api.get_devices()
        return caught.exception

    def test_rejected_credentials_are_named(self):
        error = self._raises(
            "ERROR: api-db invalid username/password", AkipsAuthenticationError
        )
        self.assertIn("invalid username/password", str(error))

    def test_a_disabled_section_is_named(self):
        error = self._raises(
            "ERROR: api-flow access is turned off", AkipsSectionDisabledError
        )
        self.assertIn("turned off", str(error))

    def test_both_are_still_akips_errors(self):
        # Callers written against 1.0.0 catch AkipsError, and must keep working
        self._raises("ERROR: api-db invalid username/password", AkipsError)
        self._raises("ERROR: api-flow access is turned off", AkipsError)

    def test_an_unrecognized_error_stays_generic(self):
        # The wording is undocumented, so anything unfamiliar must fall
        # through rather than be forced into one of the two categories
        error = self._raises("ERROR: Function doesn't exist", AkipsError)
        self.assertNotIsInstance(error, AkipsAuthenticationError)
        self.assertNotIsInstance(error, AkipsSectionDisabledError)

    def test_the_section_name_is_not_required_to_match(self):
        # AKiPS prefixes the section today, but that is not documented and the
        # match must not depend on it
        self._raises("ERROR: invalid username/password", AkipsAuthenticationError)
        self._raises("ERROR: access is turned off", AkipsSectionDisabledError)

    def test_the_disabled_section_is_carried_as_an_attribute(self):
        # Consumers should not have to match on AKiPS's wording to find out
        # which section was refused
        error = self._raises(
            "ERROR: api-db access is turned off", AkipsSectionDisabledError
        )
        self.assertEqual(error.section, "api-db")

    def test_the_section_comes_from_the_request_not_the_message(self):
        # Taken from what was asked for, so it stays right even if AKiPS
        # rewords the reply or stops naming the section in it
        with patch("requests.Session.post") as session_mock:
            session_mock.return_value.text = "ERROR: access is turned off"
            api = AKIPS("akips.example.com", ro_password="ro-secret")
            with self.assertRaises(AkipsSectionDisabledError) as caught:
                api.call("stat *", section="api-flow")
        self.assertEqual(caught.exception.section, "api-flow")

    def test_the_refused_account_is_carried_as_an_attribute(self):
        error = self._raises(
            "ERROR: api-db invalid username/password", AkipsAuthenticationError
        )
        self.assertEqual(error.section, "api-db")
        self.assertEqual(error.username, "api-ro")

    def test_the_rw_account_is_named_when_a_write_section_refuses(self):
        # A section needing api-rw and given api-ro fails here rather than
        # anywhere more obvious, so the account is the useful half
        with patch("requests.Session.post") as session_mock:
            session_mock.return_value.text = (
                "ERROR: api-script invalid username/password"
            )
            api = AKIPS("akips.example.com", rw_password="rw-secret")
            with self.assertRaises(AkipsAuthenticationError) as caught:
                api.set_group_membership("dev1", "maintenance_mode", "assign")
        self.assertEqual(caught.exception.section, "api-script")
        self.assertEqual(caught.exception.username, "api-rw")

    def test_the_attributes_default_to_none(self):
        # Constructible without them, so nothing that raises these by hand breaks
        self.assertIsNone(AkipsSectionDisabledError().section)
        self.assertIsNone(AkipsAuthenticationError().section)
        self.assertIsNone(AkipsAuthenticationError().username)
