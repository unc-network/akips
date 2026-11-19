"""Application bearer authentication, based on the AKiPS 26.6 API guide."""

import traceback
import unittest
from unittest.mock import MagicMock, patch

import requests

from akips import AKIPS
from akips.exceptions import AkipsAuthenticationError, AkipsCredentialError, AkipsError

# Invented values with the documented 64 hexadecimal character shape.
TOKEN = "a" * 64
OTHER_TOKEN = "b" * 64


class TokenConfigurationTest(unittest.TestCase):
    def test_token_alone_constructs_a_client(self):
        api = AKIPS("akips.example.com", token=TOKEN)
        self.assertEqual(api.token, TOKEN)

    def test_unusable_tokens_are_configuration_errors(self):
        for token in ("", " ", "fake token", "fake\r\ntoken"):
            with self.subTest(token=repr(token)):
                with self.assertRaises(AkipsCredentialError):
                    AKIPS("akips.example.com", token=token)

    def test_token_and_legacy_credentials_cannot_be_combined(self):
        for credentials in (
            {"password": "fake-password"},
            {"ro_password": "fake-ro"},
            {"rw_password": "fake-rw"},
            {"username": "api-rw"},
            {"username": "custom-account"},
        ):
            with self.subTest(credentials=credentials):
                with self.assertRaises(ValueError):
                    AKIPS("akips.example.com", token=TOKEN, **credentials)


class TokenRequestTest(unittest.TestCase):
    @patch(
        "requests.sessions.get_netrc_auth", return_value=("fake-user", "fake-password")
    )
    @patch("requests.Session.send")
    def test_requests_cannot_override_the_bearer_header_with_other_auth(
        self, send_mock: MagicMock, netrc_mock: MagicMock
    ):
        response = requests.Response()
        response.status_code = 200
        response._content = b""
        send_mock.return_value = response
        for session_auth in (None, ("fake-user", "fake-password")):
            with self.subTest(session_auth=session_auth):
                api = AKIPS("akips.example.com", token=TOKEN)
                api.session.auth = session_auth
                api.get_devices()
                request = send_mock.call_args.args[0]
                self.assertEqual(request.headers["Authorization"], f"Bearer {TOKEN}")
                self.assertNotIn(TOKEN, request.url)
                self.assertIsNone(request.body)

    @patch("requests.Session.post")
    @patch("requests.Session.get")
    def test_every_section_uses_the_header_and_documented_get_form(
        self, get_mock: MagicMock, post_mock: MagicMock
    ):
        get_mock.return_value.text = ""
        api = AKIPS("akips.example.com", token=TOKEN, timeout=11, verify="/fake/ca.pem")
        for section in AKIPS.SECTION_USERS:
            with self.subTest(section=section):
                params = {"probe": "value"}
                api.call(section=section, params=params)
                args, kwargs = get_mock.call_args
                self.assertEqual(args[0], f"https://akips.example.com/{section}")
                self.assertEqual(
                    kwargs["headers"], {"Authorization": f"Bearer {TOKEN}"}
                )
                self.assertEqual(kwargs["params"], params)
                self.assertNotIn("data", kwargs)
                self.assertEqual(kwargs["timeout"], 11)
                self.assertEqual(kwargs["verify"], "/fake/ca.pem")
                self.assertEqual(params, {"probe": "value"})
        post_mock.assert_not_called()

    @patch("requests.Session.get")
    def test_legacy_get_setting_does_not_move_the_token_to_the_url(
        self, get_mock: MagicMock
    ):
        get_mock.return_value.text = ""
        api = AKIPS("akips.example.com", token=TOKEN, use_post=False)
        api.get_devices()
        self.assertEqual(
            get_mock.call_args.kwargs["headers"]["Authorization"], f"Bearer {TOKEN}"
        )
        self.assertNotIn(TOKEN, str(get_mock.call_args.kwargs["params"]))

    @patch("requests.Session.get")
    def test_unknown_sections_can_still_use_a_token(self, get_mock: MagicMock):
        get_mock.return_value.text = "ok"
        api = AKIPS("akips.example.com", token=TOKEN)
        with self.assertLogs("akips", level="WARNING"):
            self.assertEqual(api.call(section="api-future", params={}), "ok")
        self.assertEqual(
            get_mock.call_args.kwargs["headers"]["Authorization"], f"Bearer {TOKEN}"
        )

    @patch("requests.Session.get")
    def test_user_cannot_change_a_tokens_fixed_permissions(self, get_mock: MagicMock):
        api = AKIPS("akips.example.com", token=TOKEN)
        for user in ("ro", "rw", "admin"):
            with self.subTest(user=user):
                with self.assertRaises(ValueError):
                    api.call("mget * * * *", user=user)
        get_mock.assert_not_called()

    @patch("requests.Session.get")
    def test_params_cannot_add_a_second_authentication_method(
        self, get_mock: MagicMock
    ):
        api = AKIPS("akips.example.com", token=TOKEN)
        for name in ("username", "password", "tok"):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    api.call(params={name: "fake-value"})
        get_mock.assert_not_called()

    @patch("requests.Session.get")
    def test_rotating_the_token_updates_the_next_request(self, get_mock: MagicMock):
        get_mock.return_value.text = ""
        api = AKIPS("akips.example.com", token=TOKEN)
        api.get_devices()
        api.token = OTHER_TOKEN
        api.get_devices()
        headers = [call.kwargs["headers"] for call in get_mock.call_args_list]
        self.assertEqual(
            headers,
            [
                {"Authorization": f"Bearer {TOKEN}"},
                {"Authorization": f"Bearer {OTHER_TOKEN}"},
            ],
        )
        self.assertNotIn("Authorization", api.session.headers)

    @patch("requests.Session.get")
    def test_parsing_and_site_script_helpers_work_without_passwords(
        self, get_mock: MagicMock
    ):
        api = AKIPS("akips.example.com", token=TOKEN)
        get_mock.return_value.text = "dev1 sys SNMPv2-MIB.sysName = switch-1\n"
        self.assertEqual(
            api.get_device("dev1"), {"sys": {"SNMPv2-MIB.sysName": "switch-1"}}
        )
        get_mock.return_value.text = "IP Address 192.0.2.10 is configured on dev1\n"
        self.assertEqual(api.get_device_by_ip("192.0.2.10"), "dev1")
        get_mock.return_value.text = ""
        self.assertIsNone(
            api.set_group_membership("dev1", "maintenance_mode", "assign")
        )

    @patch("requests.Session.post")
    @patch("requests.Session.get")
    def test_delete_uses_token_for_both_checks_and_the_script(
        self, get_mock: MagicMock, post_mock: MagicMock
    ):
        get_mock.side_effect = [
            MagicMock(text="dev1 sys ip4addr = 192.0.2.10\n"),
            MagicMock(text=""),
            MagicMock(text=""),
        ]
        api = AKIPS("akips.example.com", token=TOKEN, timeout=12)
        self.assertTrue(api.delete_device("dev1"))
        self.assertEqual(
            [call.args[0].rsplit("/", 1)[1] for call in get_mock.call_args_list],
            ["api-db", "api-script", "api-db"],
        )
        self.assertEqual(
            [call.kwargs["timeout"] for call in get_mock.call_args_list],
            [12, api.SCRIPT_TIMEOUT, 12],
        )
        for call in get_mock.call_args_list:
            self.assertEqual(
                call.kwargs["headers"], {"Authorization": f"Bearer {TOKEN}"}
            )
            self.assertNotIn("password", call.kwargs["params"])
        post_mock.assert_not_called()


class TokenErrorTest(unittest.TestCase):
    @patch("requests.Session.get")
    def test_redaction_does_not_change_error_classification(self, get_mock: MagicMock):
        from akips.exceptions import AkipsPermissionError

        cases = (
            ("token", "Invalid token", AkipsAuthenticationError),
            ("access", "Token does not grant access to this API", AkipsPermissionError),
        )
        for token, reason, expected in cases:
            with self.subTest(reason=reason):
                get_mock.return_value.text = f"ERROR: api-db {reason}\n"
                api = AKIPS("akips.example.com", token=token)
                with self.assertRaises(expected) as caught:
                    api.get_devices()
                self.assertNotIn(token, str(caught.exception))

    @patch("requests.Session.get")
    def test_parser_warnings_redact_before_truncating_the_reply(
        self, get_mock: MagicMock
    ):
        api = AKIPS("akips.example.com", token=TOKEN)
        cases = (
            (lambda: api.get_attributes(), [f"Unexpected value {TOKEN}\n"]),
            (lambda: api.get_unreachable(), [f"Unexpected value {TOKEN}\n"]),
            (
                lambda: api.get_ups_output_source(),
                [f"dev1 ups UPS-MIB.upsOutputSource = {TOKEN}\n"],
            ),
            (lambda: api.get_device_by_ip("192.0.2.10"), [f"{'X' * 180} {TOKEN}\n"]),
            (
                lambda: api.get_latest_values("SOME-MIB.reading"),
                [
                    f"parent,child,child description,attribute,2026-11-19 10:00\ndev1,sys,,SOME-MIB.reading,{TOKEN}\n"
                ],
            ),
            (lambda: api.get_aggregate(labeled=True), [f"{TOKEN}\n", "0,300\n"]),
        )
        for call, replies in cases:
            with self.subTest(reply=replies[0][:30]):
                get_mock.side_effect = [MagicMock(text=reply) for reply in replies]
                with self.assertLogs("akips", level="WARNING") as logged:
                    call()
                self.assertNotIn(TOKEN[:16], "\n".join(logged.output))

    @patch("requests.Session.post")
    @patch("requests.Session.get")
    def test_invalid_or_expired_tokens_are_authentication_errors_without_retry(
        self, get_mock: MagicMock, post_mock: MagicMock
    ):
        api = AKIPS("akips.example.com", token=TOKEN)
        for reason in ("Invalid token", "Token has expired"):
            with self.subTest(reason=reason):
                get_mock.reset_mock()
                get_mock.return_value.text = f"ERROR: api-db {reason}\n"
                with self.assertRaises(AkipsAuthenticationError) as caught:
                    api.get_devices()
                self.assertEqual(caught.exception.section, "api-db")
                self.assertIsNone(caught.exception.username)
                get_mock.assert_called_once()
        post_mock.assert_not_called()

    @patch("requests.Session.get")
    def test_permission_failures_are_distinct_from_invalid_credentials(
        self, get_mock: MagicMock
    ):
        from akips.exceptions import AkipsPermissionError

        api = AKIPS("akips.example.com", token=TOKEN)
        for reason in (
            "Token does not grant access to this API",
            "Token grants read-only access; write access required",
        ):
            with self.subTest(reason=reason):
                get_mock.return_value.text = f"ERROR: api-db {reason}\n"
                with self.assertRaises(AkipsPermissionError) as caught:
                    api.call("mget * * * *")
                self.assertEqual(caught.exception.section, "api-db")
                self.assertIsInstance(caught.exception, AkipsError)
                self.assertNotIsInstance(caught.exception, AkipsAuthenticationError)

    @patch("requests.Session.get")
    def test_other_server_errors_remain_generic(self, get_mock: MagicMock):
        get_mock.return_value.text = "ERROR: api-db access requires a valid licence\n"
        api = AKIPS("akips.example.com", token=TOKEN)
        with self.assertRaises(AkipsError) as caught:
            api.get_devices()
        self.assertEqual(type(caught.exception), AkipsError)

    @patch("requests.Session.get")
    def test_tokens_are_redacted_from_logs_but_returned_data_is_unchanged(
        self, get_mock: MagicMock
    ):
        reply = f"dev1 sys custom.attribute = {TOKEN}\n"
        get_mock.return_value.text = reply
        api = AKIPS("akips.example.com", token=TOKEN)
        with self.assertLogs("akips", level="DEBUG") as logged:
            self.assertEqual(api.call(params={"probe": TOKEN}), reply)
        self.assertNotIn(TOKEN, "\n".join(logged.output))

    @patch("requests.Session.get")
    def test_server_errors_redact_tokens_in_every_supported_form(
        self, get_mock: MagicMock
    ):
        api = AKIPS("akips.example.com", token=TOKEN)
        for text in (
            f"ERROR: api-db Invalid token {TOKEN}",
            f"ERROR: api-db Authorization: Bearer {OTHER_TOKEN}",
            f"ERROR: api-db /api-db?tok={OTHER_TOKEN};cmds=stat",
        ):
            with self.subTest(text=text[:30]):
                get_mock.return_value.text = text
                with self.assertLogs("akips", level="ERROR") as logged:
                    with self.assertRaises(AkipsError) as caught:
                        api.get_devices()
                for token in (TOKEN, OTHER_TOKEN):
                    self.assertNotIn(token, str(caught.exception))
                    self.assertNotIn(token, "\n".join(logged.output))

    @patch("requests.Session.get")
    def test_script_errors_also_redact_the_token(self, get_mock: MagicMock):
        get_mock.return_value.text = f"Unexpected script reply: {TOKEN}\n"
        api = AKIPS("akips.example.com", token=TOKEN)
        with self.assertLogs("akips", level="ERROR") as logged:
            with self.assertRaises(AkipsError) as caught:
                api.set_group_membership("dev1", "maintenance_mode", "assign")
        self.assertNotIn(TOKEN, str(caught.exception))
        self.assertNotIn(TOKEN, "\n".join(logged.output))

    @patch("requests.Session.get")
    def test_transport_exception_chain_and_attached_headers_are_scrubbed(
        self, get_mock: MagicMock
    ):
        request = requests.Request(
            "GET",
            "https://akips.example.com/api-db",
            headers={"Authorization": f"Bearer {TOKEN}"},
        ).prepare()
        response = requests.Response()
        response.status_code = 500
        response.request = request
        response.url = request.url
        inner = ValueError(f"Authorization: Bearer {TOKEN}")
        error = requests.exceptions.HTTPError(
            f"500 error for {TOKEN}", response=response
        )
        error.__cause__ = inner
        get_mock.side_effect = error
        api = AKIPS("akips.example.com", token=TOKEN)
        with self.assertLogs("akips", level="ERROR") as logged:
            with self.assertRaises(requests.exceptions.HTTPError) as caught:
                api.get_devices()
        rendered = "".join(traceback.format_exception(caught.exception))
        self.assertNotIn(TOKEN, rendered)
        self.assertNotIn(TOKEN, "\n".join(logged.output))
        self.assertNotIn(TOKEN, str(caught.exception.request.headers))
        self.assertNotIn(TOKEN, str(caught.exception.response.request.headers))
