import unittest
from unittest.mock import patch

from protocol_register import CloudTempMailReceiver, _cf_resolve_domains, _safe_proxy_label


class SafeProxyLabelTest(unittest.TestCase):
    def test_redacts_proxy_credentials(self) -> None:
        self.assertEqual(
            _safe_proxy_label("http://proxy-user:proxy-pass@127.0.0.1:8080"),
            "http://127.0.0.1:8080",
        )

    def test_preserves_direct_label(self) -> None:
        self.assertEqual(_safe_proxy_label(""), "direct")


class MailDomainSelectionTest(unittest.TestCase):
    def test_explicit_domains_only_when_auto_discovery_is_disabled(self) -> None:
        self.assertEqual(
            _cf_resolve_domains(
                {
                    "defaultDomains": "doclaw.cn, edu.doclaw.cn",
                    "mail_auto_domains": False,
                }
            ),
            ["doclaw.cn", "edu.doclaw.cn"],
        )


class CloudTempMailReceiverTest(unittest.TestCase):
    def test_resend_wait_skips_code_from_previously_consumed_message(self) -> None:
        class Response:
            ok = True

            def __init__(self, messages: list[dict[str, str]]) -> None:
                self._messages = messages

            def raise_for_status(self) -> None:
                return None

            def json(self) -> dict[str, list[dict[str, str]]]:
                return {"messages": self._messages}

        class Session:
            def __init__(self) -> None:
                self.messages = [
                    {"id": "old", "subject": "Your code ABC-123"},
                ]

            def get(self, *_args, **_kwargs) -> Response:
                return Response(self.messages)

        session = Session()
        receiver = CloudTempMailReceiver(
            "generated@example.com",
            "mailbox-token",
            {"cloudflare_api_base": "https://mail.example.com"},
        )
        with patch("protocol_register._mail_session", return_value=session):
            self.assertEqual(receiver.wait_for_code(timeout=1), "ABC123")
            session.messages = [
                {"id": "old", "subject": "Your code ABC-123"},
                {"id": "new", "subject": "Your code XYZ-789"},
            ]
            self.assertEqual(receiver.wait_for_code(timeout=1), "XYZ789")


if __name__ == "__main__":
    unittest.main()
