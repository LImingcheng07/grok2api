import unittest

from protocol_register import _cf_resolve_domains, _safe_proxy_label


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


if __name__ == "__main__":
    unittest.main()
