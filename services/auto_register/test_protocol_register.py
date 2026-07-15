import unittest

from protocol_register import _safe_proxy_label


class SafeProxyLabelTest(unittest.TestCase):
    def test_redacts_proxy_credentials(self) -> None:
        self.assertEqual(
            _safe_proxy_label("http://proxy-user:proxy-pass@127.0.0.1:8080"),
            "http://127.0.0.1:8080",
        )

    def test_preserves_direct_label(self) -> None:
        self.assertEqual(_safe_proxy_label(""), "direct")


if __name__ == "__main__":
    unittest.main()
