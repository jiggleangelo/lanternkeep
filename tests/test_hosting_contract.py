import http.client
import os
import threading
import unittest
from unittest.mock import patch

from steward.config import Config
from steward.web import BANNER, make_server


class HostingContractTests(unittest.TestCase):
    def test_default_bind_remains_loopback(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(Config.from_env().host, "127.0.0.1")

    def test_contract_starts_without_extra_credentials_and_accepts_public_host(self):
        contract = {
            "DEMO_HOST": "127.0.0.1",
            "PORT": "8080",
            "PUBLIC_BASE_URL": "https://try-lanternkeep.manykiln.com",
            "DEMO_HTTPS_TERMINATED": "true",
        }
        with patch.dict(os.environ, contract, clear=True):
            config = Config.from_env()

        self.assertIsNone(config.access_token)
        server = make_server(config.host, 0, config)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            port = server.server_address[1]
            headers = {"Host": "try-lanternkeep.manykiln.com"}

            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("GET", "/healthz", headers=headers)
            response = conn.getresponse()
            self.assertEqual(response.status, 200)
            self.assertEqual(response.read(), b"ok")
            conn.close()

            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("GET", "/", headers=headers)
            response = conn.getresponse()
            home = response.read().decode("utf-8")
            self.assertEqual(response.status, 200)
            self.assertIn(BANNER, home)
            self.assertIn("https://try-lanternkeep.manykiln.com/intake", home)
            conn.close()

            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("GET", "/intake", headers=headers)
            response = conn.getresponse()
            response.read()
            self.assertEqual(response.status, 200)
            self.assertIn("Secure", response.getheader("Set-Cookie"))
            conn.close()

            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("GET", "/", headers={"Host": "wrong.example"})
            response = conn.getresponse()
            response.read()
            self.assertEqual(response.status, 421)
            conn.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join()


if __name__ == "__main__":
    unittest.main()
