import base64
import http.client
import os
import re
import threading
import unittest
from unittest.mock import patch
from urllib.parse import urlencode
from steward.config import Config
from steward.web import BANNER, MAX_SESSIONS, MAX_WORKERS, REQUEST_TIMEOUT, State, make_server


class DemoTests(unittest.TestCase):
    def setUp(self):
        self.server = make_server("127.0.0.1", 0, Config())
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.server.server_address[1]
        self.cookie = ""

    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join()

    def request(self, method, path, data=None, headers=None):
        headers = dict(headers or {})
        if self.cookie:
            headers["Cookie"] = self.cookie
        body = urlencode(data) if isinstance(data, dict) else data
        if method == "POST":
            headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        conn.request(method, path, body=body, headers=headers)
        response = conn.getresponse(); content = response.read().decode()
        if response.getheader("Set-Cookie"):
            self.cookie = response.getheader("Set-Cookie").split(";", 1)[0]
        result = response.status, content, response.getheader("Location"), response
        conn.close()
        return result

    def csrf(self, document):
        return re.search(r"name=csrf value='([0-9a-f]+)'", document).group(1)

    def test_health_banner_limits_escape_and_flow(self):
        self.assertEqual(self.request("GET", "/healthz")[:2], (200, "ok"))
        _, home, _, _ = self.request("GET", "/")
        self.assertIn(BANNER, home)
        self.assertEqual(len(self.server.state.sessions), 0)
        _, form, _, _ = self.request("GET", "/intake?sample=1"); token = self.csrf(form)
        data = {"csrf": token, "app_name": "<script>alert(1)</script>", "platform": "android", "store_url": "https://example.invalid", "mau": "2400", "gross": "180", "fee": "15", "costs": "25", "source": "on", "key": "on", "willing": "either", "contact": "hidden@example.invalid"}
        status, _, location, _ = self.request("POST", "/intake", data); self.assertEqual(status, 303)
        _, page, _, _ = self.request("GET", location)
        self.assertIn("&lt;script&gt;", page); self.assertNotIn("hidden@example.invalid", page)
        token = self.csrf(page)
        status, _, location, _ = self.request("POST", location + "/accept", {"csrf": token, "deal": "revshare"}); self.assertEqual(status, 303)
        _, app, _, _ = self.request("GET", location); token = self.csrf(app)

        _, app, _, _ = self.request("POST", location + "/scan", {"csrf": token})
        self.assertIn("Scan complete: 7 findings", app)
        token = self.csrf(app)

        _, app, _, _ = self.request("POST", location + "/propose", {"csrf": token})
        self.assertIn("Proposed 4 simulated patches", app)
        token = self.csrf(app)

        for pid in re.findall(r"/patches/(p_[0-9]+)/approve", app):
            _, app, _, _ = self.request("POST", f"{location}/patches/{pid}/approve", {"csrf": token, "reviewer": "Sam", "read_diff": "on", "tested_on_device": "on", "policy_reviewed": "on"}); token = self.csrf(app)
        _, app, _, _ = self.request("POST", location + "/release", {"csrf": token})
        self.assertIn("approved", app.lower())

    def test_oversized_body_is_rejected_without_sending_it(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.putrequest("POST", "/intake")
        conn.putheader("Content-Type", "application/x-www-form-urlencoded")
        conn.putheader("Content-Length", "70000")
        conn.endheaders()
        response = conn.getresponse()
        self.assertEqual(response.status, 413)
        response.read(); conn.close()

    def test_sessions_are_lazy_bounded_and_evict_instead_of_locking_out(self):
        state = State(Config())
        _, first = state.session()
        self.assertIsNone(first["apps"])
        for _ in range(MAX_SESSIONS + 5):
            state.session()
        self.assertEqual(len(state.sessions), MAX_SESSIONS)

    def test_server_has_read_timeout_and_thread_cap(self):
        self.assertEqual(self.server.request_timeout, REQUEST_TIMEOUT)
        self.assertEqual(self.server.max_workers, MAX_WORKERS)

    def test_public_config_requires_auth_and_server_enforces_it(self):
        with patch.dict(os.environ, {"DEMO_HOST": "0.0.0.0", "PUBLIC_BASE_URL": "https://try.example", "DEMO_ACCESS_TOKEN": ""}, clear=True):
            with self.assertRaisesRegex(ValueError, "DEMO_ACCESS_TOKEN"):
                Config.from_env()
        token = "a-long-demo-token"
        server = make_server("127.0.0.1", 0, Config(access_token=token))
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        try:
            conn = http.client.HTTPConnection("127.0.0.1", server.server_address[1]); conn.request("GET", "/"); self.assertEqual(conn.getresponse().status, 401); conn.close()
            auth = base64.b64encode(f"steward:{token}".encode()).decode()
            conn = http.client.HTTPConnection("127.0.0.1", server.server_address[1]); conn.request("GET", "/", headers={"Authorization": "Basic " + auth}); response = conn.getresponse(); response.read(); self.assertEqual(response.status, 200); conn.close()
        finally:
            server.shutdown(); server.server_close(); thread.join()

    def test_host_and_secure_cookie(self):
        server = make_server("127.0.0.1", 0, Config(public_base_url="https://try-steward.example.test"))
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        try:
            port = server.server_address[1]
            conn = http.client.HTTPConnection("127.0.0.1", port); conn.request("GET", "/", headers={"Host": "wrong.test"}); self.assertEqual(conn.getresponse().status, 421); conn.close()
            conn = http.client.HTTPConnection("127.0.0.1", port); conn.request("GET", "/intake", headers={"Host": "try-steward.example.test"}); response = conn.getresponse(); response.read(); self.assertEqual(response.status, 200); self.assertIn("Secure", response.getheader("Set-Cookie")); conn.close()
        finally:
            server.shutdown(); server.server_close(); thread.join()


if __name__ == "__main__":
    unittest.main()
