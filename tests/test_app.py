import http.client
import json
import os
import re
import tempfile
import threading
import unittest
from urllib.parse import urlencode
from unittest.mock import patch

import app
from lanternkeep.checks import run_checks
from lanternkeep.parsers import parse_all
from lanternkeep.policy import POLICY
from lanternkeep.store import StoreError, WorkspaceStore


class AppTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.origin = "http://lantern.test"
        self.env = patch.dict(os.environ, {"DATA_DIR": self.tmp.name, "PUBLIC_BASE_URL": self.origin, "APP_HOST": "127.0.0.1", "APP_DATA_CAP_MB": "20"}, clear=True)
        self.env.start()
        self.start_server()

    def start_server(self):
        self.server = app.build_server(port=0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.server.server_address[1]

    def stop_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def tearDown(self):
        self.stop_server()
        self.env.stop()
        self.tmp.cleanup()

    def request(self, method, path, data=None, headers=None):
        headers = {"Host": "lantern.test", **(headers or {})}
        body = urlencode(data, doseq=True) if isinstance(data, dict) else data
        if method == "POST":
            headers.setdefault("Origin", self.origin)
            headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        content = response.read()
        result = response.status, content, response.getheader("Location"), response
        connection.close()
        return result

    def workspace(self, sample=False):
        status, _, location, _ = self.request("POST", "/sample" if sample else "/start", {})
        self.assertEqual(status, 303)
        return re.search(r"/w/([^/]+)$", location).group(1)

    @staticmethod
    def multipart(fields):
        boundary = "----LanternkeepBrowserBoundary"
        chunks = []
        for name, value, filename in fields:
            chunks.append("--%s\r\n" % boundary)
            disposition = 'Content-Disposition: form-data; name="%s"' % name
            if filename is not None:
                disposition += '; filename="%s"' % filename
            chunks.append(disposition + "\r\n")
            if filename is not None:
                chunks.append("Content-Type: text/plain\r\n")
            chunks.extend(["\r\n", value, "\r\n"])
        chunks.append("--%s--\r\n" % boundary)
        return "".join(chunks).encode(), "multipart/form-data; boundary=" + boundary

    def test_health_notice_and_core_flow(self):
        self.assertEqual(self.request("GET", "/healthz")[:2], (200, b"ok"))
        self.assertIn(b"manykiln.com/privacy", self.request("GET", "/")[1])
        token = self.workspace()
        gradle = 'android { compileSdk = 30\n defaultConfig { targetSdk = 30 } }\nrepositories { jcenter() }'
        manifest = '<manifest><uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/></manifest>'
        data = {"gradle": gradle, "manifest": manifest, "privacy_updated": "2026-01-01", "policy_contact": "yes", "hosting_region": "sg", "transfer_safeguard": "yes", "licence": "proprietary", "signing_key": "yes", "source_held": "yes", "account_verified": "yes", "transfer_checked": "yes", "privacy_manifest": "no"}
        status, _, location, _ = self.request("POST", "/w/%s/inputs" % token, data)
        self.assertEqual(status, 303)
        report = self.request("GET", "/w/%s/report" % token)[1].decode()
        for text in ("R1", "targetSdk = 36", "R3", "R6"):
            self.assertIn(text, report)
        self.assertEqual(self.request("POST", "/w/%s/findings/R1/review" % token, {"read_diff": "on"})[0], 400)
        self.assertEqual(self.request("POST", "/w/%s/findings/R1/review" % token, {"read_diff": "on", "tested": "on", "checked_source": "on"})[0], 303)

    def test_real_browser_multipart_form_with_more_than_twelve_parts(self):
        token = self.workspace()
        fields = [("gradle", "android { compileSdk = 35; defaultConfig { targetSdk = 35 } }", None),
                  ("root_gradle", "", None), ("manifest", "<manifest/>", None), ("plist", "", None),
                  ("dependencies", "", None), ("catalog", "", None)]
        fields += [(name + "_file", "", "") for name in ("gradle", "root_gradle", "manifest", "plist", "dependencies", "catalog")]
        fields += [(name, value, None) for name, value in {"privacy_updated": "2026-01-01", "hosting_region": "sg", "required_target_override": "", "policy_contact": "yes", "transfer_safeguard": "yes", "licence": "proprietary", "signing_key": "yes", "source_held": "yes", "account_verified": "yes", "transfer_checked": "yes", "privacy_manifest": "no"}.items()]
        body, content_type = self.multipart(fields)
        status, _, location, _ = self.request("POST", "/w/%s/inputs" % token, body, {"Content-Type": content_type})
        self.assertEqual(status, 303)
        self.assertTrue(location.endswith("/report"))

    def test_multipart_requires_origin_not_referer_fallback(self):
        token = self.workspace()
        body, content_type = self.multipart([("gradle", "android { targetSdk = 35 }", None)])
        self.assertEqual(self.request("POST", "/w/%s/inputs" % token, body, {"Content-Type": content_type, "Origin": "", "Referer": self.origin + "/w/" + token})[0], 403)

    def test_budget_log_export_share_rotation_and_persistence(self):
        token = self.workspace(True)
        self.request("POST", "/w/%s/budget" % token, {"monthly_revenue": "100", "monthly_costs": "20", "hours_per_year": "10", "hourly_rate": "30", "annual_store_fee": "25", "fee_percent": "10"})
        self.request("POST", "/w/%s/log" % token, {"kind": "release", "version": "1.2", "date": "2026-10-26", "note": "Shipped fixes", "finding": ["R1", "R3"]})
        exported = json.loads(self.request("GET", "/w/%s/export" % token)[1])
        self.assertEqual(exported["budget"]["result"]["net_annual"], 840)
        self.assertEqual(exported["log"][0]["note"], "Shipped fixes")
        self.assertEqual(exported["log"][0]["finding_ids"], ["R1", "R3"])
        self.assertEqual(exported["log"][0]["next_check_basis"], "Lanternkeep 90-day assumption")
        page = self.request("POST", "/w/%s/share" % token, {})[1].decode()
        share1 = re.search(r"/s/([A-Za-z0-9_-]+)", page).group(1)
        self.assertIn(b"Shipped fixes", self.request("GET", "/s/" + share1)[1])
        page = self.request("POST", "/w/%s/share" % token, {})[1].decode()
        share2 = re.search(r"/s/([A-Za-z0-9_-]+)", page).group(1)
        self.assertNotEqual(share1, share2)
        self.assertEqual(self.request("GET", "/s/" + share1)[0], 404)
        self.stop_server()
        self.start_server()
        self.assertIn(b"Shipped fixes", self.request("GET", "/w/" + token)[1])

    def test_log_form_exposes_findings_and_labels_due_date_assumption(self):
        token = self.workspace(True)
        page = self.request("GET", "/w/" + token)[1]
        self.assertIn(b"name=finding", page)
        self.assertIn(b"90-day Lanternkeep assumption", page)
        self.assertEqual(self.request("POST", "/w/%s/log" % token, {"kind": "check", "finding": "does-not-exist"})[0], 400)

    def test_secret_redaction_covers_url_userinfo_token_names_and_saved_text(self):
        token = self.workspace()
        secrets_text = 'storePassword "x"\nmaven { url "http://user:token@repo.example/path" }\nauth = "hidden"'
        self.request("POST", "/w/%s/inputs" % token, {"gradle": secrets_text, "signing_key": "yes", "source_held": "yes", "account_verified": "yes", "transfer_checked": "yes"})
        export = self.request("GET", "/w/%s/export" % token)[1]
        for secret in (b"user:token", b"hidden", b"storePassword"):
            self.assertNotIn(secret, export)
        self.assertIn(b"redacted by Lanternkeep", export)
        for root, _, files in os.walk(self.tmp.name):
            for name in files:
                with open(os.path.join(root, name), "rb") as handle:
                    raw = handle.read()
                for secret in (token.encode(), b"user:token", b"storePassword"):
                    self.assertNotIn(secret, raw)
                self.assertNotEqual(name, token)
        self.assertEqual(self.request("GET", "/w/not-a-token")[0], 404)
        before = len(self.server.store.locks)
        self.request("GET", "/w/another-unknown")
        self.assertEqual(len(self.server.store.locks), before)
        self.assertEqual(self.request("POST", "/w/%s/delete" % token, {})[0], 200)
        self.assertEqual(self.request("GET", "/w/" + token)[0], 404)

    def test_documents_are_discarded_but_licence_is_preserved_for_editing(self):
        token = self.workspace()
        gradle = "android { targetSdk = 35; compileSdk = 35 }\n// document-only sentinel"
        self.request("POST", "/w/%s/inputs" % token, {"gradle": gradle, "manifest": "<manifest/>", "licence": "proprietary", "signing_key": "yes", "source_held": "yes", "account_verified": "yes", "transfer_checked": "yes"})
        page = self.request("GET", "/w/" + token)[1].decode()
        self.assertIn("value=proprietary selected", page)
        self.assertIn("<textarea name=gradle></textarea>", page)
        self.assertNotIn("&lt;manifest/&gt;", page)
        exported = self.request("GET", "/w/%s/export" % token)[1]
        self.assertNotIn(b"document-only sentinel", exported)
        self.assertNotIn(b"input_text", exported)

    def test_sdk_properties_catalog_dependencies_and_precise_diff(self):
        gradle = "versionCode = 30\next.targetSdkVersion = 30\ntargetSdk = rootProject.ext.targetSdkVersion\ncompileSdk = libs.versions.compileSdk.get().toInt()\nimplementation(libs.gplThing)"
        facts = parse_all({"gradle": [gradle]})
        answers = {"required_target_override": "35", "licence": "proprietary", "signing_key": "yes", "source_held": "yes", "account_verified": "yes", "transfer_checked": "yes", "policy_contact": "yes", "hosting_region": "sg", "transfer_safeguard": "yes", "privacy_updated": "2026-10-01"}
        by_id = {item["id"]: item for item in run_checks(facts, answers, POLICY)}
        self.assertIn("+ ext.targetSdkVersion = 35", by_id["R1"]["fix"])
        self.assertNotIn("versionCode = 35", by_id["R1"]["fix"])
        self.assertEqual(by_id["R2"]["assessment"], "not_assessed")
        self.assertEqual(by_id["R5"]["severity"], "info")
        self.assertIn("R14", by_id)

    def test_ios_only_input_does_not_create_android_findings(self):
        facts = parse_all({"plist": "<plist><dict><key>NSCameraUsageDescription</key><string>Camera</string></dict></plist>"})
        answers = {"privacy_manifest": "no", "signing_key": "yes", "source_held": "yes", "account_verified": "yes", "transfer_checked": "yes", "policy_contact": "yes", "hosting_region": "sg", "transfer_safeguard": "yes", "privacy_updated": "2026-10-01"}
        ids = {item["id"] for item in run_checks(facts, answers, POLICY)}
        self.assertNotIn("R1", ids)
        self.assertNotIn("R2", ids)
        self.assertIn("R15", ids)

    def test_reads_and_exports_work_when_cap_is_full_without_rewriting_state(self):
        token = self.workspace(True)
        state_path = os.path.join(self.tmp.name, "ws", self.server.store.digest(token), "state.json")
        before = os.stat(state_path).st_mtime_ns
        self.server.store.cap_bytes = 0
        for suffix in ("", "/report", "/export"):
            self.assertEqual(self.request("GET", "/w/" + token + suffix)[0], 200)
        self.assertEqual(os.stat(state_path).st_mtime_ns, before)

    def test_projected_payload_is_included_in_data_cap(self):
        token = self.workspace()
        store = self.server.store
        store.cap_bytes = store._used_bytes + 20
        with self.assertRaises(StoreError):
            store.update(token, lambda state: state.update(extra="x" * 1000))
        self.assertLessEqual(store._measure_total(), store.cap_bytes)
        self.assertNotIn("extra", store.read(token, touch=False))

    def test_workspace_creation_limit_is_scoped_per_client(self):
        with tempfile.TemporaryDirectory() as directory:
            store = WorkspaceStore(directory, 20)
            for _ in range(60):
                store.create(client_id="client-a")
            with self.assertRaises(StoreError):
                store.create(client_id="client-a")
            self.assertTrue(store.create(client_id="client-b"))

    def test_hsts_is_sent_when_https_is_terminated(self):
        self.stop_server()
        self.env.stop()
        self.env = patch.dict(os.environ, {"DATA_DIR": self.tmp.name, "PUBLIC_BASE_URL": self.origin, "APP_HOST": "127.0.0.1", "APP_DATA_CAP_MB": "20", "APP_HTTPS_TERMINATED": "true"}, clear=True)
        self.env.start()
        self.start_server()
        self.assertEqual(self.request("GET", "/")[3].getheader("Strict-Transport-Security"), "max-age=31536000; includeSubDomains")

    def test_request_guards_and_doctype(self):
        self.assertEqual(self.request("GET", "/", headers={"Host": "wrong.test"})[0], 421)
        token = self.workspace()
        for headers in ({"Origin": "http://evil.test"}, {"Origin": "", "Referer": self.origin + "/w/x"}, {"Origin": "", "Referer": self.origin + "/w/" + token}):
            self.assertEqual(self.request("POST", "/w/%s/log" % token, {"kind": "note", "note": "ok"}, headers)[0], 403)
        body = urlencode({"kind": "note", "note": "ok"})
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        connection.request("POST", "/w/%s/log" % token, body=body, headers={"Host": "lantern.test", "Referer": self.origin + "/w/" + token, "Content-Type": "application/x-www-form-urlencoded", "Content-Length": str(len(body.encode()))})
        response = connection.getresponse()
        response.read()
        self.assertEqual(response.status, 303)
        connection.close()
        self.assertEqual(self.request("POST", "/w/%s/inputs" % token, {"manifest": "<!DOCTYPE x><manifest/>"})[0], 400)
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        connection.putrequest("POST", "/start", skip_host=True)
        for name, value in {"Host": "lantern.test", "Origin": self.origin, "Content-Type": "application/x-www-form-urlencoded", "Content-Length": str(1024 * 1024 + 1)}.items():
            connection.putheader(name, value)
        connection.endheaders()
        response = connection.getresponse()
        self.assertEqual(response.status, 413)
        response.read()
        connection.close()


if __name__ == "__main__":
    unittest.main()
