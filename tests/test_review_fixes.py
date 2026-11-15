import hashlib
import ipaddress
import json
import os
import re
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

if __package__:
    from .test_app import AppTests
else:
    from test_app import AppTests
from lanternkeep.budget import calculate
from lanternkeep.checks import CATEGORIES, run_checks
from lanternkeep.parsers import ParseError, parse_all, parse_gradle, redact
from lanternkeep.policy import POLICY
from lanternkeep.store import WorkspaceStore, StoreError
from lanternkeep.web import client_ip


class ReviewHTTPTests(AppTests):
    def test_full_documents_and_common_api_keys_never_reach_disk_or_export(self):
        token = self.workspace()
        gradle = 'android { targetSdk = 30 }\n// PRIVATE-DOCUMENT-SENTINEL\nbuildConfigField "String", "API_KEY", \u0027"AIzaGradleSecret"\u0027\n'
        manifest = '<manifest>\n<meta-data android:name="com.google.android.geo.API_KEY" android:value="AIzaManifestSecret"/>\n</manifest>'
        self.assertEqual(self.request("POST", "/w/%s/inputs" % token, {"gradle": gradle, "manifest": manifest})[0], 303)
        outputs = [self.request("GET", "/w/%s/export" % token)[1], self.request("GET", "/w/" + token)[1]]
        outputs += [path.read_bytes() for path in Path(self.tmp.name).rglob("*") if path.is_file()]
        for output in outputs:
            for value in (b"PRIVATE-DOCUMENT-SENTINEL", b"AIzaGradleSecret", b"AIzaManifestSecret", b"input_text"):
                self.assertNotIn(value, output)
        exported = json.loads(outputs[0])
        self.assertTrue(exported["inputs_facts"]["redacted"])
        self.assertIn("targetSdk = 36", next(f["fix"] for f in exported["findings"] if f["id"] == "R1"))

    def test_reupload_overrides_paste_and_root_upload_is_available(self):
        token = self.workspace()
        self.request("POST", "/w/%s/inputs" % token, {"gradle": "targetSdk = 29"})
        body, content_type = self.multipart([
            ("gradle", "targetSdk = 29", None),
            ("gradle_file", "targetSdk = 35\ncompileSdk = 35", "build.gradle.kts"),
            ("root_gradle_file", "repositories { jcenter() }", "build.gradle"),
        ])
        self.assertEqual(self.request("POST", "/w/%s/inputs" % token, body, {"Content-Type": content_type})[0], 303)
        state = json.loads(self.request("GET", "/w/%s/export" % token)[1])
        self.assertEqual(state["inputs_facts"]["gradle"][0]["sdk"]["targetSdk"]["value"], 35)
        self.assertIn("R3", {f["id"] for f in state["findings"]})
        self.assertIn(b"name=root_gradle_file", self.request("GET", "/w/" + token)[1])

    def test_share_link_can_be_redisplayed_after_restart_without_rotation(self):
        token = self.workspace(True)
        page = self.request("POST", "/w/%s/share" % token, {})[1].decode()
        share = re.search(r"/s/([A-Za-z0-9_-]+)", page).group(1)
        self.stop_server()
        self.start_server()
        self.assertIn(("/s/" + share).encode(), self.request("GET", "/w/" + token)[1])
        self.assertEqual(self.request("GET", "/s/" + share)[0], 200)
        for path in Path(self.tmp.name).rglob("*"):
            if path.is_file():
                self.assertNotIn(share.encode(), path.read_bytes())
        self.request("POST", "/w/%s/share/off" % token, {})
        self.assertEqual(self.request("GET", "/s/" + share)[0], 404)
        self.assertNotIn(("/s/" + share).encode(), self.request("GET", "/w/" + token)[1])

    def test_parse_error_returns_editable_escaped_unsaved_input(self):
        token = self.workspace()
        body, content_type = self.multipart([
            ("manifest_file", "<!DOCTYPE x><manifest/>", "AndroidManifest.xml"),
            ("gradle", 'targetSdk = 30\n// <script>alert(1)</script>\napi_key = "do-not-echo"', None),
            ("hosting_region", "Singapore (ap-southeast-1)", None),
        ])
        status, page, _, response = self.request("POST", "/w/%s/inputs" % token, body, {"Content-Type": content_type})
        self.assertEqual(status, 400)
        self.assertIn(b"&lt;!DOCTYPE x&gt;", page)
        self.assertIn(b"&lt;script&gt;", page)
        self.assertIn(b"targetSdk = 30", page)
        self.assertIn(b"Singapore (ap-southeast-1)", page)
        self.assertNotIn(b"do-not-echo", page)
        self.assertEqual(response.getheader("Cache-Control"), "no-store")
        self.assertEqual(self.server.store.read(token)["inputs_facts"], {})

    def test_budget_and_log_validation_errors_preserve_fields(self):
        token = self.workspace()
        status, page, _, _ = self.request("POST", "/w/%s/budget" % token, {"monthly_revenue": "123", "monthly_costs": "bad"})
        self.assertEqual(status, 400)
        self.assertIn(b">123</textarea>", page)
        self.assertIn(b">bad</textarea>", page)
        status, page, _, _ = self.request("POST", "/w/%s/log" % token, {"kind": "release", "version": "1.2", "date": "bad", "note": "Keep this note"})
        self.assertEqual(status, 400)
        self.assertIn(b"Keep this note", page)
        self.assertIn(b">1.2</textarea>", page)
        self.assertEqual(self.server.store.read(token)["log"], [])

    def test_duplicate_repository_hits_have_one_review_and_changed_fixes_reopen(self):
        token = self.workspace()
        gradle = 'repositories { jcenter(); jcenter(); maven { url "http://repo.one" }; maven { url "http://repo.two" } }'
        self.request("POST", "/w/%s/inputs" % token, {"gradle": gradle})
        state = self.server.store.read(token)
        ids = [item["id"] for item in state["findings"]]
        self.assertEqual(len(ids), len(set(ids)))
        r4 = next(f for f in state["findings"] if f["id"] == "R4")
        self.assertIn('https://repo.one', r4["fix"][0])
        self.assertIn('https://repo.two', r4["fix"][0])
        self.request("POST", "/w/%s/findings/R4/review" % token, {"read_diff": "on", "tested": "on", "checked_source": "on"})
        self.request("POST", "/w/%s/inputs" % token, {"gradle": gradle.replace("repo.two", "repo.three")})
        self.assertNotIn("R4", self.server.store.read(token)["reviews"])

    def test_trusted_proxy_clients_have_separate_rate_buckets(self):
        self.stop_server()
        os.environ["APP_TRUSTED_PROXIES"] = "127.0.0.1/32"
        self.start_server()
        for _ in range(60):
            self.server.store.create(client_id="198.51.100.1")
        self.assertEqual(self.request("POST", "/start", {}, {"X-Forwarded-For": "198.51.100.1"})[0], 507)
        self.assertEqual(self.request("POST", "/start", {}, {"X-Forwarded-For": "198.51.100.2"})[0], 303)


class ReviewRuleTests(unittest.TestCase):
    def findings(self, documents, answers=None):
        return {item["id"]: item for item in run_checks(parse_all(documents), answers or {}, POLICY)}

    def test_auth_and_token_dependency_names_are_not_secrets(self):
        coordinates = ["com.google.android.gms:play-services-auth:20.7.0", "io.jsonwebtoken:jjwt:0.9.1", "org.example:token:1.0", "org.example:auth:+"]
        text = "\n".join('implementation("%s")' % coordinate for coordinate in coordinates)
        facts = parse_all({"gradle": [text], "dependencies": "\n".join(coordinates)})
        self.assertFalse(facts["redacted"])
        self.assertEqual(len(facts["gradle"][0]["dependencies"]), 4)
        self.assertEqual(len(facts["dependency_list"]["dependencies"]), 4)
        findings = run_checks(facts, {}, POLICY)
        self.assertTrue(any(f["id"] == "R5" and f["severity"] == "high" for f in findings))
        self.assertTrue(redact('auth = "secret"')[1])
        self.assertTrue(redact('token: "secret"')[1])

    def test_unresolved_catalog_is_info_and_catalog_upload_resolves_versions(self):
        gradle = "implementation(libs.android.auth)\nimplementation(libs.gplThing)"
        finding = self.findings({"gradle": [gradle]}, {"licence": "proprietary"})["R5"]
        self.assertEqual((finding["severity"], finding["assessment"]), ("info", "not_assessed"))
        catalog = '[versions]\nauth = "20.7.0"\n[libraries]\nandroid-auth = { module = "com.google.android.gms:play-services-auth", version.ref = "auth" }\ngplThing = "org.example:gpl-chart:1.0"\n'
        findings = self.findings({"gradle": [gradle], "catalog": catalog}, {"licence": "proprietary"})
        self.assertNotIn("R5", findings)
        self.assertIn("R14", findings)
        risky = self.findings({"gradle": [gradle], "catalog": catalog.replace('auth = "20.7.0"', 'auth = "+"')})
        self.assertEqual(risky["R5"]["severity"], "high")

    def test_http_rule_only_matches_repository_url_values(self):
        text = '''android { buildConfigField "String", "BASE_URL", "http://api.example" }
// repositories { maven { url "http://comment.invalid" } }
repositories {
  maven { url = uri("http://repo.example") }
  maven { credentials { username = "http://not-a-repository" } }
}
'''
        facts = parse_all({"gradle": [text]})
        hits = facts["gradle"][0]["http_repositories"]
        self.assertEqual(len(hits), 1)
        self.assertIn("repo.example", hits[0]["text"])
        self.assertNotIn("R4", self.findings({"gradle": ['buildConfigField "String", "BASE_URL", "http://api.example"']}))

    def test_manifest_without_sdk_is_not_a_blocker(self):
        findings = self.findings({"manifest": "<manifest/>"})
        for name in ("R1", "R2"):
            self.assertEqual(findings[name]["severity"], "info")
            self.assertEqual(findings[name]["assessment"], "not_assessed")
            self.assertNotIn("Add targetSdk", str(findings[name]["fix"]))

    def test_ambiguous_permissions_do_not_invent_categories(self):
        permissions = ["USE_BIOMETRIC", "USE_FINGERPRINT", "POST_NOTIFICATIONS", "BLUETOOTH_CONNECT"]
        manifest = "<manifest>" + "".join('<uses-permission android:name="android.permission.%s"/>' % p for p in permissions) + "</manifest>"
        self.assertNotIn("R6", self.findings({"manifest": manifest}))
        self.assertTrue({"financial_info", "web_browsing", "app_info_and_performance"}.issubset(CATEGORIES))
        result = self.findings({"manifest": '<uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/>'})
        self.assertEqual(result["R6"]["source_url"], "assumption")

    def test_singapore_region_variations(self):
        for region in ("sg", " Singapore ", "Singapore (ap-southeast-1)", "SG (ap-southeast-1)", "ap-southeast-1"):
            with self.subTest(region=region):
                self.assertNotIn("R10", self.findings({}, {"hosting_region": region}))
        self.assertIn("R10", self.findings({}, {"hosting_region": "Singapore and US"}))

    def test_budget_metric_is_coverage_not_runway(self):
        values = {"monthly_revenue": "100", "monthly_costs": "20", "hours_per_year": "10", "hourly_rate": "30", "annual_store_fee": "25", "fee_percent": "10"}
        result = calculate(values)["result"]
        self.assertNotIn("months_of_runway", result)
        self.assertAlmostEqual(result["months_of_upkeep_coverage"], 840 / 325 * 12)
        values.update(hours_per_year="0", annual_store_fee="0")
        self.assertIsNone(calculate(values)["result"]["months_of_upkeep_coverage"])

    def test_whitespace_and_property_prepass_are_bounded(self):
        started = time.monotonic()
        parse_all({"gradle": ["targetSdk" + " " * 100000]})
        self.assertLess(time.monotonic() - started, 2)
        with patch("lanternkeep.parsers.time.monotonic", return_value=10):
            with self.assertRaises(ParseError):
                parse_gradle("ext.value = 35\n" * 100, deadline=1)
        facts = parse_all({"gradle": ["targetSdk " + " " * 1000 + "35"]})
        self.assertEqual(facts["gradle"][0]["sdk"]["targetSdk"]["value"], 35)

    def test_matched_lines_have_a_request_wide_cap(self):
        lines = "\n".join('repositories { maven { url "http://repo%s.example" } }' % n for n in range(180))
        facts = parse_all({"gradle": [lines, lines]})
        self.assertEqual(sum(len(group["matched_lines"]) for group in facts["gradle"]), 200)
        self.assertTrue(facts["matched_line_limit_reached"])

    def test_forwarding_requires_trust_and_cannot_spoof_leftmost_hop(self):
        networks = (ipaddress.ip_network("10.0.0.0/8"),)
        self.assertEqual(client_ip("192.0.2.1", "198.51.100.9", networks), "192.0.2.1")
        self.assertEqual(client_ip("10.0.0.1", "198.51.100.99, 192.0.2.2, 10.0.0.2", networks), "192.0.2.2")
        self.assertEqual(client_ip("10.0.0.1", "invalid", networks), "10.0.0.1")


class ReviewStoreTests(unittest.TestCase):
    def test_workspace_and_share_read_activity_survive_restart(self):
        for via_share in (False, True):
            with self.subTest(via_share=via_share), tempfile.TemporaryDirectory() as directory:
                now = [1000000.0]
                store = WorkspaceStore(directory, clock=lambda: now[0])
                token = store.create()
                store.update(token, lambda state: state.update(answers={"licence": "proprietary"}))
                share = store.set_share(token)
                state_path = Path(directory) / "ws" / store.digest(token) / "state.json"
                old = state_path.read_bytes()
                now[0] += 89 * 86400
                store.read_share(share) if via_share else store.read(token)
                self.assertEqual(state_path.read_bytes(), old)
                now[0] += 2 * 86400
                restarted = WorkspaceStore(directory, clock=lambda: now[0])
                restarted.sweep()
                self.assertTrue(restarted.read(token, touch=False)["written"])
                now[0] += 89 * 86400
                restarted.sweep()
                with self.assertRaises(KeyError):
                    restarted.read(token, touch=False)

    def test_ip_identifiers_are_not_persisted_and_sweep_prunes_memory(self):
        with tempfile.TemporaryDirectory() as directory:
            now = [1000000.0]
            store = WorkspaceStore(directory, clock=lambda: now[0])
            ip = "198.51.100.17"
            store.create(client_id=ip)
            raw = b"".join(path.read_bytes() for path in Path(directory).rglob("*") if path.is_file())
            self.assertNotIn(ip.encode(), raw)
            self.assertNotIn(hashlib.sha256(ip.encode()).hexdigest().encode(), raw)
            self.assertFalse((Path(directory) / "meta.json").exists())
            now[0] += 3601
            store.sweep()
            self.assertEqual(store._clients, {})
            self.assertEqual(store._creates, [])

    def test_legacy_documents_snippets_and_ip_hashes_are_removed_on_startup(self):
        with tempfile.TemporaryDirectory() as directory:
            store = WorkspaceStore(directory)
            token = store.create()
            state_path = Path(directory) / "ws" / store.digest(token) / "state.json"
            state = json.loads(state_path.read_text())
            state.pop("schema_version")
            state.update(input_text={"gradle": "raw-private-file"}, inputs_facts={"leak": "old-secret"}, findings=[{"fix": "old-secret"}], reviews={"R1": "2026-01-01"})
            state_path.write_text(json.dumps(state))
            (Path(directory) / "meta.json").write_text('{"created_by_client":{"old-ip-hash":[]}}')
            migrated = WorkspaceStore(directory)
            saved = migrated.read(token)
            self.assertNotIn("input_text", saved)
            self.assertEqual(saved["findings"], [])
            self.assertEqual(saved["inputs_facts"], {})
            self.assertEqual(saved["reviews"], {})
            self.assertNotIn("old-secret", state_path.read_text())
            self.assertFalse((Path(directory) / "meta.json").exists())

    def test_global_rate_limit_is_separate_from_client_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            store = WorkspaceStore(directory)
            with patch("lanternkeep.store.MAX_CREATES_PER_HOUR", 2):
                store.create(client_id="a")
                store.create(client_id="b")
                with self.assertRaisesRegex(StoreError, "global"):
                    store.create(client_id="c")


if __name__ == "__main__":
    unittest.main()
