import io
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import app
from lanternkeep.budget import calculate
from lanternkeep.checks import run_checks
from lanternkeep.parsers import ParseError, parse_all, parse_gradle
from lanternkeep.policy import POLICY
from lanternkeep.store import WorkspaceStore
from lanternkeep.web import DeadlineReader

if __package__:
    from . import test_app as app_tests
else:
    import test_app as app_tests


class ExternalParserTests(unittest.TestCase):
    def findings(self, documents):
        return {f["id"]: f for f in run_checks(parse_all(documents), {}, POLICY)}

    def test_unterminated_comment_attack_finishes_in_separate_process(self):
        # An external timeout can kill a regression even if a C regex holds
        # the GIL; a watchdog thread in the same process cannot do that.
        script = '''
from lanternkeep.parsers import parse_all
for text in (('/* ' * 68266), ('/* ' * 300 + '\\n') * 220):
    result = parse_all({'gradle': [text, text]})
    assert not any(g['jcenter'] or g['http_repositories'] for g in result['gradle'])
'''
        completed = subprocess.run([sys.executable, "-c", script], cwd=Path(__file__).resolve().parents[1],
                                   capture_output=True, text=True, timeout=5)
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_comment_string_scopes_and_offsets(self):
        text = '''/* repositories { jcenter() }\n maven { url "http://fake.invalid" } */
repositories {
  maven { url = uri("http://real.example") }
  jcenter()
}
'''
        facts = parse_gradle(text)
        self.assertEqual(len(facts["http_repositories"]), 1)
        self.assertEqual(len(facts["jcenter"]), 1)
        hit = facts["http_repositories"][0]
        self.assertEqual(hit["text"][hit["value_start"]:hit["value_end"]], "http://")
        self.assertEqual(hit["line"], 4)
        self.assertEqual(parse_gradle('"unterminated /* ' * 1000)["jcenter"], [])
        with patch("lanternkeep.parsers.time.monotonic", return_value=10):
            with self.assertRaises(ParseError):
                parse_gradle("/* never closed", deadline=1)

    def test_root_properties_resolve_and_diff_points_to_root(self):
        app_text = "targetSdkVersion rootProject.ext.targetSdkVersion\ncompileSdkVersion rootProject.ext.compileSdkVersion"
        root_text = "ext {\n targetSdkVersion = 34\n compileSdkVersion = 33\n}"
        findings = self.findings({"gradle": [app_text, root_text]})
        self.assertEqual(findings["R1"]["severity"], "blocker")
        self.assertEqual(findings["R2"]["severity"], "high")
        self.assertIn("Root Gradle\n@@ line 2 @@", findings["R1"]["fix"])
        # The configured target requirement is 36. R2 compares the submitted
        # compile SDK (33) with the submitted target SDK (34).
        self.assertIn("+  targetSdkVersion = 36", findings["R1"]["fix"])
        self.assertIn("+  compileSdkVersion = 34", findings["R2"]["fix"])

    def test_app_value_wins_and_unused_root_values_are_not_app_evidence(self):
        facts = parse_all({"gradle": ["targetSdk = 30", "ext.targetSdkVersion = 35"]})
        self.assertEqual(facts["gradle"][0]["sdk"]["targetSdk"]["value"], 30)
        self.assertEqual(facts["gradle"][1]["sdk"], {})
        findings = self.findings({"gradle": ["targetSdk = missingPlugin.targetSdkVersion", "ext.targetSdkVersion = 35"]})
        self.assertEqual(findings["R1"]["assessment"], "not_assessed")
        self.assertEqual(self.findings({"gradle": ["", "ext.targetSdkVersion = 35"]})["R1"]["assessment"], "not_assessed")

    def test_flutter_requires_actual_numeric_evidence(self):
        text = "targetSdk = flutter.targetSdkVersion"
        findings = self.findings({"gradle": [text, "ext.targetSdkVersion = 35"]})
        self.assertEqual(findings["R1"]["assessment"], "not_assessed")
        self.assertIn("installed Flutter plugin", findings["R1"]["fix"])
        findings = self.findings({"gradle": [text, "flutter.targetSdkVersion = 34"]})
        self.assertEqual(findings["R1"]["severity"], "blocker")
        self.assertIn("Root Gradle", findings["R1"]["fix"])

    def test_gms_ad_id_permission_produces_category_evidence(self):
        findings = self.findings({"manifest": '<manifest><uses-permission android:name="com.google.android.gms.permission.AD_ID"/></manifest>'})
        self.assertIn("device_or_other_ids", " ".join(findings["R6"]["fix"]))
        self.assertEqual(findings["R6"]["source_url"], "assumption")

    def test_ambiguous_redaction_is_explicit_and_does_not_expose_values(self):
        facts = parse_all({"gradle": ['def token = "private-value"; targetSdk = 30\nauth = "other-private"; repositories { jcenter() }']})
        finding = next(f for f in run_checks(facts, {}, POLICY) if f["id"] == "REDACTION")
        self.assertEqual(finding["assessment"], "not_assessed")
        self.assertIn("App Gradle lines 1, 2", finding["fix"][0])
        self.assertIn("false positives", finding["why"])
        for secret in ("private-value", "other-private"):
            self.assertNotIn(secret, json.dumps(facts))
            self.assertNotIn(secret, json.dumps(finding))


class ExternalBudgetTests(unittest.TestCase):
    def values(self, **changes):
        return dict(monthly_revenue="100", monthly_costs="200", hours_per_year="12", hourly_rate="50",
                    annual_store_fee="0", fee_percent="0", cash_reserve="900", **changes)

    def test_runway_uses_reserve_and_net_burn_including_upkeep(self):
        result = calculate(self.values())["result"]
        self.assertEqual(result["months_of_runway"], 6)
        self.assertEqual(result["runway_status"], "finite")

    def test_zero_reserve_missing_reserve_and_no_burn_are_distinct(self):
        values = self.values()
        values["cash_reserve"] = "0"
        self.assertEqual(calculate(values)["result"]["months_of_runway"], 0)
        values["cash_reserve"] = ""
        self.assertNotIn("months_of_runway", calculate(values)["result"])
        values.update(cash_reserve="900", monthly_revenue="250")
        result = calculate(values)["result"]
        self.assertIsNone(result["months_of_runway"])
        self.assertEqual(result["runway_status"], "no_net_burn")
        values["monthly_revenue"] = "300"
        self.assertEqual(calculate(values)["result"]["runway_status"], "no_net_burn")
        for invalid in ("-1", "nan", "inf"):
            values["cash_reserve"] = invalid
            with self.assertRaises(ValueError):
                calculate(values)


class ExternalStoreTests(unittest.TestCase):
    def test_delete_and_sweep_leave_no_historical_token_set(self):
        with tempfile.TemporaryDirectory() as directory:
            now = [1000000.0]
            store = WorkspaceStore(directory, clock=lambda: now[0])
            for index in range(100):
                token = store.create(client_id=str(index))
                store.read(token)
                store.delete(token)
            token = store.create(client_id="swept")
            store.read(token)
            now[0] += 86401
            store.sweep()
            self.assertFalse(getattr(store, "tombstones", set()))
            self.assertEqual(store.locks, {})
            self.assertEqual(list(store.ws_root.iterdir()), [])

    def test_waiting_update_cannot_resurrect_deleted_workspace(self):
        with tempfile.TemporaryDirectory() as directory:
            store = WorkspaceStore(directory)
            token = store.create()
            share = store.set_share(token)
            key, path, lock = store._resolved(token)
            resolved = threading.Event()
            errors = []
            original = store._resolved

            def signal_resolution(value):
                result = original(value)
                resolved.set()
                return result

            def update():
                try:
                    store.update(token, lambda state: state.update(warning="resurrected"))
                except Exception as exc:
                    errors.append(exc)

            with lock:
                with patch.object(store, "_resolved", side_effect=signal_resolution):
                    worker = threading.Thread(target=update)
                    worker.start()
                    self.assertTrue(resolved.wait(2))
                    store.delete(token)
            worker.join(2)
            self.assertFalse(worker.is_alive())
            self.assertEqual(len(errors), 1)
            self.assertIsInstance(errors[0], KeyError)
            self.assertFalse(path.exists())
            with self.assertRaises(KeyError):
                store.read_share(share)


class DeadlineReaderTests(unittest.TestCase):
    def test_each_receive_uses_remaining_total_time(self):
        class Connection:
            def __init__(self):
                self.timeouts = []
                self.reads = 0

            def settimeout(self, value):
                self.timeouts.append(value)

            def recv_into(self, target):
                target[0] = 120
                self.reads += 1
                return 1

        connection = Connection()
        reader = DeadlineReader(connection, 10)
        with patch("lanternkeep.web.time.monotonic", side_effect=[0, 9, 10]):
            self.assertEqual(reader.readinto(bytearray(1)), 1)
            self.assertEqual(reader.readinto(bytearray(1)), 1)
            with self.assertRaises(TimeoutError):
                reader.readinto(bytearray(1))
        self.assertEqual(connection.timeouts, [10, 1])
        self.assertEqual(connection.reads, 2)


class ExternalHTTPTests(app_tests.AppTests):
    def test_startup_warns_about_missing_proxy_configuration(self):
        with self.assertLogs("lanternkeep", level="WARNING") as captured:
            extra = app.build_server(port=0)
        extra.server_close()
        text = " ".join(captured.output)
        self.assertIn("APP_TRUSTED_PROXIES", text)
        self.assertIn("60/hour", text)
        self.assertIn("600/hour", text)
        with patch.dict(os.environ, {"APP_TRUSTED_PROXIES": "127.0.0.1/32"}):
            with self.assertNoLogs("lanternkeep", level="WARNING"):
                extra = app.build_server(port=0)
            extra.server_close()

    def test_slow_body_expires_and_worker_slot_is_released(self):
        connection = socket.create_connection(("127.0.0.1", self.port), timeout=2)
        stopped = threading.Event()
        writer = None
        try:
            with patch("lanternkeep.web.REQUEST_TIMEOUT", 0.5):
                connection.sendall(b"POST /start HTTP/1.0\r\nHost: lantern.test\r\nOrigin: http://lantern.test\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 100000\r\n\r\n")

                def trickle():
                    while not stopped.wait(0.05):
                        try:
                            connection.sendall(b"x")
                        except OSError:
                            return

                writer = threading.Thread(target=trickle)
                writer.start()
                response = b""
                while b"\r\n\r\n" not in response:
                    chunk = connection.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                self.assertIn(b"408", response.split(b"\r\n", 1)[0])
            self.assertEqual(self.request("GET", "/healthz")[0], 200)
            self.assertEqual(list(self.server.store.ws_root.iterdir()), [])
        finally:
            stopped.set()
            connection.close()
            if writer:
                writer.join(2)

    def test_delete_requires_two_ui_actions_and_confirmation_is_read_only(self):
        token = self.workspace(True)
        base = "/w/" + token
        dashboard = self.request("GET", base)[1].decode()
        self.assertIn("href='%s/delete'" % base, dashboard)
        self.assertNotIn("action='%s/delete'" % base, dashboard)
        status, page, _, _ = self.request("GET", base + "/delete")
        self.assertEqual(status, 200)
        self.assertIn(b"Cancel and keep workspace", page)
        self.assertIn(b"cannot be undone", page)
        self.assertEqual(self.request("GET", base)[0], 200)
        self.assertEqual(self.request("POST", base + "/delete", {})[0], 200)
        self.assertEqual(self.request("GET", base)[0], 404)

    def test_review_and_default_log_dates_use_utc(self):
        token = self.workspace(True)
        instant = datetime(2026, 1, 2, 0, 5, tzinfo=timezone.utc)
        with patch("lanternkeep.web.datetime") as clock:
            clock.now.return_value = instant
            status = self.request("POST", "/w/%s/findings/R1/review" % token,
                                  {"read_diff": "on", "tested": "on", "checked_source": "on"})[0]
            self.assertEqual(status, 303)
            self.assertEqual(self.request("POST", "/w/%s/log" % token, {"kind": "note", "note": "UTC"})[0], 303)
            self.assertTrue(all(call.args == (timezone.utc,) for call in clock.now.call_args_list))
        state = self.server.store.read(token)
        self.assertEqual(state["reviews"]["R1"], "2026-01-02")
        self.assertEqual(state["log"][-1]["date"], "2026-01-02")
        self.request("POST", "/w/%s/log" % token, {"kind": "note", "date": "2026-01-01"})
        self.assertEqual(self.server.store.read(token)["log"][-1]["date"], "2026-01-01")

    def test_cash_reserve_form_export_and_display(self):
        token = self.workspace()
        base = "/w/" + token
        self.assertIn(b"name='cash_reserve'", self.request("GET", base)[1])
        values = {"monthly_revenue": "100", "monthly_costs": "200", "hours_per_year": "12",
                  "hourly_rate": "50", "annual_store_fee": "0", "cash_reserve": "900"}
        self.assertEqual(self.request("POST", base + "/budget", values)[0], 303)
        self.assertIn(b"Months of runway: 6.0", self.request("GET", base)[1])
        state = json.loads(self.request("GET", base + "/export")[1])
        self.assertEqual(state["budget"]["result"]["months_of_runway"], 6)


if __name__ == "__main__":
    unittest.main()
