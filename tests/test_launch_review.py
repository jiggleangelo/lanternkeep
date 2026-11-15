import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import date
from email.parser import BytesParser
from pathlib import Path
from unittest.mock import Mock, patch

if __package__:
    from . import test_app as app_tests
else:
    import test_app as app_tests

from lanternkeep.checks import run_checks
from lanternkeep.multipart import FileTooLarge, parse_form
from lanternkeep.parsers import MAX_LINE, PERMISSION, PLIST_KEY, ParseError, parse_all, parse_manifest, parse_plist
from lanternkeep.policy import POLICY
from lanternkeep.store import WorkspaceStore
from lanternkeep.throttle import MissingLinkLimiter
from lanternkeep.web import DeadlineReader, REQUEST_TIMEOUT


class LaunchParserTests(unittest.TestCase):
    def test_manifest_attack_finishes_in_killable_process(self):
        script = '''
from lanternkeep.parsers import parse_all
from lanternkeep.checks import run_checks
from lanternkeep.policy import POLICY
facts = parse_all({'manifest': '<uses-permission ' * 12000})
assert facts['manifest']['truncated']
assert facts['manifest']['permissions'] == []
assert any(f['id'] == 'LIMIT' for f in run_checks(facts, {}, POLICY))
'''
        result = subprocess.run([sys.executable, '-c', script], cwd=Path(__file__).resolve().parents[1],
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_oversized_xml_lines_are_skipped_before_attribute_regexes(self):
        # 17 * 1000 = 17,000 characters, above the 2,000-character cap.
        # Matching a short omission marker is safe; matching the omitted
        # source is not. Wrap real regexes so mocks cannot invent evidence.
        oversized = '<uses-permission ' * 1000
        self.assertEqual(len(oversized), 17000)
        self.assertGreater(len(oversized), MAX_LINE)
        permission_line = '<uses-permission android:name="android.permission.CAMERA"/>'

        def bounded_permission_match(text, *args, **kwargs):
            self.assertLessEqual(len(text), MAX_LINE)
            return PERMISSION.match(text, *args, **kwargs)

        with patch('lanternkeep.parsers.PERMISSION') as permission:
            permission.match.side_effect = bounded_permission_match
            facts = parse_manifest(oversized)
            self.assertTrue(facts['truncated'])
            self.assertTrue(facts['permissions_not_assessed'])
            self.assertEqual(facts['permissions'], [])
            permission.match.reset_mock()
            facts = parse_manifest(oversized + '\n' + permission_line)
            permission.match.assert_any_call(permission_line)
            self.assertTrue(facts['truncated'])
            self.assertEqual(facts['permissions'], ['android.permission.CAMERA'])

        oversized_plist = '<key>' + ' ' * 5000 + 'NSCameraUsageDescription</key>'
        # 5 + 5000 + 24 + 6 = 5,035 characters.
        self.assertEqual(len(oversized_plist), 5035)
        self.assertGreater(len(oversized_plist), MAX_LINE)
        key_line = '<key>NSCameraUsageDescription</key>'

        def bounded_key_findall(text, *args, **kwargs):
            self.assertLessEqual(len(text), MAX_LINE)
            return PLIST_KEY.findall(text, *args, **kwargs)

        with patch('lanternkeep.parsers.PLIST_KEY') as key:
            key.findall.side_effect = bounded_key_findall
            facts = parse_plist(oversized_plist)
            self.assertTrue(facts['truncated'])
            self.assertEqual(facts['usage_keys'], [])
            key.findall.reset_mock()
            facts = parse_plist(oversized_plist + '\n' + key_line)
            key.findall.assert_any_call(key_line)
            self.assertTrue(facts['truncated'])
            self.assertEqual(facts['usage_keys'], ['NSCameraUsageDescription'])
        with patch('lanternkeep.parsers.time.monotonic', return_value=10):
            for parser in (parse_manifest, parse_plist):
                with self.assertRaises(ParseError):
                    parser('<manifest/>', deadline=1)

    def test_multiline_permission_and_target_attribute_have_original_offsets(self):
        text = '<manifest>\n<uses-permission\n android:name="android.permission.CAMERA"\n/>\n<uses-sdk\n android:targetSdkVersion="30"/>\n</manifest>'
        facts = parse_all({'manifest': text})
        manifest = facts['manifest']
        self.assertEqual(manifest['permissions'], ['android.permission.CAMERA'])
        self.assertFalse(manifest['permissions_not_assessed'])
        findings = {f['id']: f for f in run_checks(facts, {}, POLICY)}
        self.assertIn('R6', findings)
        self.assertIn('@@ line 6 @@', findings['R1']['fix'])
        self.assertIn('+  android:targetSdkVersion="36"/>', findings['R1']['fix'])

    def test_incomplete_permissions_are_explicitly_unassessed(self):
        for text in ('<uses-permission\n', '<uses-permission android:name="${permission}"/>',
                     '<uses-permission\n' + 'x' * 3000 + '\n android:name="android.permission.CAMERA"/>'):
            with self.subTest(text=text[:40]):
                facts = parse_all({'manifest': text})
                findings = {f['id']: f for f in run_checks(facts, {}, POLICY)}
                self.assertEqual(findings['R6-unassessed']['assessment'], 'not_assessed')
                self.assertEqual(facts['manifest']['permissions'], [])

    def test_comments_do_not_supply_permissions(self):
        facts = parse_manifest('<!-- <uses-permission\n android:name="android.permission.CAMERA"/> -->\n<manifest/>')
        self.assertEqual(facts['permissions'], [])
        self.assertFalse(facts['permissions_not_assessed'])

    def test_xml_caps_surface_in_report_and_do_not_skip_next_valid_line(self):
        manifest = '<uses-permission ' * 300 + '\n<uses-permission android:name="android.permission.CAMERA"/>'
        plist = ' ' * 3000 + '\n<key>NSCameraUsageDescription</key>'
        facts = parse_all({'manifest': manifest, 'plist': plist})
        self.assertEqual(facts['manifest']['permissions'], ['android.permission.CAMERA'])
        self.assertEqual(facts['plist']['usage_keys'], ['NSCameraUsageDescription'])
        self.assertIn('LIMIT', {f['id'] for f in run_checks(facts, {}, POLICY)})


class LaunchRuleTests(unittest.TestCase):
    def findings(self, answers=None, documents=None):
        return {f['id']: f for f in run_checks(parse_all(documents or {}), answers or {}, POLICY, today=date(2026, 10, 26))}

    def test_verified_target_requirement_and_explicit_override(self):
        row = POLICY['required_target_sdk']
        self.assertEqual(row['value'], 36)
        self.assertEqual(row['effective_from'], '2026-08-31')
        self.assertEqual(row['source_url'], 'https://developer.android.com/google/play/requirements/target-sdk')
        documents = {'gradle': ['targetSdk = 35\ncompileSdk = 36']}
        finding = self.findings(documents=documents)['R1']
        self.assertEqual(finding['severity'], 'blocker')
        self.assertIn('+ targetSdk = 36', finding['fix'])
        self.assertNotIn('R1', self.findings({'required_target_override': '35'}, documents))
        self.assertNotIn('R1', self.findings(documents={'gradle': ['targetSdk = 36\ncompileSdk = 36']}))

    def test_missing_or_invalid_policy_date_is_not_assessed(self):
        for value in ('', None, 'not-a-date', '2026-02-30'):
            finding = self.findings({'privacy_updated': value})['R8']
            self.assertEqual((finding['severity'], finding['assessment']), ('info', 'not_assessed'))
        self.assertNotIn('R8', self.findings({'privacy_updated': '2026-10-01'}))
        self.assertEqual(self.findings({'privacy_updated': '2024-01-01'})['R8']['severity'], 'high')
        self.assertEqual(self.findings({'privacy_updated': '2027-01-01'})['R8']['severity'], 'high')

    def test_missing_date_does_not_suppress_known_category_gap(self):
        finding = self.findings({'data_categories': ['location'], 'privacy_updated': ''})['R8']
        self.assertEqual(finding['severity'], 'high')
        self.assertIn('Add categories: location', finding['fix'])
        self.assertIn('date was not assessed', finding['why'])

    def test_r6_explains_sdk_collection_and_partial_mapping(self):
        finding = self.findings(documents={'manifest': '<uses-permission android:name="android.permission.CAMERA"/>'})['R6']
        self.assertIn('Absent permission evidence does not mean nothing is collected', finding['why'])
        self.assertIn('analytics and crash reporting', finding['why'])
        self.assertTrue(any('every other SDK' in task for task in finding['fix']))
        self.assertEqual(finding['source_url'], 'assumption')


class LaunchMultipartTests(unittest.TestCase):
    def test_part_flood_rejected_before_part_messages_are_created(self):
        body, content_type = app_tests.AppTests.multipart([('a', '', None)] * 4000)
        original = BytesParser.parsebytes
        calls = []
        def tracked(parser, data, headersonly=False):
            calls.append((len(data), headersonly))
            return original(parser, data, headersonly=headersonly)
        with patch.object(BytesParser, 'parsebytes', tracked):
            with self.assertRaisesRegex(ValueError, '100 parts'):
                parse_form(content_type, body)
        self.assertEqual(len(calls), 1)
        self.assertTrue(calls[0][1])
        self.assertLess(calls[0][0], 200)

    def test_exact_part_limit_and_quoted_boundary(self):
        body, content_type = app_tests.AppTests.multipart([('a', 'value', None)] * 100)
        prefix, boundary = content_type.split('boundary=')
        result = parse_form(prefix + 'boundary="' + boundary + '"', body)
        self.assertEqual(result['a'], ['value'] * 100)
        body, content_type = app_tests.AppTests.multipart([('a', '', None)] * 101)
        with self.assertRaises(ValueError):
            parse_form(content_type, body)

    def test_nested_multipart_is_rejected_without_recursive_parse(self):
        body = (b'--outer\r\nContent-Disposition: form-data; name="a"\r\n'
                b'Content-Type: multipart/mixed; boundary=inner\r\n\r\n' +
                b'--inner\r\n\r\nx\r\n' * 10000 + b'--inner--\r\n--outer--\r\n')
        original = BytesParser.parsebytes
        calls = []
        def tracked(parser, data, headersonly=False):
            calls.append(headersonly)
            return original(parser, data, headersonly=headersonly)
        with patch.object(BytesParser, 'parsebytes', tracked):
            with self.assertRaisesRegex(ValueError, 'Nested'):
                parse_form('multipart/form-data; boundary=outer', body)
        self.assertEqual(calls, [True, True])

    def test_file_payload_newlines_and_limits(self):
        value = 'first\r\nsecond\n'
        body, content_type = app_tests.AppTests.multipart([('gradle_file', value, 'build.gradle')])
        self.assertEqual(parse_form(content_type, body)['gradle_file'], [value])
        with self.assertRaises(FileTooLarge):
            parse_form(content_type, body, max_file=2)


class LaunchStoreTests(unittest.TestCase):
    def test_corrupt_state_is_quarantined_and_other_workspaces_survive(self):
        for damaged in (b'{', b'\xff', b'[]', b'{"created":"invalid"}'):
            with self.subTest(damaged=damaged), tempfile.TemporaryDirectory() as directory:
                store = WorkspaceStore(directory)
                good, bad = store.create(), store.create()
                share = store.set_share(bad)
                state_path = Path(directory) / 'ws' / store.digest(bad) / 'state.json'
                state_path.write_bytes(damaged)
                restarted = WorkspaceStore(directory)
                restarted.sweep()
                self.assertEqual(restarted.read(good)['schema_version'], 2)
                self.assertTrue(restarted.create())
                with self.assertRaises(KeyError):
                    restarted.read(bad)
                with self.assertRaises(KeyError):
                    restarted.read_share(share)
                quarantined = list((Path(directory) / 'quarantine').glob('*/state.json'))
                self.assertEqual(len(quarantined), 1)
                self.assertEqual(quarantined[0].read_bytes(), damaged)
                self.assertEqual(restarted._used_bytes, restarted._measure_total())
                WorkspaceStore(directory).sweep()
                self.assertEqual(quarantined[0].read_bytes(), damaged)


class LaunchLimiterTests(unittest.TestCase):
    def test_expiry_client_isolation_and_bounded_private_memory(self):
        now = [10.0]
        limiter = MissingLinkLimiter(limit=2, window=60, max_clients=2, clock=lambda: now[0])
        for _ in range(2):
            limiter.record('198.51.100.1')
        self.assertTrue(limiter.blocked('198.51.100.1'))
        self.assertFalse(limiter.blocked('198.51.100.2'))
        limiter.record('198.51.100.2')
        for n in range(100):
            limiter.record('other-%s' % n)
        self.assertEqual(len(limiter._entries), 2)
        self.assertNotIn('198.51.100.1', repr(limiter._entries))
        now[0] = 70.1
        self.assertFalse(limiter.blocked('198.51.100.1'))
        self.assertEqual(limiter._entries, {})


class LaunchHTTPTests(unittest.TestCase):
    setUp = app_tests.AppTests.setUp
    tearDown = app_tests.AppTests.tearDown
    start_server = app_tests.AppTests.start_server
    stop_server = app_tests.AppTests.stop_server
    request = app_tests.AppTests.request
    workspace = app_tests.AppTests.workspace
    multipart = staticmethod(app_tests.AppTests.multipart)

    def test_missing_capability_throttle_uses_trusted_client_and_expires(self):
        self.stop_server()
        os.environ['APP_TRUSTED_PROXIES'] = '127.0.0.1/32'
        self.start_server()
        now = [0.0]
        self.server.missing_links = MissingLinkLimiter(limit=2, clock=lambda: now[0])
        a = {'X-Forwarded-For': '198.51.100.1'}
        b = {'X-Forwarded-For': '198.51.100.2'}
        self.assertEqual(self.request('GET', '/w/missing', headers=a)[0], 404)
        self.assertEqual(self.request('GET', '/s/missing', headers=a)[0], 404)
        response = self.request('GET', '/w/another', headers=a)
        self.assertEqual(response[0], 429)
        self.assertEqual(response[3].getheader('Retry-After'), '60')
        self.assertEqual(self.request('GET', '/w/missing', headers=b)[0], 404)
        self.assertEqual(self.request('GET', '/healthz', headers=a)[0], 200)
        now[0] = 61
        self.assertEqual(self.request('GET', '/w/missing', headers=a)[0], 404)

    def test_successful_capability_reads_do_not_consume_failure_budget(self):
        self.server.missing_links = MissingLinkLimiter(limit=1)
        token = self.workspace()
        for _ in range(3):
            self.assertEqual(self.request('GET', '/w/' + token)[0], 200)
        self.assertEqual(self.server.missing_links._entries, {})

    def test_blank_and_invalid_dates_export_as_unassessed_and_report_has_scope(self):
        token = self.workspace()
        for value in ('', 'bad-date'):
            self.assertEqual(self.request('POST', '/w/%s/inputs' % token, {'privacy_updated': value})[0], 303)
            state = json.loads(self.request('GET', '/w/%s/export' % token)[1])
            r8 = next(f for f in state['findings'] if f['id'] == 'R8')
            self.assertEqual((r8['severity'], r8['assessment']), ('info', 'not_assessed'))
        page = self.request('GET', '/w/%s/report' % token)[1]
        self.assertIn(b'analytics and crash reporting', page)
        self.assertIn(b'Default target API: 36', page)

    def test_multipart_flood_does_not_mutate_workspace(self):
        token = self.workspace()
        before = self.server.store.read(token, touch=False)
        body, content_type = self.multipart([('a', '', None)] * 1000)
        self.assertEqual(self.request('POST', '/w/%s/inputs' % token, body, {'Content-Type': content_type})[0], 400)
        self.assertEqual(self.server.store.read(token, touch=False), before)

    def test_every_response_path_resets_late_read_timeout_before_writing(self):
        token = self.workspace()
        handler_type = self.server.RequestHandlerClass
        for action in ('raw', 'redirect', 'export'):
            handler = handler_type.__new__(handler_type)
            handler.connection = Mock()
            handler.connection.recv_into.return_value = 1
            handler.request_version = 'HTTP/1.1'
            handler.command = 'GET'
            # __new__ bypasses request parsing, which normally sets this field.
            # BaseHTTPRequestHandler.log_request reads it even with logging off.
            handler.requestline = 'GET / HTTP/1.1'
            handler.close_connection = True
            reader = DeadlineReader(handler.connection, 100.0)
            with patch('lanternkeep.web.time.monotonic', return_value=99.999):
                reader.readinto(bytearray(1))
            # Remaining read time is 100.0 - 99.999 = 0.001 seconds.
            self.assertAlmostEqual(handler.connection.settimeout.call_args.args[0], 0.001)
            self.assertLess(handler.connection.settimeout.call_args.args[0], 0.01)
            class CheckedWriter(io.BytesIO):
                def write(writer, data):
                    self.assertEqual(handler.connection.settimeout.call_args.args[0], REQUEST_TIMEOUT)
                    return super().write(data)
            handler.wfile = CheckedWriter()
            if action == 'raw':
                handler.raw(200, b'ok', 'text/plain')
            elif action == 'redirect':
                handler.redirect('/')
            else:
                handler.export(token)
            self.assertTrue(handler.wfile.getvalue())


if __name__ == '__main__':
    unittest.main()
