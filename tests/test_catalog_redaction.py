import unittest

from lanternkeep.checks import run_checks
from lanternkeep.parsers import parse_all, redact
from lanternkeep.policy import POLICY


class CatalogRedactionTests(unittest.TestCase):
    def test_version_aliases_resolve_without_disabling_secret_redaction(self):
        for alias in ("auth", "token"):
            for version, risky in (("20.7.0", False), ("+", True),
                                   ("1.0-SNAPSHOT", True), ("latest.release", True)):
                with self.subTest(alias=alias, version=version):
                    catalog = ('[versions]\n%s = "%s"\n[libraries]\n'
                               'android-auth = { module = "org.example:auth", version.ref = "%s" }\n'
                               % (alias, version, alias))
                    facts = parse_all({"gradle": ["implementation(libs.android.auth)"],
                                       "catalog": catalog})
                    self.assertFalse(facts["redacted"])
                    dependencies = facts["gradle"][0]["dependencies"]
                    self.assertEqual(len(dependencies), 1)
                    self.assertEqual(dependencies[0]["coordinate"], "org.example:auth:" + version)
                    findings = {f["id"]: f for f in run_checks(facts, {}, POLICY)}
                    if risky:
                        self.assertEqual(findings["R5"]["severity"], "high")
                    else:
                        self.assertNotIn("R5", findings)

    def test_exemption_is_limited_to_version_values_and_table(self):
        for text in ('auth = "20.7.0"', 'token = "+"',
                     '[versions]\nauth = "secret"',
                     '[versions]\napi_key = "20.7.0"',
                     '[versions]\nauth = "20.7.0" # password = "secret"',
                     '[versions]\nauth = "20.7.0"\n[credentials]\ntoken = "20.7.0"'):
            with self.subTest(text=text):
                clean, changed = redact(text, version_catalog=True)
                self.assertTrue(changed)
                self.assertEqual(clean.splitlines()[-1], "<redacted by Lanternkeep>")
        self.assertTrue(redact('auth = "20.7.0"')[1])
        self.assertTrue(redact('token = "+"')[1])


if __name__ == "__main__":
    unittest.main()
