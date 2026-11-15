import unittest
from datetime import datetime, timezone
from steward.config import Config
from steward.fakes import FakeAdvisoryDB, FakeBuildRunner, FakePatchAgent, FakeStore, FixedClock
from steward.models import AppRecord, Submission
from steward.offers import calculate
from steward.pipeline import MAX_PATCHES, Pipeline, PipelineError
from steward.rules import scan
from steward.seed import manifest_for_submission, tide_manifest
from steward.triage import triage
from steward.vault import MemoryVault


class CoreTests(unittest.TestCase):
    def submission(self, mau=1000, willing="either"):
        return Submission("s_x", "App", "android", "https://example.invalid", mau, 180, 15, 25, True, True, willing, None, datetime.now(timezone.utc))

    def pipeline(self, store=None):
        config, db, clock = Config(), FakeAdvisoryDB(), FixedClock()
        store = store or FakeStore()
        return Pipeline(config, db, clock, FakePatchAgent(config, db, clock), FakeBuildRunner(), store), store

    def test_triage_boundaries_and_score_reasons(self):
        self.assertFalse(triage(self.submission(999)).qualified)
        result = triage(self.submission(1000))
        self.assertTrue(result.qualified)
        self.assertEqual(len(result.reasons), 5)
        self.assertFalse(triage(self.submission(willing="no")).qualified)
        self.assertTrue(triage(self.submission(willing="acquire")).qualified)

    def test_offer_math(self):
        config = Config()
        low, high = calculate(self.submission(), 0, config), calculate(self.submission(), 100, config)
        self.assertEqual(low["multiple"], 1)
        self.assertEqual(high["multiple"], 2)
        self.assertAlmostEqual(high["upfront"] + high["earnout"], high["price"])
        self.assertAlmostEqual(high["developer_share"] / high["annual"], .7)

    def test_intake_sample_spec_counts(self):
        config, db, clock = Config(), FakeAdvisoryDB(), FixedClock()
        manifest = manifest_for_submission(self.submission(), config)
        findings = scan(manifest, "android", config, db, clock)
        self.assertEqual(len(findings), 7)
        self.assertEqual(sum(f.severity == "blocker" for f in findings), 2)
        patches = FakePatchAgent(config, db, clock).propose(manifest, findings, "android")
        self.assertEqual(len(patches), 4)

    def test_rules_clean_and_flagged(self):
        config, db, clock = Config(), FakeAdvisoryDB(), FixedClock()
        findings = scan(tide_manifest(), "android", config, db, clock)
        self.assertTrue({"C1", "C2", "C3", "C4", "C5", "C7"}.issubset({f.rule_id for f in findings}))
        bad = tide_manifest()
        bad["account"] = {"verified": False, "transfer_approved": False}
        self.assertTrue({"C6", "C8", "C9"}.issubset({f.rule_id for f in scan(bad, "android", config, db, clock)}))

    def test_pipeline_gate_and_rejection(self):
        pipe, store = self.pipeline()
        manifest = tide_manifest(); manifest["signing_key"] = "present"
        app = AppRecord("a_x", None, "App", "android", "revshare", manifest)
        pipe.scan(app); pipe.propose(app)
        checklist = {"read_diff": True, "tested_on_device": True, "policy_reviewed": True}
        failed = next(p for p in app.patches if p.build == "fail")
        with self.assertRaises(PipelineError):
            pipe.approve(app, failed.id, "R", checklist)
        for patch in app.patches:
            if patch.build == "pass" and patch.rule_id != "C4":
                pipe.approve(app, patch.id, "Reviewer", checklist)
        release = pipe.release(app)
        self.assertEqual(release.store_result, "rejected")
        self.assertEqual(store.calls, 1)
        with self.assertRaisesRegex(PipelineError, "already submitted"):
            pipe.release(app)
        self.assertEqual(store.calls, 1)
        self.assertEqual((len(app.releases), len(app.log)), (1, 1))

    def test_review_lengths_and_patch_history_are_bounded(self):
        pipe, _ = self.pipeline()
        manifest = tide_manifest(); manifest["signing_key"] = "present"
        app = AppRecord("a_x", None, "App", "android", "revshare", manifest)
        pipe.scan(app); patches = pipe.propose(app)
        with self.assertRaisesRegex(PipelineError, "too long"):
            pipe.reject(app, patches[0].id, "R" * 101, "reason")
        with self.assertRaisesRegex(PipelineError, "too long"):
            pipe.reject(app, patches[0].id, "R", "x" * 501)
        for patch in patches:
            if patch.status in ("proposed", "needs_rework"):
                pipe.reject(app, patch.id, "R", "bounded")
        while len(app.patches) < MAX_PATCHES:
            pipe.propose(app)
            for patch in app.patches:
                if patch.status in ("proposed", "needs_rework"):
                    pipe.reject(app, patch.id, "R", "bounded")
        with self.assertRaisesRegex(PipelineError, "patch history limit"):
            pipe.propose(app)
        self.assertEqual(len(app.patches), MAX_PATCHES)

    def test_release_is_blocked_without_signing_key_or_rebuild_path(self):
        pipe, store = self.pipeline()
        app = AppRecord("a_c6", None, "App", "android", "revshare", tide_manifest())
        pipe.scan(app); pipe.propose(app)
        checklist = {"read_diff": True, "tested_on_device": True, "policy_reviewed": True}
        for patch in app.patches:
            if patch.build == "pass":
                pipe.approve(app, patch.id, "Reviewer", checklist)
        with self.assertRaisesRegex(PipelineError, "Signing-key transfer blocker"):
            pipe.release(app)
        self.assertEqual(store.calls, 0)

    def test_vault_is_write_only(self):
        vault = MemoryVault()
        token = vault.put("secret@example.invalid")
        self.assertRegex(token, r"^v_[0-9a-f]{12}$")
        self.assertFalse(hasattr(vault, "get"))
        with self.assertRaises(TypeError):
            iter(vault)


if __name__ == "__main__":
    unittest.main()
