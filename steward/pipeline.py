import copy
import re
import secrets
from datetime import timedelta
from .fakes import apply_changes
from .models import LogEntry, Release
from .rules import scan

MAX_PATCHES = 24
MAX_RELEASES = 20
MAX_LOG_ENTRIES = 20
MAX_REVIEWER_LENGTH = 100
MAX_REJECTION_REASON_LENGTH = 500


class PipelineError(Exception):
    pass


_CHECKLIST = {"read_diff", "tested_on_device", "policy_reviewed"}
_ACTIVE_PATCH_STATES = {"proposed", "needs_rework", "approved"}


class Pipeline:
    def __init__(self, config, advisories, clock, agent, builder, store):
        self.config, self.advisories, self.clock = config, advisories, clock
        self.agent, self.builder, self.store = agent, builder, store

    def _refresh_findings(self, app):
        app.findings = scan(app.manifest, app.platform, self.config, self.advisories, self.clock)
        return app.findings

    def scan(self, app):
        if any(p.status in _ACTIVE_PATCH_STATES for p in app.patches):
            raise PipelineError("Resolve or ship active patches before rescanning.")
        return self._refresh_findings(app)

    def propose(self, app):
        if any(p.status in _ACTIVE_PATCH_STATES for p in app.patches):
            raise PipelineError("Resolve or ship active patches before proposing again.")
        proposed = self.agent.propose(app.manifest, app.findings, app.platform)
        if len(app.patches) + len(proposed) > MAX_PATCHES:
            raise PipelineError("This app has reached its patch history limit.")
        start = len(app.patches)
        for offset, patch in enumerate(proposed, 1):
            patch.id = f"p_{start + offset:02d}"
            candidate = apply_changes(app.manifest, patch.changes)
            ok, output = self.builder.run(candidate)
            patch.build, patch.build_output = ("pass" if ok else "fail"), output
            if not ok:
                patch.status = "needs_rework"
        app.patches.extend(proposed)
        return proposed

    def approve(self, app, patch_id, reviewer, checklist):
        patch = self._patch(app, patch_id)
        reviewer = reviewer.strip()
        if len(reviewer) > MAX_REVIEWER_LENGTH:
            raise PipelineError("Reviewer name is too long.")
        checklist = dict(checklist)
        valid_review = reviewer and set(checklist) == _CHECKLIST and all(checklist.values())
        if patch.status in ("approved", "shipped"):
            if valid_review and patch.reviewer == reviewer and patch.checklist == checklist:
                return patch
            raise PipelineError("The patch was already reviewed and cannot be changed.")
        if patch.build != "pass" or patch.status != "proposed":
            raise PipelineError("Only a passing proposed patch can be approved.")
        if not valid_review:
            raise PipelineError("Reviewer name and all three checklist items are required.")
        patch.status, patch.reviewer, patch.checklist = "approved", reviewer, checklist
        return patch

    def reject(self, app, patch_id, reviewer, reason):
        patch = self._patch(app, patch_id)
        reviewer, reason = reviewer.strip(), reason.strip()
        if patch.status not in ("proposed", "needs_rework"):
            raise PipelineError("Only a proposed or needs-rework patch can be rejected.")
        if not reviewer or not reason:
            raise PipelineError("Reviewer and reason are required.")
        if len(reviewer) > MAX_REVIEWER_LENGTH or len(reason) > MAX_REJECTION_REASON_LENGTH:
            raise PipelineError("Reviewer or rejection reason is too long.")
        patch.status, patch.reviewer, patch.rejection_reason = "rejected", reviewer, reason
        return patch

    def release(self, app):
        approved = [p for p in app.patches if p.status == "approved"]
        if not approved:
            raise PipelineError("Approve at least one patch before release.")
        if len(app.releases) >= MAX_RELEASES or len(app.log) >= MAX_LOG_ENTRIES:
            raise PipelineError("This app has reached its release history limit.")
        patch_ids = [p.id for p in approved]
        if any(release.patch_ids == patch_ids for release in app.releases):
            raise PipelineError("This exact reviewed patch set was already submitted.")

        finding_keys = {(f.rule_id, f.title, f.detail): f for f in app.findings}
        covered = set()
        for patch in approved:
            if patch.build != "pass":
                raise PipelineError(f"Patch {patch.id} does not have a passing build.")
            if not patch.reviewer or set(patch.checklist) != _CHECKLIST or not all(patch.checklist.values()):
                raise PipelineError(f"Patch {patch.id} lacks a complete human review.")
            keys = patch.covered_findings or [(patch.rule_id, patch.finding_title, patch.finding_detail)]
            for key in keys:
                finding = finding_keys.get(tuple(key))
                if finding is None:
                    raise PipelineError(f"Patch {patch.id} no longer matches an open finding.")
                if not finding.fixable_by_agent:
                    raise PipelineError(f"Patch {patch.id} cannot cover a human-only finding.")
                covered.add(tuple(key))

        blockers = [
            finding for finding in app.findings
            if finding.severity == "blocker"
            and (not finding.fixable_by_agent or (finding.rule_id, finding.title, finding.detail) not in covered)
        ]
        if blockers:
            raise PipelineError("Release blocked by: " + ", ".join(f.title for f in blockers))

        candidate = copy.deepcopy(app.manifest)
        for patch in approved:
            candidate = apply_changes(candidate, patch.changes)
        version = str(candidate.get("version", "1.0.0"))
        if not re.fullmatch(r"\d+(?:\.\d+)*", version):
            raise PipelineError(f"Cannot bump unsupported version format: {version}")
        parts = version.split(".")
        parts[-1] = str(int(parts[-1]) + 1)
        candidate["version"] = ".".join(parts)

        ok, reason = self.store.submit(app.id, candidate)
        release = Release(
            "r_" + secrets.token_hex(4), candidate["version"], patch_ids,
            "approved" if ok else "rejected", reason,
        )
        app.releases.append(release)
        if ok:
            app.manifest = candidate
            for patch in approved:
                patch.status = "shipped"
            self._refresh_findings(app)
        today = self.clock.today()
        app.log.append(LogEntry(
            today.isoformat(), f"Store {release.store_result}: {reason}", candidate["version"],
            len(app.findings), (today + timedelta(days=self.config.check_interval_days)).isoformat(),
        ))
        return release

    @staticmethod
    def _patch(app, patch_id):
        for patch in app.patches:
            if patch.id == patch_id:
                return patch
        raise PipelineError("Patch not found.")
