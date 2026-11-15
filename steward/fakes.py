import copy
from datetime import date
from .models import Patch

BREAKING_BUMPS = {("com.example:netlib", "4.0.0")}


class FixedClock:
    def today(self):
        return date(2026, 10, 25)


class FakeAdvisoryDB:
    data = {
        ("com.example:netlib", "3.2.0"): [{"id": "FAKE-2026-0001", "fixed": "4.0.0", "severity": "high"}],
        ("com.example:adkit", "6.0.0"): [{"id": "FAKE-2026-0002", "fixed": "6.1.1", "severity": "blocker"}],
        ("org.example:image", "1.0.0"): [{"id": "FAKE-2026-0003", "fixed": "1.0.1", "severity": "high"}],
    }

    def lookup(self, dep, version):
        return self.data.get((dep, version), [])


class FakeStore:
    def __init__(self, required=35):
        self.required = required
        self.calls = 0

    def submit(self, app_id, manifest):
        self.calls += 1
        if set(manifest.get("data_collected", [])) != set(manifest.get("data_safety_declared", [])):
            return False, "data-safety declaration mismatch"
        if manifest.get("platform", "android") == "android" and manifest.get("target_sdk", 0) < self.required:
            return False, "target API below requirement"
        return True, "approved by fake store"


class FakeBuildRunner:
    def run(self, manifest):
        for dep, version in manifest.get("dependencies", {}).items():
            if (dep, version) in BREAKING_BUMPS:
                return False, "Compiler error: incompatible netlib request adapter (simulated)"
        return True, "Build and smoke tests passed (simulated)"


def apply_changes(manifest, changes):
    result = copy.deepcopy(manifest)
    for key, value in changes.items():
        if key.startswith("dependency:"):
            result.setdefault("dependencies", {})[key.split(":", 1)[1]] = value
        else:
            result[key] = copy.deepcopy(value)
    return result


class FakePatchAgent:
    def __init__(self, config, advisories, clock):
        self.config, self.advisories, self.clock = config, advisories, clock

    def propose(self, manifest, findings, platform="android"):
        groups = {}
        for finding in findings:
            if not finding.fixable_by_agent:
                continue
            if finding.rule_id == "C1" or (finding.rule_id == "C2" and "com.example:adkit" in finding.detail):
                group = "modernization"
            elif finding.rule_id == "C2":
                group = "dependency:" + finding.detail.split(" ", 1)[0]
            elif finding.rule_id in ("C3", "C5"):
                group = "privacy"
            else:
                group = finding.rule_id
            groups.setdefault(group, []).append(finding)

        patches = []
        for grouped in groups.values():
            changes = {}
            for finding in grouped:
                if finding.rule_id == "C1":
                    changes["target_sdk"] = self.config.required_target_sdk.get(platform, 0)
                elif finding.rule_id == "C2":
                    for dep, version in manifest.get("dependencies", {}).items():
                        for hit in self.advisories.lookup(dep, version):
                            if hit["id"] in finding.detail:
                                changes["dependency:" + dep] = hit["fixed"]
                                break
                elif finding.rule_id in ("C3", "C5"):
                    policy = copy.deepcopy(manifest.get("privacy_policy", {}))
                    policy.update({
                        "updated": self.clock.today().isoformat(),
                        "lists": list(manifest.get("data_collected", [])),
                        "dpo_contact": "DPO placeholder — verify before real use",
                    })
                    changes["privacy_policy"] = policy
                elif finding.rule_id == "C4":
                    changes["data_safety_declared"] = list(manifest.get("data_collected", []))
            if not changes:
                continue
            first = grouped[0]
            rule_names = "/".join(dict.fromkeys(f.rule_id for f in grouped))
            diff = "\n".join(f"- {key}: old\n+ {key}: {value}" for key, value in changes.items())
            patches.append(Patch(
                id=f"p_{len(patches) + 1:02d}",
                rule_id=first.rule_id,
                summary=f"Agent (simulated): address {rule_names}",
                diff=diff,
                changes=changes,
                finding_title=first.title,
                finding_detail=first.detail,
                covered_findings=[(f.rule_id, f.title, f.detail) for f in grouped],
            ))
        return patches
