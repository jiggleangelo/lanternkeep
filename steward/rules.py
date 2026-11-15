from datetime import datetime
from .models import Finding


def scan(manifest, platform, policy, advisories, clock):
    out = []

    def add(rule_id, severity, title, detail, fixable):
        out.append(Finding(rule_id, severity, title, detail, fixable))

    required = policy.required_target_sdk.get(platform, 0)
    if manifest.get("target_sdk", 0) < required:
        add("C1", "blocker", "Target SDK gap", f"Target {manifest.get('target_sdk')} is below illustrative requirement {required}.", True)

    for dep, version in manifest.get("dependencies", {}).items():
        for advisory in advisories.lookup(dep, version):
            add("C2", advisory.get("severity", "high"), "Vulnerable dependency", f"{dep} {version}: {advisory['id']} (made-up advisory).", True)

    privacy = manifest.get("privacy_policy", {})
    try:
        updated = datetime.strptime(privacy.get("updated", "1900-01-01"), "%Y-%m-%d").date()
    except (TypeError, ValueError):
        updated = datetime(1900, 1, 1).date()
    stale = (clock.today() - updated).days > 365
    missing = set(manifest.get("data_collected", [])) - set(privacy.get("lists", []))
    if stale or missing:
        add("C3", "high", "Privacy policy stale or incomplete", "Regenerate the policy and verify it with counsel.", True)
    if set(manifest.get("data_collected", [])) != set(manifest.get("data_safety_declared", [])):
        add("C4", "high", "Data-safety mismatch", "Collected data differs from the store declaration.", True)
    if not privacy.get("dpo_contact"):
        add("C5", "info", "PDPA DPO contact missing", "Illustrative PDPA publication/contact check; confirm with Singapore counsel.", True)
    if manifest.get("hosting_region") not in ("sg", "singapore") and not manifest.get("transfer_safeguard"):
        add("C10", "blocker", "Overseas transfer safeguard missing", "Human/legal action required; confirm the transfer limitation obligation.", False)
    if manifest.get("signing_key") != "present" and not manifest.get("rebuild_path"):
        add("C6", "blocker", "Signing-key transfer blocker", "No signing key or declared rebuild path.", False)
    for dep in manifest.get("dependencies", {}):
        if "gpl" in dep.lower() and manifest.get("license") == "proprietary":
            add("C7", "info", "Copyleft license review", f"Review {dep} compatibility with the proprietary app.", False)
    account = manifest.get("account", {})
    if account.get("verified") is False:
        add("C8", "blocker", "Developer verification incomplete", "Store-account verification requires human action.", False)
    if account.get("transfer_approved") is False:
        add("C9", "blocker", "App transfer not approved", "Verify store-specific transfer eligibility.", False)
    return out
