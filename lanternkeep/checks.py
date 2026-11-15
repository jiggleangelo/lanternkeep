import re
from datetime import date, datetime, timezone
from urllib.parse import quote

CATEGORIES = ["personal_info", "financial_info", "location", "contacts", "photos_and_videos",
              "audio", "device_or_other_ids", "health_and_fitness", "calendar", "app_activity",
              "messages", "files_and_docs", "web_browsing", "app_info_and_performance"]
PERMISSION_CATEGORIES = {
    "android.permission.ACCESS_COARSE_LOCATION": "location",
    "android.permission.ACCESS_FINE_LOCATION": "location",
    "android.permission.ACCESS_BACKGROUND_LOCATION": "location",
    "android.permission.ACCESS_MEDIA_LOCATION": "location",
    "android.permission.READ_CONTACTS": "contacts",
    "android.permission.WRITE_CONTACTS": "contacts",
    "android.permission.CAMERA": "photos_and_videos",
    "android.permission.READ_MEDIA_IMAGES": "photos_and_videos",
    "android.permission.READ_MEDIA_VIDEO": "photos_and_videos",
    "android.permission.RECORD_AUDIO": "audio",
    "android.permission.READ_MEDIA_AUDIO": "audio",
    "android.permission.AD_ID": "device_or_other_ids",
    "com.google.android.gms.permission.AD_ID": "device_or_other_ids",
    "android.permission.BODY_SENSORS": "health_and_fitness",
    "android.permission.BODY_SENSORS_BACKGROUND": "health_and_fitness",
    "android.permission.ACTIVITY_RECOGNITION": "health_and_fitness",
    "android.permission.READ_CALENDAR": "calendar",
    "android.permission.WRITE_CALENDAR": "calendar",
    "android.permission.READ_SMS": "messages",
    "android.permission.RECEIVE_SMS": "messages",
    "android.permission.SEND_SMS": "messages",
    "android.permission.QUERY_ALL_PACKAGES": "app_activity",
    "android.permission.PACKAGE_USAGE_STATS": "app_activity",
    "android.permission.MANAGE_EXTERNAL_STORAGE": "files_and_docs",
}
DATA_SAFETY_SCOPE = (
    "The permission mapping is partial. Absent permission evidence does not mean nothing is collected. "
    "Forms and SDKs, including analytics and crash reporting, may collect data without permissions. "
    "Inventory actual off-device collection by the app and every SDK before completing the store form."
)


def _finding(rule, severity, title, why, kind, fix, source, assessment="assessed"):
    return {"id": rule, "severity": severity, "title": title, "why": why,
            "fix_kind": kind, "fix": fix, "source_url": source, "assessment": assessment}


def _diff(hit, replacement):
    prefix = hit.get("source_file", "")
    return (prefix + "\n" if prefix else "") + "@@ line %s @@\n- %s\n+ %s" % (hit.get("line", "?"), hit.get("text", ""), replacement)


def _replace_value(hit, replacement):
    text = hit.get("text", "")
    start, end = hit.get("value_start"), hit.get("value_end")
    if isinstance(start, int) and isinstance(end, int) and 0 <= start <= end <= len(text):
        return text[:start] + str(replacement) + text[end:]
    return text


def _sdk_fix(hit, name, required):
    if hit and "text" in hit:
        return "diff", _diff(hit, _replace_value(hit, required))
    if hit and hit.get("catalog"):
        return "human", "Set versions.%s in libs.versions.toml to %s and test the build." % (hit["catalog"], required)
    return "human", "Locate the defining %s setting and set it to at least %s; test the build." % (name, required)


def run_checks(facts, answers, policy, today=None):
    today = today or datetime.now(timezone.utc).date()
    out = []
    gradles = facts.get("gradle", [])
    sdk = {}
    for gradle in reversed(gradles):
        sdk.update(gradle.get("sdk", {}))
    manifest = facts.get("manifest", {})
    if not sdk.get("targetSdk") and manifest.get("targetSdk_hit"):
        sdk["targetSdk"] = manifest["targetSdk_hit"]
    required = int(answers.get("required_target_override") or policy["required_target_sdk"]["value"])
    if not 1 <= required <= 100:
        raise ValueError("Required target API must be between 1 and 100")
    android_present = bool(facts.get("provided", {}).get("gradle") or facts.get("provided", {}).get("manifest"))
    target = sdk.get("targetSdk")
    source = policy["required_target_sdk"]["source_url"]
    if android_present:
        if not target:
            expressions = sorted({g.get("sdk_unresolved", {}).get("targetSdk", {}).get("expression", "") for g in gradles} - {""})
            detail = " Unresolved expressions: %s." % ", ".join(expressions) if expressions else ""
            out.append(_finding("R1", "info", "Target API level was not assessed",
                "The submitted files do not establish the target SDK. It may be defined in another Gradle file, a version catalog or a plugin." + detail,
                "human", "Supply the app Gradle file and its numeric defining properties or catalog; compare the resolved targetSdk with %s. For flutter.targetSdkVersion, inspect the installed Flutter plugin's value or use an explicit tested numeric targetSdk. Lanternkeep does not infer plugin defaults." % required,
                source, "not_assessed"))
        elif target["value"] < required:
            kind, fix = _sdk_fix(target, "targetSdk", required)
            out.append(_finding("R1", "blocker", "Target API level is below the configured requirement",
                "The saved target SDK is below %s. Verify the dated policy row, platform exceptions and any granted extension before release." % required,
                kind, fix, source))
        compile_sdk = sdk.get("compileSdk")
        if not target or not compile_sdk:
            out.append(_finding("R2", "info", "compileSdk compatibility was not assessed",
                "The submitted files do not establish both SDK levels.", "human",
                "Resolve targetSdk and compileSdk and confirm compileSdk is at least targetSdk.",
                "https://developer.android.com/build", "not_assessed"))
        elif compile_sdk["value"] < target["value"]:
            kind, fix = _sdk_fix(compile_sdk, "compileSdk", target["value"])
            out.append(_finding("R2", "high", "compileSdk is below targetSdk",
                "Android compilation should use an SDK at least as recent as the target SDK.", kind, fix,
                "https://developer.android.com/build"))
    dependencies = list(facts.get("dependency_list", {}).get("dependencies", []))
    repository_fixes = {"R3": [], "R4": []}
    omitted = []
    for index, gradle in enumerate(gradles):
        dependencies.extend(gradle.get("dependencies", []))
        label = "App Gradle" if index == 0 else "Root Gradle"
        if gradle.get("redacted_lines"):
            omitted.append(label + " lines " + ", ".join(map(str, gradle["redacted_lines"])))
        for key, rule, replacement in (("jcenter", "R3", "mavenCentral"), ("http_repositories", "R4", "https://")):
            by_line = {}
            for hit in gradle.get(key, []):
                by_line.setdefault(hit["line"], []).append(hit)
            for hits in by_line.values():
                text = hits[0]["text"]
                for hit in sorted(hits, key=lambda h: h["value_start"], reverse=True):
                    text = text[:hit["value_start"]] + replacement + text[hit["value_end"]:]
                repository_fixes[rule].append(label + "\n" + _diff(hits[0], text))
    if omitted:
        out.append(_finding("REDACTION", "info", "Redacted Gradle lines were not assessed",
            "Whole lines containing possible credentials were omitted, including any SDK, dependency or repository declarations on those lines. Names such as auth and token may be false positives; their values are still withheld for safety.",
            "checklist", [item + ": remove credentials locally, put non-secret declarations on separate lines and resubmit; manually review any omitted declarations." for item in omitted],
            "assumption", "not_assessed"))
    if repository_fixes["R3"]:
        out.append(_finding("R3", "high", "jcenter() repository is present",
            "JCenter is sunset. Confirm artifact availability before applying every listed edit.", "checklist",
            repository_fixes["R3"], policy["jcenter"]["source_url"]))
    if repository_fixes["R4"]:
        out.append(_finding("R4", "high", "Plain-HTTP repository is present",
            "HTTP does not protect artifact transport. Confirm HTTPS support before applying every listed edit.",
            "checklist", repository_fixes["R4"], "https://docs.gradle.org/current/userguide/declaring_repositories.html"))
    risky = [dep for dep in dependencies if not dep.get("version_unknown") and
             (dep.get("version", "").lower().startswith("latest") or "+" in dep.get("version", "")
              or "snapshot" in dep.get("version", "").lower())]
    unknown = [dep for dep in dependencies if dep.get("version_unknown")]
    if risky:
        out.append(_finding("R5", "high", "Unpinned dependency versions",
            "Dynamic and snapshot versions are not immutable. Lanternkeep does not query vulnerability services.",
            "checklist", ["Pin %s to a tested immutable version; lookup: https://osv.dev/list?q=%s" %
                          (dep["coordinate"], quote(dep["name"], safe="")) for dep in risky],
            "https://docs.gradle.org/current/userguide/dependency_versions.html"))
    if unknown:
        out.append(_finding("R5-catalog" if risky else "R5", "info", "Version-catalog dependencies were not assessed",
            "A catalog reference is not evidence of an unpinned dependency. Its definition was not supplied or could not be resolved.",
            "checklist", ["Supply libs.versions.toml or manually resolve %s and look up its coordinate at https://osv.dev/." % dep["name"] for dep in unknown],
            "https://docs.gradle.org/current/userguide/version_catalogs.html", "not_assessed"))
    evidence = {PERMISSION_CATEGORIES[p] for p in manifest.get("permissions", []) if p in PERMISSION_CATEGORIES}
    declared = set(answers.get("data_categories", []))
    missing = sorted(evidence - declared)
    if missing:
        out.append(_finding("R6", "high", "Permission evidence needs a data-safety review",
            "These permission-to-category suggestions are assumptions to investigate, not proof of collection. Confirm actual off-device collection before changing the store form. " + DATA_SAFETY_SCOPE,
            "checklist", ["Investigate actual collection; add only if collected: " + item for item in missing] +
            ["Review analytics, crash reporting and every other SDK for collection without permissions; add the applicable categories only after confirming collection."], "assumption"))
    if manifest.get("permissions_not_assessed"):
        out.append(_finding("R6-unassessed", "info", "Some manifest permissions were not assessed",
            "A permission element was incomplete or unsupported, or XML content was omitted by redaction or parsing limits. " + DATA_SAFETY_SCOPE,
            "human", "Review omitted permissions locally. Supply complete uses-permission elements with android:name attributes, using lines and elements no longer than 2,000 characters.",
            "assumption", "not_assessed"))
    unsupported = sorted(declared - evidence)
    if unsupported:
        out.append(_finding("R7", "info", "Declared categories have no permission evidence",
            "Forms and SDKs may collect data without permissions. Do not remove a category solely because permission evidence is absent.",
            "checklist", ["Confirm actual collection before keeping or removing: " + item for item in unsupported], "assumption"))
    stale = None
    try:
        updated = date.fromisoformat(answers.get("privacy_updated", ""))
        stale = (today - updated).days > 365 or updated > today
    except (ValueError, TypeError):
        pass
    policy_missing = sorted(declared - set(answers.get("privacy_categories", [])))
    if stale or policy_missing:
        tasks = ["State what data is collected and why", "Describe retention and deletion",
                 "Describe sharing and processors", "State user choices and rights"]
        if policy_missing:
            tasks.append("Add categories: " + ", ".join(policy_missing))
        explanation = "The 12-month review interval is a Lanternkeep assumption, not a legal deadline."
        if stale is None:
            explanation += " The last-updated date was not assessed; the listed category gaps are independent of that missing date."
            tasks.append("Supply a valid last-updated date to assess policy age")
        out.append(_finding("R8", "high", "Privacy policy may be stale or incomplete",
            explanation, "checklist", tasks, "assumption"))
    elif stale is None:
        out.append(_finding("R8", "info", "Privacy-policy age was not assessed",
            "No valid last-updated date was supplied. A missing or invalid date is not evidence of a stale policy.",
            "human", "Check the policy and supply its last-updated date. The 12-month review interval is a Lanternkeep assumption, not a legal deadline.",
            "assumption", "not_assessed"))
    if answers.get("policy_contact") != "yes":
        out.append(_finding("R9", "info", "No data-questions contact is shown in the policy",
            "Confirm the appropriate public contact route without entering it into Lanternkeep.", "checklist",
            ["Choose an appropriate public contact route", "Add it to the policy", "Have the responsible person verify it"],
            policy["pdpc"]["source_url"]))
    region = answers.get("hosting_region", "").strip().lower()
    singapore = region in ("sg", "singapore", "ap-southeast-1") or bool(re.fullmatch(r"(?:sg|singapore)\s*\(\s*ap-southeast-1\s*\)", region))
    if not singapore and answers.get("transfer_safeguard") != "yes":
        out.append(_finding("R10", "info", "Hosting location and transfer safeguards need confirmation",
            "The entered location was not recognised as Singapore; an unknown location does not establish an overseas transfer.",
            "human", "Confirm all hosting destinations and applicable safeguards with an adviser.", policy["pdpc"]["source_url"]))
    if answers.get("signing_key") != "yes" and answers.get("source_held") != "yes":
        out.append(_finding("R11", "blocker", "Neither signing key nor source is confirmed held",
            "Future updates may be impossible without a recovery, key-upgrade or rebuild path.", "human",
            "Check Play App Signing recovery/key-upgrade options and locate a buildable source copy. Never upload a key or keystore here.",
            policy["play_signing"]["source_url"]))
    if answers.get("account_verified") != "yes":
        out.append(_finding("R12", "blocker", "Store account verification is not confirmed",
            "A human must verify applicable store-account requirements.", "human",
            "Open the store console and complete identity and account-verification tasks.", policy["play_verification"]["source_url"]))
    if answers.get("transfer_checked") != "yes":
        out.append(_finding("R13", "high", "Transfer eligibility has not been checked",
            "Transfer rules depend on the store and app history.", "human",
            "Check current store transfer requirements and record the result in the log.", policy["play_transfer"]["source_url"]))
    if answers.get("licence") == "proprietary" and any("gpl" in (dep.get("name", "") + dep.get("alias", "")).lower() for dep in dependencies):
        out.append(_finding("R14", "info", "Possible GPL dependency in a proprietary app",
            "A dependency name or alias contains 'gpl'; the name alone does not establish its licence.", "human",
            "Inspect the actual licence and obtain legal advice if compatibility is unclear.", "assumption"))
    if facts.get("plist", {}).get("usage_keys") and answers.get("privacy_manifest") == "no":
        out.append(_finding("R15", "high", "iOS usage descriptions exist without a confirmed privacy manifest",
            "Review whether the app and SDKs require PrivacyInfo.xcprivacy declarations.", "checklist",
            ["Inventory required-reason APIs", "Inventory collected-data declarations", "Add and validate PrivacyInfo.xcprivacy"],
            policy["apple_privacy_manifest"]["source_url"]))
    groups = [*gradles, facts.get("dependency_list", {}), manifest, facts.get("plist", {})]
    if facts.get("matched_line_limit_reached") or any(g.get("truncated") for g in groups):
        out.append(_finding("LIMIT", "info", "Some input was not assessed",
            "The retained-line, line-length, XML-element or dependency limit was reached.", "human",
            "Review omitted content manually or submit smaller relevant files.", "assumption", "not_assessed"))
    order = {"blocker": 0, "high": 1, "info": 2}
    return sorted(out, key=lambda item: (order[item["severity"]], item["id"]))
