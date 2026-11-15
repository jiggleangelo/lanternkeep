import copy
from .models import AppRecord


def tide_manifest():
    return {
        "platform": "android",
        "target_sdk": 31,
        "min_sdk": 23,
        "version": "2.3.1",
        "dependencies": {
            "com.example:netlib": "3.2.0",
            "com.example:adkit": "6.0.0",
            "org.example:gpl-chart": "1.4",
        },
        "data_collected": ["approx_location", "device_id"],
        "data_safety_declared": ["approx_location"],
        "privacy_policy": {
            "url": "https://example.invalid/privacy",
            "updated": "2022-03-01",
            "lists": ["approx_location"],
            "dpo_contact": False,
        },
        "hosting_region": "us-east",
        "transfer_safeguard": "sample contractual safeguard",
        "license": "proprietary",
        "signing_key": "missing",
        "rebuild_path": False,
        "account": {"verified": True, "transfer_approved": True},
    }


def manifest_for_submission(submission, config):
    manifest = tide_manifest()
    platform = submission.platform
    required = config.required_target_sdk.get(platform, 0)
    manifest.update({
        "platform": platform,
        "target_sdk": max(0, required - 4) if required else 0,
        "store_url": submission.store_url,
        "signing_key": "present" if submission.has_signing_key else "missing",
        "rebuild_path": bool(submission.has_source),
    })
    if platform == "desktop":
        manifest["dependencies"] = {}
    return manifest


def seed_apps():
    tide = AppRecord("a_tide0001", None, "Tidepool Tide Tables", "android", "revshare", tide_manifest())
    hawker = copy.deepcopy(tide)
    hawker.id, hawker.name = "a_hawker01", "HawkerHop"
    hawker.manifest.update({
        "version": "1.1.0",
        "data_collected": [],
        "data_safety_declared": [],
        "hosting_region": "us-east",
        "transfer_safeguard": None,
    })
    hawker.manifest["account"]["verified"] = False
    kopi = copy.deepcopy(tide)
    kopi.id, kopi.name, kopi.platform = "a_kopi0001", "Kopi Timer", "desktop"
    kopi.manifest.update({
        "platform": "desktop",
        "target_sdk": 0,
        "version": "3.0.0",
        "dependencies": {},
        "data_collected": [],
        "data_safety_declared": [],
        "hosting_region": "sg",
        "signing_key": "missing",
        "rebuild_path": True,
    })
    kopi.manifest["privacy_policy"]["lists"] = []
    return {a.id: a for a in (tide, hawker, kopi)}
