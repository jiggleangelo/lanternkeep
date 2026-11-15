POLICY = {
    "required_target_sdk": {
        "value": 36,
        "as_of": "2026-10-26",
        "effective_from": "2026-08-31",
        "scope": "Google Play new apps and app updates; standard Android apps",
        "exceptions": "Wear OS and Automotive: 35; TV and XR: 34. Confirm eligibility and any granted extension in Play Console before using a workspace override.",
        "source_url": "https://developer.android.com/google/play/requirements/target-sdk",
        "verify": True,
    },
    "jcenter": {
        "value": "sunset",
        "as_of": "2026-10-26",
        "source_url": "https://blog.gradle.org/jcenter-shutdown",
        "verify": True,
    },
    "pdpc": {
        "value": "guidance",
        "as_of": "2026-10-26",
        "source_url": "https://www.pdpc.gov.sg/overview-of-pdpa/the-legislation/personal-data-protection-act",
        "verify": True,
    },
    "play_verification": {
        "value": "required where applicable",
        "as_of": "2026-10-26",
        "source_url": "https://support.google.com/googleplay/android-developer/answer/13628312",
        "verify": True,
    },
    "play_signing": {
        "value": "store-specific recovery and upgrade paths",
        "as_of": "2026-10-26",
        "source_url": "https://support.google.com/googleplay/android-developer/answer/9842756",
        "verify": True,
    },
    "play_transfer": {
        "value": "eligibility must be checked",
        "as_of": "2026-10-26",
        "source_url": "https://support.google.com/googleplay/android-developer/answer/6230247",
        "verify": True,
    },
    "apple_privacy_manifest": {
        "value": "privacy manifest guidance",
        "as_of": "2026-10-26",
        "source_url": "https://developer.apple.com/documentation/bundleresources/privacy_manifest_files",
        "verify": True,
    },
}
