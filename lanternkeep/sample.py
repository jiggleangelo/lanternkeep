SAMPLE = "Made-up sample"

GRADLE = """plugins { id(\"com.android.application\") }
android {
    namespace = \"example.tidepool\"
    compileSdk = 31
    defaultConfig {
        applicationId = \"example.tidepool\"
        minSdk = 23
        targetSdk = 31
        versionCode = 42
        versionName = \"2.3.1\"
    }
}
repositories { jcenter() }
dependencies {
    implementation(\"org.example:gpl-chart:+\")
}
"""
MANIFEST = """<manifest xmlns:android=\"http://schemas.android.com/apk/res/android\">
<uses-permission android:name=\"android.permission.ACCESS_FINE_LOCATION\"/>
<uses-permission android:name=\"android.permission.AD_ID\"/>
</manifest>"""
ANSWERS = {
    "data_categories": [],
    "privacy_updated": "2022-03-01",
    "privacy_categories": [],
    "policy_contact": "no",
    "hosting_region": "sg",
    "transfer_safeguard": "yes",
    "licence": "proprietary",
    "signing_key": "yes",
    "source_held": "yes",
    "account_verified": "yes",
    "transfer_checked": "yes",
    "privacy_manifest": "no",
    "required_target_override": "",
}
BUDGET = {
    "monthly_revenue": "180",
    "monthly_costs": "25",
    "hours_per_year": "16",
    "hourly_rate": "40",
    "annual_store_fee": "25",
    "fee_percent": "15",
}
