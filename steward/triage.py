from urllib.parse import urlsplit
from .models import TriageResult


def _valid_store_url(value):
    try:
        parsed = urlsplit(value.strip())
    except ValueError:
        return False
    return parsed.scheme in ("http", "https") and bool(parsed.netloc)


def triage(submission):
    reasons = []
    mau_points = min(30.0, submission.mau / 1000.0 * 5.0)
    reasons.append(f"MAU contributes {mau_points:.1f}/30 points.")
    net = submission.monthly_gross_usd * (1 - submission.store_fee_pct / 100) - submission.other_costs_usd_month
    revenue_points = 20 if net > 0 else 0
    reasons.append(f"Net revenue contributes {revenue_points}/20 points.")
    source_points = 20 if submission.has_source else 0
    reasons.append(f"Source availability contributes {source_points}/20 points.")
    key_points = 20 if submission.has_signing_key or submission.has_source else 0
    reasons.append(f"Signing or rebuild path contributes {key_points}/20 points.")
    platform_points = 10 if submission.platform in ("android", "desktop") else 0
    reasons.append(f"Platform transfer assumption contributes {platform_points}/10 points.")
    valid_url = _valid_store_url(submission.store_url)
    qualified = submission.willing != "no" and submission.mau >= 1000 and valid_url
    if submission.mau < 1000:
        reasons.append("Not qualified: fewer than 1,000 MAU.")
    if submission.willing == "no":
        reasons.append("Not qualified: owner is not willing to transfer or rev-share.")
    if not valid_url:
        reasons.append("Not qualified: the store URL must use http or https.")
    return TriageResult(qualified, round(mau_points + revenue_points + source_points + key_points + platform_points, 1), reasons)
