import math

REQUIRED_FIELDS = ("monthly_revenue", "monthly_costs", "hours_per_year", "hourly_rate", "annual_store_fee")
FIELDS = REQUIRED_FIELDS + ("fee_percent", "cash_reserve")


def calculate(values):
    parsed = {}
    for field in FIELDS:
        raw = values.get(field, "")
        if raw in (None, ""):
            parsed[field] = None
            continue
        value = float(raw)
        if not math.isfinite(value) or not 0 <= value <= 100000000:
            raise ValueError("Budget values must be finite and between 0 and 100,000,000")
        parsed[field] = value
    fee = parsed["fee_percent"] or 0
    if fee > 100:
        raise ValueError("Fee percentage must be between 0 and 100")
    if any(parsed[field] is None for field in REQUIRED_FIELDS):
        return {"inputs": parsed, "result": None}
    net_annual = (parsed["monthly_revenue"] * (1 - fee / 100) - parsed["monthly_costs"]) * 12
    upkeep = parsed["hours_per_year"] * parsed["hourly_rate"] + parsed["annual_store_fee"]
    coverage = None if upkeep == 0 else max(net_annual, 0) / upkeep * 12
    denominator = 12 * (1 - fee / 100)
    result = {
        "net_annual": net_annual,
        "annual_upkeep": upkeep,
        "months_of_upkeep_coverage": coverage,
        "break_even_monthly_revenue": None if denominator <= 0 else (parsed["monthly_costs"] * 12 + upkeep) / denominator,
    }
    # Absence of a reserve is not a zero reserve. Keep legacy budgets meaningful.
    if parsed["cash_reserve"] is not None:
        burn = (upkeep - net_annual) / 12
        result["months_of_runway"] = parsed["cash_reserve"] / burn if burn > 0 else None
        result["runway_status"] = "finite" if burn > 0 else "no_net_burn"
    return {"inputs": parsed, "result": result}
