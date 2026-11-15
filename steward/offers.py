def calculate(submission, score, config):
    net_monthly = submission.monthly_gross_usd * (1 - submission.store_fee_pct / 100) - submission.other_costs_usd_month
    annual = 12 * max(net_monthly, 0)
    multiple = config.acquisition_min_multiple + score / 100 * (config.acquisition_max_multiple - config.acquisition_min_multiple)
    price = annual * multiple
    annual_cost = config.annual_cost(submission.platform)
    steward_revenue = annual * (1 - config.developer_share)
    acquire_viable = annual > annual_cost and price > 0
    if annual == 0:
        rev_verdict = "Viable only with monetization plan (out of MVP scope)"
        acquire_verdict = "Not viable as acquisition without retained revenue"
    else:
        minimum_share = annual_cost / annual * 100
        rev_verdict = "Viable as rev-share" if steward_revenue >= annual_cost else f"Not viable as rev-share; needs {minimum_share:.1f}% steward share or a maintenance fee"
        acquire_verdict = f"Viable acquisition; estimated payback {price / (annual - annual_cost) * 12:.1f} months" if acquire_viable else "Not viable as acquisition at the fixed stewardship cost"
    return {
        "net_monthly": net_monthly,
        "annual": annual,
        "multiple": multiple,
        "price": price,
        "upfront": price / 2,
        "earnout": price / 2,
        "earnout_contingent": True,
        "earnout_note": "Contingent, paid pro rata on retained revenue and capped at the displayed earn-out amount.",
        "developer_share": annual * config.developer_share,
        "steward_share": steward_revenue,
        "annual_cost": annual_cost,
        "rev_viable": steward_revenue >= annual_cost and annual > 0,
        "rev_verdict": rev_verdict,
        "acquire_viable": acquire_viable,
        "acquire_verdict": acquire_verdict,
    }
