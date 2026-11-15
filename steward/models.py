from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class Submission:
    id: str
    app_name: str
    platform: str
    store_url: str
    mau: int
    monthly_gross_usd: float
    store_fee_pct: float
    other_costs_usd_month: float
    has_source: bool
    has_signing_key: bool
    willing: str
    contact_token: str | None
    created_at: datetime


@dataclass
class TriageResult:
    qualified: bool
    score: float
    reasons: list[str]


@dataclass
class Finding:
    rule_id: str
    severity: str
    title: str
    detail: str
    fixable_by_agent: bool


@dataclass
class Patch:
    id: str
    rule_id: str
    summary: str
    diff: str
    build: str = "pending"
    build_output: str = ""
    status: str = "proposed"
    reviewer: str | None = None
    checklist: dict = field(default_factory=dict)
    changes: dict = field(default_factory=dict)
    finding_title: str = ""
    finding_detail: str = ""
    covered_findings: list[tuple[str, str, str]] = field(default_factory=list)
    rejection_reason: str = ""


@dataclass
class Release:
    id: str
    version: str
    patch_ids: list[str]
    store_result: str
    store_reason: str


@dataclass
class LogEntry:
    date: str
    action: str
    version: str
    open_findings: int
    next_check_due: str


@dataclass
class AppRecord:
    id: str
    submission_id: str | None
    name: str
    platform: str
    deal: str
    manifest: dict
    findings: list[Finding] = field(default_factory=list)
    patches: list[Patch] = field(default_factory=list)
    releases: list[Release] = field(default_factory=list)
    log: list[LogEntry] = field(default_factory=list)
