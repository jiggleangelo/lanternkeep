import os
from dataclasses import dataclass, field
from urllib.parse import urlsplit


@dataclass
class Config:
    host: str = "127.0.0.1"
    port: int = 8080
    public_base_url: str | None = None
    https_terminated: bool = False
    access_token: str | None = None
    required_target_sdk: dict = field(default_factory=lambda: {"android": 35, "ios": 18, "desktop": 0})
    policy_date: str = "2026-10-25"
    check_interval_days: int = 90
    review_hours_per_year: float = 16.0
    hourly_rate_usd: float = 40.0
    compliance_overhead_usd: float = 200.0
    apple_fee_usd: float = 99.0
    google_fee_annual_usd: float = 25.0 / 3.0
    acquisition_min_multiple: float = 1.0
    acquisition_max_multiple: float = 2.0
    developer_share: float = 0.70
    currency: str = "USD"

    @classmethod
    def from_env(cls):
        host = os.environ.get("DEMO_HOST", "127.0.0.1")
        if not host:
            raise ValueError("DEMO_HOST must not be empty")

        port = int(os.environ.get("PORT", "8080"))
        if not 1 <= port <= 65535:
            raise ValueError("PORT must be between 1 and 65535")

        public_base_url = os.environ.get("PUBLIC_BASE_URL") or None
        if public_base_url:
            public_base_url = public_base_url.rstrip("/")
            parsed = urlsplit(public_base_url)
            if (
                parsed.scheme not in ("http", "https")
                or not parsed.hostname
                or parsed.username is not None
                or parsed.password is not None
                or parsed.query
                or parsed.fragment
                or parsed.path not in ("", "/")
            ):
                raise ValueError("PUBLIC_BASE_URL must be an HTTP(S) origin without credentials, a path, query or fragment")

        https_terminated = os.environ.get("DEMO_HTTPS_TERMINATED", "").lower() == "true"
        access_token = os.environ.get("DEMO_ACCESS_TOKEN") or None
        public_bind = host not in ("127.0.0.1", "::1", "localhost") or bool(public_base_url)
        hosting_contract = (
            bool(os.environ.get("DEMO_HOST"))
            and bool(os.environ.get("PORT"))
            and bool(public_base_url)
            and https_terminated
        )
        if public_bind and not hosting_contract and (not access_token or len(access_token) < 16):
            raise ValueError("Public deployments require DEMO_ACCESS_TOKEN with at least 16 characters")

        return cls(
            host=host,
            port=port,
            public_base_url=public_base_url,
            https_terminated=https_terminated,
            access_token=access_token,
        )

    @property
    def public_host(self):
        return urlsplit(self.public_base_url).hostname.lower() if self.public_base_url else None

    def absolute_url(self, path):
        if not self.public_base_url:
            return path
        return self.public_base_url + "/" + path.lstrip("/")

    def annual_cost(self, platform):
        store = self.apple_fee_usd if platform == "ios" else self.google_fee_annual_usd if platform == "android" else 0
        return self.review_hours_per_year * self.hourly_rate_usd + store + self.compliance_overhead_usd
