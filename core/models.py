from dataclasses import dataclass, field


@dataclass
class SiteRecord:
    url: str
    ip: str
    c_seg: str
    is_cdn: bool
    cdn_provider: str
    status: int
    server: str
    title: str
    headers: dict
    content: str
    fingerprint: list[str] = field(default_factory=list)
    fp_score: int = 0


@dataclass(frozen=True)
class AppAssetRecord:
    source_site: str
    platform: str
    asset_type: str
    identifier: str
    url: str = ""
    note: str = ""
    confidence: int = 0
    evidence_count: int = 1


@dataclass(frozen=True)
class JsFindingRecord:
    source_site: str
    category: str
    value: str
    source_url: str = ""
    evidence: str = ""
    confidence: int = 0
    evidence_count: int = 1


@dataclass(frozen=True)
class JsVerificationRecord:
    source_site: str
    category: str
    value: str
    verify_url: str
    method: str
    status: int | None
    result: str
    content_type: str = ""
    location: str = ""
    evidence: str = ""
    confidence: int = 0


@dataclass
class ScanContext:
    target: str
    all_subdomains: set[str] = field(default_factory=set)
    selected_subdomains: list[str] = field(default_factory=list)
    alive_results: list[SiteRecord] = field(default_factory=list)
    app_assets: list[AppAssetRecord] = field(default_factory=list)
    js_findings: list[JsFindingRecord] = field(default_factory=list)
    js_verifications: list[JsVerificationRecord] = field(default_factory=list)
    path_results: list[str] = field(default_factory=list)
    port_results: dict[str, list[str]] = field(default_factory=dict)
