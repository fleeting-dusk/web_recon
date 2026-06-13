import re
from collections import defaultdict
from urllib.parse import parse_qsl, urljoin, urlparse

from bs4 import BeautifulSoup

from core.base_module import BaseModule
from core.domain_utils import belongs_to_domain, extract_hostname
from core.models import JsFindingRecord


STATIC_SUFFIXES = (
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff",
    ".woff2", ".ttf", ".eot", ".map", ".mp4", ".webp", ".vue", ".ts",
    ".tsx", ".jsx",
)

ENDPOINT_SUFFIXES = (
    ".jsp", ".do", ".action", ".json", ".aspx", ".ashx", ".php", ".xml",
)

INTERESTING_PREFIXES = (
    "/api", "/apis", "/rest", "/service", "/services", "/system", "/admin",
    "/manage", "/manager", "/auth", "/login", "/logout", "/cas", "/sso",
    "/oauth", "/oauth2", "/gateway", "/dwr", "/workflow", "/portal",
)

LOCAL_SOURCE_PREFIXES = (
    "/home/runner/", "/node_modules/", "/packages/", "/src/", "/var/",
    "/tmp/", "/workspace/",
)

BUSINESS_KEYWORDS = {
    "student": "学生业务",
    "teacher": "教师业务",
    "course": "课程/教学",
    "exam": "考试业务",
    "score": "成绩业务",
    "grade": "年级/成绩",
    "school": "学校业务",
    "edu": "教育业务",
    "admin": "后台管理",
    "manage": "管理端",
    "system": "系统管理",
    "workflow": "流程审批",
    "audit": "审核业务",
    "apply": "申报/申请",
    "report": "报表统计",
    "stat": "统计分析",
    "notice": "通知公告",
    "message": "消息通知",
    "upload": "上传业务",
    "download": "下载业务",
    "学生": "学生业务",
    "教师": "教师业务",
    "考试": "考试业务",
    "成绩": "成绩业务",
    "申报": "申报/申请",
    "审核": "审核业务",
    "统计": "统计分析",
    "管理": "管理端",
}

STRING_URL_RE = re.compile(r"""(?P<q>['"`])(?P<url>(?:https?:\\?/\\?/|/)[^'"`<>\s\\]{2,300})(?P=q)""")
FETCH_RE = re.compile(r"""(?:fetch|axios(?:\.\w+)?|open)\s*\(\s*['"`]([^'"`]{1,260})['"`]""", re.I)
AJAX_URL_RE = re.compile(r"""\burl\s*:\s*['"`]([^'"`]{1,260})['"`]""", re.I)
ROUTE_RE = re.compile(
    r"""\bpath\s*:\s*['"`]([^'"`]{1,180})['"`]|<Route\b[^>]*\bpath\s*=\s*['"]([^'"]{1,180})['"]""",
    re.I,
)
HASH_ROUTE_RE = re.compile(r"""['"`](#[/!][^'"`]{1,160})['"`]""")
STORAGE_RE = re.compile(
    r"""\b(localStorage|sessionStorage)\s*\.\s*(?:getItem|setItem|removeItem)\s*\(\s*['"`]([^'"`]{1,120})['"`]""",
    re.I,
)
ROUTE_ALLOWED_RE = re.compile(r"""^[/#][A-Za-z0-9_\-./#!?&=:%+~\u4e00-\u9fff]+$""")


class JsDeepDiscovery(BaseModule):
    def __init__(self):
        super().__init__()
        self.category = "js_discovery"
        self.target_domain = ""
        self.max_sites = None
        self.max_scripts_per_site = 8
        self.max_js_bytes = 800_000

    def configure(self, target_domain=None, max_sites=None, max_scripts=None, max_bytes=None):
        if target_domain:
            self.target_domain = extract_hostname(target_domain)
        if max_sites:
            self.max_sites = max(1, int(max_sites))
        if max_scripts:
            self.max_scripts_per_site = max(1, int(max_scripts))
        if max_bytes:
            self.max_js_bytes = max(20_000, int(max_bytes))

    def run(self, alive_results):
        findings = []
        sites = [
            site for site in alive_results
            if site.status < 400 and site.content and not site.is_cdn
        ]
        if self.max_sites:
            sites = sites[: self.max_sites]

        self.log(
            f"开始 JS 深度信息收集: 站点数={len(sites)}, "
            f"每站JS上限={self.max_scripts_per_site}, 单JS上限={self.max_js_bytes} bytes"
        )

        for site in sites:
            findings.extend(self._analyze_site(site))

        self.results = self._finalize(findings)
        self.log(f"JS 深度信息收集完成，发现 {len(self.results)} 条线索。")
        return self.results

    def _analyze_site(self, site):
        soup = BeautifulSoup(site.content or "", "html.parser")
        findings = []

        findings.extend(self._extract_forms(site, soup))
        findings.extend(self._extract_links(site, soup))

        inline_scripts = []
        script_urls = []
        for tag in soup.find_all("script"):
            src = (tag.get("src") or "").strip()
            if src:
                script_urls.append(urljoin(site.url, src))
                continue
            text = tag.string or tag.get_text("\n", strip=False)
            if text and text.strip():
                inline_scripts.append(text)

        for idx, text in enumerate(inline_scripts[:3], start=1):
            findings.extend(self._extract_from_text(
                site=site,
                text=text,
                source_url=f"{site.url}#inline-script-{idx}",
                source_kind="inline-script",
            ))

        fetched = 0
        for script_url in sorted(self._dedupe(script_urls), key=self._script_priority):
            if not self._same_origin(site.url, script_url):
                findings.append(self._build_record(
                    site.url,
                    "外部系统",
                    self._normalize_external_url(script_url),
                    source_url=site.url,
                    evidence="external script reference",
                    confidence=35,
                ))
                continue
            if fetched >= self.max_scripts_per_site:
                continue

            script_text = self._fetch_script(site.url, script_url)
            if script_text is None:
                continue

            fetched += 1
            findings.append(self._build_record(
                site.url,
                "JS文件",
                self._display_url(script_url, site.url),
                source_url=script_url,
                evidence=f"size={len(script_text)}",
                confidence=45,
            ))
            findings.extend(self._extract_from_text(
                site=site,
                text=script_text,
                source_url=script_url,
                source_kind="script",
            ))

        return findings

    def _fetch_script(self, page_url, script_url):
        try:
            res = self.safe_request(script_url, timeout=8, allow_redirects=True)
        except Exception:
            return None

        if res.status_code >= 400 or not self._same_origin(page_url, res.url):
            return None

        content_type = res.headers.get("Content-Type", "").lower()
        if "javascript" not in content_type and "text/plain" not in content_type and not urlparse(res.url).path.endswith(".js"):
            return None

        content_length = self._safe_int(res.headers.get("Content-Length"))
        if content_length and content_length > self.max_js_bytes:
            return None

        text = self._decoded_text(res)
        return text[: self.max_js_bytes]

    def _extract_from_text(self, site, text, source_url, source_kind):
        findings = []
        candidates = set()

        for regex in (STRING_URL_RE, FETCH_RE, AJAX_URL_RE):
            for match in regex.finditer(text):
                raw = match.group("url") if "url" in match.groupdict() else match.group(1)
                candidates.add(self._unescape_url(raw))

        for raw in candidates:
            record = self._classify_url_candidate(site, raw, source_url, source_kind)
            if record:
                findings.append(record)

        for match in ROUTE_RE.finditer(text):
            route = next((group for group in match.groups() if group), "")
            if self._is_meaningful_route(route):
                findings.append(self._build_record(
                    site.url,
                    "前端路由",
                    self._normalize_route(route),
                    source_url=source_url,
                    evidence=source_kind,
                    confidence=70,
                ))
                findings.extend(self._business_clues(site.url, route, source_url))

        for match in HASH_ROUTE_RE.finditer(text):
            route = match.group(1)
            if self._is_meaningful_route(route):
                findings.append(self._build_record(
                    site.url,
                    "前端路由",
                    self._normalize_route(route),
                    source_url=source_url,
                    evidence=source_kind,
                    confidence=60,
                ))
                findings.extend(self._business_clues(site.url, route, source_url))

        for match in STORAGE_RE.finditer(text):
            storage, key = match.groups()
            findings.append(self._build_record(
                site.url,
                "存储键",
                f"{storage}.{key}",
                source_url=source_url,
                evidence=source_kind,
                confidence=55,
            ))

        return findings

    def _extract_forms(self, site, soup):
        findings = []
        for form in soup.find_all("form"):
            action = (form.get("action") or site.url).strip()
            method = (form.get("method") or "GET").upper()
            full_url = urljoin(site.url, action)
            if not self._same_origin(site.url, full_url):
                continue
            fields = []
            for tag in form.find_all(["input", "select", "textarea", "button"]):
                name = tag.get("name") or tag.get("id")
                if name:
                    fields.append(name)
            evidence = "fields=" + ",".join(self._dedupe(fields)[:8]) if fields else "html form"
            findings.append(self._build_record(
                site.url,
                "表单入口",
                f"{method} {self._display_url(full_url, site.url)}",
                source_url=site.url,
                evidence=evidence,
                confidence=75,
            ))
        return findings

    def _extract_links(self, site, soup):
        findings = []
        for tag in soup.find_all(["a", "iframe", "link"]):
            raw = (tag.get("href") or tag.get("src") or "").strip()
            if not raw or raw.startswith(("javascript:", "mailto:", "tel:")):
                continue
            full_url = urljoin(site.url, raw)
            record = self._classify_url_candidate(site, full_url, site.url, "html")
            if record:
                findings.append(record)
        return findings

    def _classify_url_candidate(self, site, raw, source_url, source_kind):
        if not raw:
            return None

        value = self._unescape_url(raw.strip())
        parsed = urlparse(urljoin(site.url, value))
        path = parsed.path or "/"
        lower_path = path.lower()

        if lower_path.endswith(STATIC_SUFFIXES):
            return None

        if parsed.netloc and not self._same_origin(site.url, parsed.geturl()):
            host = extract_hostname(parsed.netloc)
            if self.target_domain and belongs_to_domain(host, self.target_domain):
                return self._build_record(
                    site.url,
                    "外部系统",
                    self._normalize_external_url(parsed.geturl()),
                    source_url=source_url,
                    evidence=source_kind,
                    confidence=70,
                )
            return None

        normalized = self._normalize_path(parsed)
        if self._is_endpoint_path(path):
            return self._build_record(
                site.url,
                "API接口",
                normalized,
                source_url=source_url,
                evidence=source_kind,
                confidence=80,
            )

        if self._is_meaningful_route(path):
            return self._build_record(
                site.url,
                "前端路由",
                normalized,
                source_url=source_url,
                evidence=source_kind,
                confidence=55,
            )

        return None

    def _business_clues(self, source_site, value, source_url):
        clues = []
        lower = value.lower()
        for keyword, label in BUSINESS_KEYWORDS.items():
            if keyword.lower() in lower:
                clues.append(self._build_record(
                    source_site,
                    "业务线索",
                    label,
                    source_url=source_url,
                    evidence=value[:120],
                    confidence=50,
                ))
        return clues

    def _finalize(self, records):
        merged = {}
        for record in records:
            if not record.value:
                continue
            key = (record.source_site, record.category, record.value.lower())
            bucket = merged.setdefault(
                key,
                {
                    "record": record,
                    "sources": {record.source_url} if record.source_url else set(),
                    "evidence": {record.evidence} if record.evidence else set(),
                    "confidence": record.confidence,
                },
            )
            if bucket["record"] is not record:
                if record.source_url:
                    bucket["sources"].add(record.source_url)
                if record.evidence:
                    bucket["evidence"].add(record.evidence)
                bucket["confidence"] = max(bucket["confidence"], record.confidence)

        finalized = []
        for item in merged.values():
            primary = item["record"]
            source = sorted(item["sources"])[0] if item["sources"] else primary.source_url
            evidence = "; ".join(sorted(item["evidence"]))[:180]
            finalized.append(JsFindingRecord(
                source_site=primary.source_site,
                category=primary.category,
                value=primary.value,
                source_url=source,
                evidence=evidence,
                confidence=min(100, item["confidence"] + max(0, len(item["sources"]) - 1) * 3),
                evidence_count=max(1, len(item["sources"])),
            ))

        return sorted(finalized, key=lambda item: (
            item.source_site,
            self._category_order(item.category),
            -item.confidence,
            item.value,
        ))

    @staticmethod
    def _category_order(category):
        order = {
            "API接口": 1,
            "表单入口": 2,
            "前端路由": 3,
            "业务线索": 4,
            "外部系统": 5,
            "存储键": 6,
            "JS文件": 7,
        }
        return order.get(category, 99)

    def _is_endpoint_path(self, path):
        lower = (path or "").lower()
        if lower.endswith((".html", ".htm")) and not lower.startswith(("/api", "/apis")):
            return False
        return lower.endswith(ENDPOINT_SUFFIXES) or lower.startswith(INTERESTING_PREFIXES)

    def _is_meaningful_route(self, path):
        if not path or path in {"/", "#/", "#!"}:
            return False
        path = path.strip()
        lower = path.lower()
        if not ROUTE_ALLOWED_RE.match(path):
            return False
        if lower.startswith(LOCAL_SOURCE_PREFIXES) or any(prefix in lower for prefix in LOCAL_SOURCE_PREFIXES):
            return False
        if lower.endswith(STATIC_SUFFIXES):
            return False
        if len(path) < 3:
            return False
        if any(lower.startswith(prefix) for prefix in INTERESTING_PREFIXES):
            return True
        return any(keyword.lower() in lower for keyword in BUSINESS_KEYWORDS)

    @staticmethod
    def _normalize_route(route):
        route = (route or "").strip()
        return route if route.startswith(("/", "#")) else f"/{route}"

    @staticmethod
    def _normalize_path(parsed):
        path = parsed.path or "/"
        query_keys = sorted({key for key, _ in parse_qsl(parsed.query, keep_blank_values=True) if key})
        if query_keys:
            return f"{path}?{'&'.join(query_keys)}"
        return path

    @staticmethod
    def _normalize_external_url(url):
        parsed = urlparse(url)
        path = parsed.path or "/"
        return f"{parsed.netloc.lower()}{path}"

    @staticmethod
    def _display_url(url, base_url):
        parsed = urlparse(url)
        base = urlparse(base_url)
        if parsed.netloc == base.netloc:
            return parsed.path or "/"
        return f"{parsed.netloc}{parsed.path or '/'}"

    @staticmethod
    def _same_origin(left, right):
        a = urlparse(left)
        b = urlparse(right)
        return a.scheme == b.scheme and a.netloc.lower() == b.netloc.lower()

    @staticmethod
    def _unescape_url(value):
        return value.replace("\\/", "/").replace("&amp;", "&")

    @staticmethod
    def _decoded_text(response):
        encoding = (response.encoding or "").lower()
        if not encoding or encoding in {"iso-8859-1", "windows-1252"}:
            response.encoding = response.apparent_encoding or response.encoding
        return response.text

    @staticmethod
    def _dedupe(items):
        seen = set()
        result = []
        for item in items:
            if item in seen:
                continue
            seen.add(item)
            result.append(item)
        return result

    @staticmethod
    def _safe_int(value):
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _script_priority(script_url):
        path = urlparse(script_url).path.lower()
        filename = path.rsplit("/", 1)[-1]
        vendor_markers = (
            "jquery", "bootstrap", "swiper", "lodash", "moment", "vue.min",
            "react.production", "vendor", "chunk-vendors", "polyfill",
        )
        business_markers = (
            "app", "main", "index", "login", "auth", "system", "admin",
            "route", "router", "common", "service",
        )
        if any(marker in filename for marker in business_markers):
            return (0, filename)
        if any(marker in filename for marker in vendor_markers):
            return (2, filename)
        return (1, filename)

    @staticmethod
    def _build_record(source_site, category, value, source_url="", evidence="", confidence=0):
        return JsFindingRecord(
            source_site=source_site,
            category=category,
            value=value[:240],
            source_url=source_url,
            evidence=evidence[:240],
            confidence=confidence,
        )
