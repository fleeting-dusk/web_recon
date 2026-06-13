import time
from collections import defaultdict
from urllib.parse import urljoin, urlparse

import requests

from core.base_module import BaseModule
from core.models import JsVerificationRecord


VERIFY_CATEGORIES = {"API接口", "前端路由", "表单入口"}

GET_DENY_WORDS = {
    "add", "audit", "create", "del", "delete", "disable", "edit", "enable",
    "logout", "password", "remove", "save", "send", "sendsms", "submit",
    "update", "upload", "短信", "密码", "删除", "新增", "修改", "上传",
}

AUTH_HINTS = ("login", "cas", "sso", "auth", "signin", "unauthorized")
API_PATH_PREFIXES = ("/api", "/apis", "/rest", "/service", "/services", "/gateway", "/dwr")
HTML_TYPES = ("text/html", "application/xhtml")


class JsFindingVerifier(BaseModule):
    def __init__(self):
        super().__init__()
        self.category = "js_verify"
        self.max_findings = 80
        self.max_per_site = 30
        self.timeout = 6
        self.delay = 0.2

    def configure(self, max_findings=None, max_per_site=None, timeout=None, delay=None):
        if max_findings:
            self.max_findings = max(1, int(max_findings))
        if max_per_site:
            self.max_per_site = max(1, int(max_per_site))
        if timeout:
            self.timeout = max(1, int(timeout))
        if delay is not None:
            self.delay = max(0.0, float(delay))

    def run(self, js_findings):
        candidates = self._select_candidates(js_findings)
        self.log(
            f"开始验证 JS 发现: 候选={len(candidates)}, "
            f"总上限={self.max_findings}, 每站上限={self.max_per_site}"
        )

        results = []
        for finding in candidates:
            record = self._verify_finding(finding)
            if record:
                results.append(record)
            if self.delay:
                time.sleep(self.delay)

        self.results = results
        self.log(f"JS 发现验证完成，生成 {len(results)} 条验证结果。")
        return results

    def _select_candidates(self, js_findings):
        per_site = defaultdict(int)
        selected = []
        seen = set()

        priority = {
            "API接口": 1,
            "表单入口": 2,
            "前端路由": 3,
        }

        for finding in sorted(
            js_findings,
            key=lambda item: (
                item.source_site,
                priority.get(item.category, 99),
                -item.confidence,
                item.value,
            ),
        ):
            if finding.category not in VERIFY_CATEGORIES:
                continue
            key = (finding.source_site, finding.category, finding.value.lower())
            if key in seen:
                continue
            if per_site[finding.source_site] >= self.max_per_site:
                continue

            url = self._build_verify_url(finding)
            if not url or self._has_dynamic_placeholder(url):
                continue

            seen.add(key)
            per_site[finding.source_site] += 1
            selected.append(finding)
            if len(selected) >= self.max_findings:
                break

        return selected

    def _verify_finding(self, finding):
        url = self._build_verify_url(finding)
        if not url:
            return None

        if not self._same_origin(finding.source_site, url):
            return self._build_result(
                finding,
                url,
                "SKIP",
                None,
                "skipped_cross_origin",
                evidence="只验证同源发现",
                confidence=20,
            )

        method_hint, path_value = self._split_method_value(finding.value)
        safe_get = self._safe_get_allowed(path_value)

        methods = ["HEAD"]
        if safe_get:
            methods.append("GET")
        else:
            methods.append("OPTIONS")

        last = None
        for method in methods:
            response, error = self._request(method, url)
            if error:
                last = self._build_result(
                    finding,
                    url,
                    method,
                    None,
                    "request_error",
                    evidence=error,
                    confidence=25,
                )
                continue

            result = self._classify_response(response, path_value, method)
            if method == "HEAD" and result == "possible_fallback" and safe_get:
                last = self._build_result(
                    finding,
                    url,
                    method,
                    response.status_code,
                    "observed",
                    content_type=response.headers.get("Content-Type", "").split(";", 1)[0],
                    location=response.headers.get("Location", ""),
                    evidence=self._response_evidence(
                        response,
                        method_hint,
                        safe_get,
                        extra="HEAD html response; GET confirmation required",
                    ),
                    confidence=50,
                )
                continue

            record = self._build_result(
                finding,
                url,
                method,
                response.status_code,
                result,
                content_type=response.headers.get("Content-Type", "").split(";", 1)[0],
                location=response.headers.get("Location", ""),
                evidence=self._response_evidence(response, method_hint, safe_get),
                confidence=self._result_confidence(result, response.status_code),
            )
            last = record

            if result in {"reachable", "auth_required", "redirect"}:
                return record
            if response.status_code not in {405, 501, 403}:
                return record

        return last

    def _request(self, method, url):
        try:
            response = self.http.request(
                method,
                url,
                timeout=self.timeout,
                allow_redirects=False,
                headers=self._verify_headers(),
            )
            return response, None
        except requests.exceptions.RequestException as exc:
            return None, str(exc)[:160]

    def _build_verify_url(self, finding):
        _method, value = self._split_method_value(finding.value)
        value = value.strip()
        if not value:
            return ""
        if value.startswith(("http://", "https://")):
            return value
        if value.startswith("//"):
            scheme = urlparse(finding.source_site).scheme or "https"
            return f"{scheme}:{value}"
        if not value.startswith("/"):
            value = "/" + value
        return urljoin(finding.source_site, value)

    @staticmethod
    def _split_method_value(value):
        parts = str(value or "").strip().split(None, 1)
        if len(parts) == 2 and parts[0].isalpha() and parts[0].upper() == parts[0]:
            return parts[0], parts[1]
        return "", str(value or "").strip()

    @staticmethod
    def _safe_get_allowed(value):
        lower = str(value or "").lower()
        return not any(word in lower for word in GET_DENY_WORDS)

    @staticmethod
    def _has_dynamic_placeholder(url):
        return any(token in url for token in ("${", "{{", "}}", "<", ">", "undefined"))

    @staticmethod
    def _same_origin(left, right):
        a = urlparse(left)
        b = urlparse(right)
        return a.scheme == b.scheme and a.netloc.lower() == b.netloc.lower()

    @staticmethod
    def _classify_response(response, value="", method="HEAD"):
        status = response.status_code
        location = response.headers.get("Location", "").lower()
        auth_header = response.headers.get("WWW-Authenticate", "")

        if status in {401, 403} or auth_header:
            return "auth_required"
        if status == 200 and method == "GET" and JsFindingVerifier._body_has_auth_hint(response):
            return "auth_required"
        if 200 <= status < 300:
            if JsFindingVerifier._looks_like_api_path(value) and JsFindingVerifier._is_html_response(response):
                return "possible_fallback"
            return "reachable"
        if 300 <= status < 400:
            if any(hint in location for hint in AUTH_HINTS):
                return "auth_required"
            return "redirect"
        if status == 404:
            return "not_found"
        if status in {405, 501}:
            return "method_not_allowed"
        if status in {429, 503}:
            return "rate_limited_or_unavailable"
        return "observed"

    @staticmethod
    def _result_confidence(result, status):
        if result in {"reachable", "auth_required"}:
            return 90
        if result == "redirect":
            return 75
        if result == "possible_fallback":
            return 55
        if result in {"method_not_allowed", "not_found"}:
            return 60
        if status is None:
            return 25
        return 50

    @staticmethod
    def _response_evidence(response, method_hint, safe_get, extra=""):
        parts = []
        if method_hint and method_hint not in {"HEAD", "GET", "OPTIONS"}:
            parts.append(f"original_method={method_hint}; not submitted")
        allow = response.headers.get("Allow")
        if allow:
            parts.append(f"allow={allow}")
        if not safe_get:
            parts.append("GET skipped for mutating-looking path")
        if extra:
            parts.append(extra)
        return "; ".join(parts)

    @staticmethod
    def _looks_like_api_path(value):
        _method, path = JsFindingVerifier._split_method_value(value)
        path = (path or "").lower()
        return path.startswith(API_PATH_PREFIXES) or any(
            path.endswith(suffix) for suffix in (".jsp", ".do", ".action", ".json", ".aspx", ".ashx", ".php", ".xml")
        )

    @staticmethod
    def _is_html_response(response):
        content_type = response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        return any(content_type.startswith(item) for item in HTML_TYPES)

    @staticmethod
    def _body_has_auth_hint(response):
        if not JsFindingVerifier._is_html_response(response):
            return False
        text = (response.text or "")[:5000].lower()
        return any(hint in text for hint in AUTH_HINTS) or any(
            word in text for word in ("登录", "认证", "统一身份认证")
        )

    @staticmethod
    def _verify_headers():
        return {
            "User-Agent": "web-recon-js-verifier/1.0",
            "Accept": "text/html,application/json,*/*;q=0.8",
            "Connection": "close",
        }

    @staticmethod
    def _build_result(
        finding,
        url,
        method,
        status,
        result,
        content_type="",
        location="",
        evidence="",
        confidence=0,
    ):
        return JsVerificationRecord(
            source_site=finding.source_site,
            category=finding.category,
            value=finding.value,
            verify_url=url,
            method=method,
            status=status,
            result=result,
            content_type=content_type,
            location=location[:180],
            evidence=evidence[:240],
            confidence=confidence,
        )
