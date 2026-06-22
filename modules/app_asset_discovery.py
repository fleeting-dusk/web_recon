"""
文件名: app_asset_discovery.py
功能:   App 资产线索发现模块。从存活站点的页面与关联文件中，挖掘其移动端 App 的线索：
        - 页面链接中的 APK 下载、App Store/应用市场跳转；
        - Web App Manifest 里的 related_applications / PWA 信息；
        - /.well-known/assetlinks.json（Android 应用关联）；
        - apple-app-site-association（iOS 通用链接）。
        最后对多来源线索做合并、置信度加权与强类型过滤。
作者:   李豪
版本:   v1.0
创建时间: 2026-06
"""

import json
import re
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from core.base_module import BaseModule
from core.models import AppAssetRecord


# 匹配 .apk 下载链接
APK_PATTERN = re.compile(r"\.apk(?:$|[?#])", re.I)
# 从苹果商店链接中提取数字 AppID（形如 /id123456789）
APPLE_APP_ID_PATTERN = re.compile(r"/id(\d{5,})", re.I)


class AppAssetDiscovery(BaseModule):
    """App 资产线索发现模块。"""

    # 强类型线索：只有这些「可信度高」的资产类型才会进入最终结果
    STRONG_ASSET_TYPES = {
        "APK下载",
        "App Store",
        "应用市场",
        "Manifest关联应用",
        "PWA",
        "AssetLinks",
        "Universal Links",
    }

    def __init__(self):
        super().__init__()
        self.category = "app_asset"
        self.store_hosts = {
            "apps.apple.com": ("iOS", "App Store"),
            "itunes.apple.com": ("iOS", "App Store"),
            "sj.qq.com": ("Android", "应用市场"),
            "a.app.qq.com": ("Android", "应用市场"),
            "appgallery.huawei.com": ("Android", "应用市场"),
            "www.coolapk.com": ("Android", "应用市场"),
            "m.coolapk.com": ("Android", "应用市场"),
            "d.taptap.cn": ("Android", "应用市场"),
            "www.taptap.cn": ("Android", "应用市场"),
        }
        self.assetlinks_paths = [
            "/.well-known/assetlinks.json",
        ]
        self.aasa_paths = [
            "/.well-known/apple-app-site-association",
            "/apple-app-site-association",
        ]

    def run(self, alive_results):
        found = []
        for site in alive_results:
            if site.status >= 400:
                continue

            page_url = site.url
            soup = BeautifulSoup(site.content or "", "html.parser")

            for record in self._extract_from_html(site, soup):
                found.append(record)

            for record in self._extract_from_manifest(page_url, soup):
                found.append(record)

            for record in self._extract_assetlinks(page_url):
                found.append(record)

            for record in self._extract_apple_association(page_url):
                found.append(record)

        self.results = self._finalize_records(found)
        self.log(f"App 资产发现完成，共识别 {len(self.results)} 条线索。")
        return self.results

    def _extract_from_html(self, site, soup):
        found = set()
        for tag in soup.find_all(["a", "link", "script", "iframe", "meta"]):
            candidates = []
            for attr in ("href", "src", "content", "data-url"):
                value = tag.get(attr)
                if value:
                    candidates.append(value.strip())

            for raw_url in candidates:
                if not raw_url or raw_url.startswith("javascript:"):
                    continue
                full_url = urljoin(site.url, raw_url)
                parsed = urlparse(full_url)
                host = parsed.netloc.lower()
                path = parsed.path or ""

                if APK_PATTERN.search(full_url):
                    identifier = path.rsplit("/", 1)[-1] or "unknown.apk"
                    found.add(self._build_record(
                        source_site=site.url,
                        platform="Android",
                        asset_type="APK下载",
                        identifier=identifier,
                        url=full_url,
                        note=site.title,
                        confidence=95,
                    ))
                    continue

                if host in self.store_hosts:
                    platform, asset_type = self.store_hosts[host]
                    identifier = self._build_store_identifier(host, full_url, tag.get_text(" ", strip=True))
                    found.add(self._build_record(
                        source_site=site.url,
                        platform=platform,
                        asset_type=asset_type,
                        identifier=identifier,
                        url=full_url,
                        note=site.title,
                        confidence=90,
                    ))

        return found

    def _extract_from_manifest(self, page_url, soup):
        found = set()
        for tag in soup.find_all("link", rel=True):
            rel_value = " ".join(tag.get("rel", []))
            if "manifest" not in rel_value.lower():
                continue
            href = tag.get("href", "").strip()
            if not href:
                continue

            manifest_url = urljoin(page_url, href)
            try:
                res = self.safe_request(manifest_url, timeout=6, allow_redirects=True)
                if res.status_code != 200:
                    continue
                data = res.json()
            except Exception:
                continue

            app_name = (data.get("name") or data.get("short_name") or "").strip()
            for item in data.get("related_applications", []):
                platform = (item.get("platform") or "").strip()
                item_url = (item.get("url") or "").strip()
                item_id = (item.get("id") or item_url or app_name or manifest_url).strip()
                found.add(self._build_record(
                    source_site=page_url,
                    platform=self._map_manifest_platform(platform),
                    asset_type="Manifest关联应用",
                    identifier=item_id,
                    url=item_url or manifest_url,
                    note=app_name or "web manifest",
                    confidence=80,
                ))

            if app_name:
                found.add(self._build_record(
                    source_site=page_url,
                    platform="Web",
                    asset_type="PWA",
                    identifier=app_name,
                    url=manifest_url,
                    note="manifest.json",
                    confidence=70,
                ))

        return found

    def _extract_assetlinks(self, page_url):
        found = set()
        root = self._root_url(page_url)
        for path in self.assetlinks_paths:
            url = root + path
            try:
                res = self.safe_request(url, timeout=6, allow_redirects=True)
                if res.status_code != 200:
                    continue
                data = res.json()
            except Exception:
                continue

            if not isinstance(data, list):
                continue

            for item in data:
                target = item.get("target") or {}
                package_name = (target.get("package_name") or "").strip()
                fingerprints = target.get("sha256_cert_fingerprints") or []
                if not package_name:
                    continue
                note = ""
                if fingerprints:
                    note = f"sha256={fingerprints[0][:16]}..."
                found.add(self._build_record(
                    source_site=page_url,
                    platform="Android",
                    asset_type="AssetLinks",
                    identifier=package_name,
                    url=url,
                    note=note,
                    confidence=95,
                ))
        return found

    def _extract_apple_association(self, page_url):
        found = set()
        root = self._root_url(page_url)
        for path in self.aasa_paths:
            url = root + path
            try:
                res = self.safe_request(url, timeout=6, allow_redirects=True)
                if res.status_code != 200:
                    continue
                data = json.loads(res.text)
            except Exception:
                continue

            applinks = data.get("applinks") or {}
            details = applinks.get("details") or []
            for item in details:
                app_ids = item.get("appIDs") or []
                if not app_ids and item.get("appID"):
                    app_ids = [item.get("appID")]
                for app_id in app_ids:
                    found.add(self._build_record(
                        source_site=page_url,
                        platform="iOS",
                        asset_type="Universal Links",
                        identifier=app_id,
                        url=url,
                        note="apple-app-site-association",
                        confidence=95,
                    ))
        return found

    def _finalize_records(self, records):
        merged = {}
        for record in records:
            key = self._record_key(record)
            bucket = merged.setdefault(
                key,
                {
                    "record": record,
                    "sources": {record.source_site},
                    "notes": {record.note} if record.note else set(),
                    "confidence": record.confidence,
                },
            )
            if bucket["record"] is not record:
                bucket["sources"].add(record.source_site)
                if record.note:
                    bucket["notes"].add(record.note)
                bucket["confidence"] = min(100, max(bucket["confidence"], record.confidence) + 5)
                if len(record.url) > len(bucket["record"].url):
                    bucket["record"] = record

        finalized = []
        for item in merged.values():
            source_list = sorted(item["sources"])
            evidence_count = len(source_list)
            confidence = min(100, item["confidence"] + max(0, evidence_count - 1) * 5)
            note = "; ".join(sorted(item["notes"]))[:120]
            primary = item["record"]
            if primary.asset_type not in self.STRONG_ASSET_TYPES:
                continue
            finalized.append(
                AppAssetRecord(
                    source_site=source_list[0],
                    platform=primary.platform,
                    asset_type=primary.asset_type,
                    identifier=primary.identifier,
                    url=primary.url,
                    note=note,
                    confidence=confidence,
                    evidence_count=evidence_count,
                )
            )

        return sorted(
            finalized,
            key=lambda item: (
                -item.confidence,
                item.platform,
                item.asset_type,
                item.identifier,
            ),
        )

    @staticmethod
    def _record_key(record):
        if record.url:
            return (
                record.platform,
                record.asset_type,
                record.identifier.lower(),
                record.url.lower(),
            )
        return (
            record.platform,
            record.asset_type,
            record.identifier.lower(),
            "",
        )

    @staticmethod
    def _build_record(source_site, platform, asset_type, identifier, url="", note="", confidence=0):
        return AppAssetRecord(
            source_site=source_site,
            platform=platform,
            asset_type=asset_type,
            identifier=identifier,
            url=url,
            note=note,
            confidence=confidence,
        )

    @staticmethod
    def _map_manifest_platform(platform):
        value = platform.lower()
        if "play" in value or "android" in value:
            return "Android"
        if "itunes" in value or "ios" in value:
            return "iOS"
        return platform or "Web"

    @staticmethod
    def _build_store_identifier(host, full_url, text):
        if "apple.com" in host:
            match = APPLE_APP_ID_PATTERN.search(full_url)
            if match:
                return f"AppID {match.group(1)}"
        if text:
            return text[:60]
        parsed = urlparse(full_url)
        return parsed.path.rsplit("/", 1)[-1] or full_url

    @staticmethod
    def _root_url(url):
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"
