import json
import random
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
from dataclasses import asdict
from pathlib import Path
from queue import Queue

import requests
from bs4 import BeautifulSoup
from tqdm import tqdm

from core.domain_utils import belongs_to_domain, extract_hostname
from core.http_client import HttpClient
from core.models import AppAssetRecord, JsFindingRecord, JsVerificationRecord, SiteRecord


class AssetCollector:
    # 这些模块不受全局 timeout 限制，由模块自身控制运行时长
    NO_TIMEOUT_CATEGORIES = {"active"}

    def __init__(self, modules, max_subdomains=500, module_timeout=25):
        self.modules = modules
        self.max_subdomains = max_subdomains
        self.module_timeout = module_timeout

    def run_stage(self, category, target, subdomains):
        target_mods = [m for m in self.modules if m.category == category]
        if not target_mods:
            return

        print(f"\n[*] 阶段: {category.upper()} 资产收集，启动 {len(target_mods)} 个模块...")

        for module in target_mods:
            if category == "passive":
                time.sleep(random.uniform(0.5, 1.0))

            before_count = len(subdomains)
            print(f"    -> 运行模块: {module.module_name}")

            # active 类模块（如 RecursiveBrute）不设超时，直接同步运行
            if category in self.NO_TIMEOUT_CATEGORIES:
                try:
                    results = module.run(target)
                    status = "ok"
                except Exception as exc:
                    results = []
                    status = "error"
                    print(f"    !! 模块异常: {module.module_name} | {exc}")
            else:
                status, payload = self._run_module_with_timeout(module, target)
                if status == "timeout":
                    print(f"    !! 模块超时: {module.module_name} | 超过 {self.module_timeout} 秒，已跳过")
                    continue
                if status == "error":
                    print(f"    !! 模块异常: {module.module_name} | {payload}")
                    continue
                results = payload

            if not results:
                print(f"    <- 模块完成: {module.module_name} | 新增 0 | 累计 {len(subdomains)}")
                continue

            for item in sorted(set(results)):
                domain = extract_hostname(item.split(",")[0])
                if belongs_to_domain(domain, target):
                    subdomains.add(domain)

            added_count = len(subdomains) - before_count
            print(f"    <- 模块完成: {module.module_name} | 新增 {added_count} | 累计 {len(subdomains)}")

    def _run_module_with_timeout(self, module, target):
        result_queue = Queue(maxsize=1)
        module._timed_out = False

        def runner():
            try:
                result_queue.put(("ok", module.run(target)))
            except Exception as exc:
                result_queue.put(("error", str(exc)))

        thread = threading.Thread(target=runner, daemon=True)
        thread.start()
        thread.join(self.module_timeout)

        if thread.is_alive():
            module._timed_out = True
            return "timeout", None

        if result_queue.empty():
            return "ok", []

        return result_queue.get()


class SubdomainPrioritizer:
    def __init__(self, threads=50):
        self.threads = threads
        self.common_prefixes = {
            "www", "api", "m", "mail", "dev", "test", "admin", "static",
            "cdn", "img", "app", "portal", "open", "beta", "staging",
        }

    def select(self, target, subdomains, limit):
        candidates = sorted(subdomains, key=lambda d: self._sort_key(d, target))
        if not limit:
            limit = len(candidates)
        if not candidates:
            return []

        print(f"\n[*] 阶段: 子域名预筛选，原始唯一结果 {len(candidates)}，目标保留 {limit} 个可解析域名...")
        resolvable = []
        checked = 0
        resolution_pool = min(len(candidates), max(limit * 8, limit + 50))

        with ThreadPoolExecutor(max_workers=min(self.threads, max(1, resolution_pool))) as executor:
            future_map = {
                executor.submit(self._resolve_domain, domain): domain
                for domain in candidates[:resolution_pool]
            }
            for future in as_completed(future_map):
                domain, ip = future.result()
                checked += 1
                if ip:
                    resolvable.append(domain)
                if len(resolvable) >= limit:
                    break

        if len(resolvable) < limit and resolution_pool < len(candidates):
            remaining = candidates[resolution_pool:]
            needed = limit - len(resolvable)
            second_pool = min(len(remaining), max(needed * 10, needed + 100))
            with ThreadPoolExecutor(max_workers=min(self.threads, max(1, second_pool))) as executor:
                future_map = {
                    executor.submit(self._resolve_domain, domain): domain
                    for domain in remaining[:second_pool]
                }
                for future in as_completed(future_map):
                    domain, ip = future.result()
                    checked += 1
                    if ip:
                        resolvable.append(domain)
                    if len(resolvable) >= limit:
                        break

        selected = resolvable[:limit]
        print(
            f"[*] 预筛选完成: 已检查 {checked} 个候选，"
            f"发现 {len(resolvable)} 个可解析域名，"
            f"纳入后续探测 {len(selected)} 个。"
        )
        if selected:
            print(f"[*] 预筛选样本: {', '.join(selected[:10])}")
        return selected

    def _sort_key(self, domain, target):
        labels = domain.split(".")
        depth = max(0, len(labels) - len(target.split(".")))
        first_label = labels[0] if labels else ""
        priority = 0
        if domain == target:
            priority -= 100
        if domain == f"www.{target}":
            priority -= 90
        if first_label in self.common_prefixes:
            priority -= 30
        priority += depth * 10
        priority += max(0, len(first_label) - 12)
        return (priority, depth, len(domain), domain)

    @staticmethod
    def _resolve_domain(domain):
        try:
            return domain, socket.gethostbyname(domain)
        except OSError:
            return domain, None


class AliveChecker:
    def __init__(self, threads=30):
        self.threads = threads
        self.http = HttpClient()
        self.cdn_headers = {
            "Cloudflare": ["cloudflare", "cf-ray"],
            "Akamai": ["akamai", "x-akamai"],
            "AliyunCDN": ["aliyun", "alicdn", "yundun"],
            "TencentCDN": ["tencent", "tcdn", "qcloud"],
            "BaiduCloud": ["yunjiasu", "baidu"],
            "Fastly": ["fastly"],
            "Amazon CloudFront": ["cloudfront", "x-amz-cf-id"],
            "Incapsula": ["incapsula", "visid_incap"],
            "Wangsu": ["chinacache", "wangsu"],
        }

    @staticmethod
    def get_ip_info(domain):
        try:
            ip = socket.gethostbyname(domain)
            if ip:
                c_segment = ".".join(ip.split(".")[:-1]) + ".0/24"
                return ip, c_segment
        except socket.gaierror:
            pass
        return "0.0.0.0", "Unknown"

    def identify_cdn(self, headers):
        header_str = str(headers).lower()
        server_header = headers.get("Server", "").lower()
        for cdn_name, signs in self.cdn_headers.items():
            if any(s in header_str for s in signs) or any(s in server_header for s in signs):
                return cdn_name
        return None

    def run(self, subdomains):
        if not subdomains:
            return []

        print(f"\n[*] 阶段: 存活检测与拓扑分析 (共 {len(subdomains)} 个目标)...")
        queue = Queue()
        for domain in sorted(subdomains):
            queue.put(domain)

        results = []
        results_lock = threading.Lock()
        pbar = tqdm(total=queue.qsize(), desc="分析进度", unit="url")

        def worker():
            headers = self.http.get_headers()
            while True:
                domain = queue.get()
                if domain is None:
                    queue.task_done()
                    break
                try:
                    ip, c_seg = self.get_ip_info(domain)
                    for proto in ("https://", "http://"):
                        try:
                            url = proto + domain
                            response = self.http.get(
                                url,
                                headers=headers,
                                timeout=6,
                                allow_redirects=True,
                            )
                            body_text = self._decoded_text(response)
                            cdn_name = self.identify_cdn(response.headers)
                            soup = BeautifulSoup(body_text, "html.parser")
                            title = (
                                soup.title.string.strip()
                                if soup.title and soup.title.string
                                else "No Title"
                            )
                            site = SiteRecord(
                                url=url,
                                ip=ip,
                                c_seg=c_seg,
                                is_cdn=bool(cdn_name),
                                cdn_provider=cdn_name or "Real_IP",
                                status=response.status_code,
                                server=response.headers.get("Server", "Unknown"),
                                title=title.replace("\n", "").replace("\r", "")[:30],
                                headers=dict(response.headers),
                                content=body_text,
                            )
                            with results_lock:
                                results.append(site)
                            break
                        except requests.exceptions.RequestException:
                            continue
                except Exception:
                    pass
                finally:
                    pbar.update(1)
                    queue.task_done()

        threads = []
        for _ in range(self.threads):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            threads.append(t)

        # 先等所有任务完成，再发退出信号
        queue.join()
        for _ in threads:
            queue.put(None)
        for t in threads:
            t.join()

        pbar.close()
        return results

    @staticmethod
    def _decoded_text(response):
        encoding = (response.encoding or "").lower()
        if not encoding or encoding in {"iso-8859-1", "windows-1252"}:
            response.encoding = response.apparent_encoding or response.encoding
        return response.text


class ReportService:
    def __init__(self, output_dir="reports"):
        self.output_dir = Path(output_dir) if output_dir else Path(".")

    def write(
        self,
        target,
        alive_results,
        port_results,
        app_assets,
        js_findings,
        js_verifications,
        path_results,
    ):
        self.output_dir.mkdir(parents=True, exist_ok=True)
        filename = self.output_dir / f"{target}_final_report.txt"
        print("\n" + "=" * 120)
        print(f" WEB 资产深度识别与网络拓扑报告: {target}")
        print("=" * 120)

        topology = defaultdict(lambda: defaultdict(list))
        for item in alive_results:
            topology[item.c_seg][item.ip].append(item)

        with open(filename, "w", encoding="utf-8") as file:
            file.write(f"Web Recon Report for {target}\n\n")

            for c_seg in sorted(topology.keys(), key=self._sort_c_segment):
                seg_head = f"\nC-Segment: {c_seg}"
                print(seg_head)
                file.write(seg_head + "\n")

                for ip in sorted(topology[c_seg].keys()):
                    first_site = topology[c_seg][ip][0]
                    ip_type = f"[{first_site.cdn_provider}]"
                    ports = port_results.get(ip, [])
                    ip_head = f"  - IP: {ip:<15} {ip_type}"
                    if ports:
                        ip_head += f"  [{len(ports)} ports open]"
                    print(ip_head)
                    file.write(ip_head + "\n")
                    if ports:
                        ports_line = "    ports: " + " | ".join(ports)
                        print(ports_line)
                        file.write(ports_line + "\n")

                    for site in topology[c_seg][ip]:
                        fp_str = ",".join(site.fingerprint[:4])
                        line = (
                            f"    - {site.url:<45} "
                            f"| {site.status:<4} "
                            f"| {fp_str:<25} "
                            f"| {site.title}"
                        )
                        print(line)
                        file.write(line + "\n")

            if app_assets:
                print("\n[+] 发现 App 资产线索:")
                file.write("\n--- App Assets ---\n")
                for asset in self._sort_app_assets(app_assets):
                    line = self._format_app_asset(asset)
                    print(f" [APP] {line}")
                    file.write(line + "\n")

            if js_findings:
                print("\n[+] JS 深度信息收集线索:")
                file.write("\n--- JS Deep Discovery ---\n")
                for line in self._format_js_findings(js_findings):
                    print(f" [JS] {line}")
                    file.write(line + "\n")
                js_detail_file = self._write_js_findings_json(target, js_findings)
                detail_line = f"完整 JS 明细: {js_detail_file.resolve()}"
                print(f" [JS] {detail_line}")
                file.write(detail_line + "\n")

            if js_verifications:
                print("\n[+] JS 发现验证结果:")
                file.write("\n--- JS Finding Verification ---\n")
                for line in self._format_js_verifications(js_verifications):
                    print(f" [JV] {line}")
                    file.write(line + "\n")
                verify_file = self._write_js_verifications_json(target, js_verifications)
                detail_line = f"完整 JS 验证明细: {verify_file.resolve()}"
                print(f" [JV] {detail_line}")
                file.write(detail_line + "\n")

            if path_results:
                print("\n[+] 发现有效路径/入口 (已过滤 CDN 噪音):")
                file.write("\n--- Useful Paths ---\n")
                for path in sorted(set(path_results)):
                    print(f" [PATH] {path}")
                    file.write(path + "\n")

        print("\n" + "=" * 120)
        print(f"报告已生成: {filename.resolve()}")

    @staticmethod
    def _sort_app_assets(app_assets):
        return sorted(
            app_assets,
            key=lambda item: (
                -item.confidence,
                item.platform,
                item.asset_type,
                item.identifier,
                item.source_site,
            ),
        )

    @staticmethod
    def _format_app_asset(asset: AppAssetRecord):
        level = ReportService._app_asset_level(asset.confidence)
        parts = [
            level,
            asset.platform,
            asset.asset_type,
            asset.identifier,
            f"source={asset.source_site}",
        ]
        if asset.evidence_count > 1:
            parts.append(f"seen={asset.evidence_count}")
        if asset.url:
            parts.append(f"url={asset.url}")
        if asset.note:
            parts.append(f"note={asset.note}")
        return " | ".join(parts)

    @staticmethod
    def _app_asset_level(confidence):
        if confidence >= 90:
            return "HIGH"
        if confidence >= 65:
            return "MEDIUM"
        return "LOW"

    @staticmethod
    def _sort_c_segment(c_seg):
        return (c_seg == "Unknown", c_seg)

    @staticmethod
    def _format_js_findings(js_findings: list[JsFindingRecord]):
        grouped = defaultdict(list)
        for item in js_findings:
            grouped[item.source_site].append(item)

        lines = []
        for site in sorted(grouped):
            lines.append(f"{site}")
            by_category = defaultdict(list)
            for item in grouped[site]:
                by_category[item.category].append(item)

            for category in sorted(by_category, key=ReportService._js_category_order):
                findings = sorted(
                    by_category[category],
                    key=lambda finding: (-finding.confidence, finding.value),
                )
                limit = ReportService._js_display_limit(category)
                for item in findings[:limit]:
                    parts = [
                        f"  {item.category}",
                        item.value,
                        f"confidence={item.confidence}",
                    ]
                    if item.evidence_count > 1:
                        parts.append(f"seen={item.evidence_count}")
                    if item.source_url:
                        parts.append(f"source={ReportService._compact_source(item.source_url)}")
                    if item.evidence:
                        parts.append(f"evidence={item.evidence}")
                    lines.append(" | ".join(parts))
                if len(findings) > limit:
                    lines.append(f"  {category} | ... 另有 {len(findings) - limit} 条，见完整 JSON 明细")
        return lines

    @staticmethod
    def _js_category_order(category):
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

    @staticmethod
    def _compact_source(source_url):
        if len(source_url) <= 90:
            return source_url
        return source_url[:42] + "..." + source_url[-42:]

    @staticmethod
    def _js_display_limit(category):
        limits = {
            "API接口": 30,
            "前端路由": 25,
            "业务线索": 12,
            "表单入口": 12,
            "外部系统": 10,
            "存储键": 12,
            "JS文件": 8,
        }
        return limits.get(category, 20)

    def _write_js_findings_json(self, target, js_findings):
        filename = self.output_dir / f"{target}_js_findings.json"
        data = [asdict(item) for item in js_findings]
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        return filename

    @staticmethod
    def _format_js_verifications(js_verifications: list[JsVerificationRecord]):
        summary = defaultdict(int)
        by_site = defaultdict(list)
        for item in js_verifications:
            summary[item.result] += 1
            by_site[item.source_site].append(item)

        lines = [
            "summary " + ", ".join(f"{key}={summary[key]}" for key in sorted(summary))
        ]
        for site in sorted(by_site):
            lines.append(f"{site}")
            for item in sorted(
                by_site[site],
                key=lambda record: (
                    ReportService._verification_result_order(record.result),
                    record.status if record.status is not None else 999,
                    record.value,
                ),
            )[:40]:
                status = item.status if item.status is not None else "-"
                parts = [
                    f"  {item.result}",
                    f"{item.method} {status}",
                    item.value,
                    f"url={ReportService._compact_source(item.verify_url)}",
                ]
                if item.content_type:
                    parts.append(f"type={item.content_type}")
                if item.location:
                    parts.append(f"location={ReportService._compact_source(item.location)}")
                if item.evidence:
                    parts.append(f"evidence={item.evidence}")
                lines.append(" | ".join(parts))
            if len(by_site[site]) > 40:
                lines.append(f"  ... 另有 {len(by_site[site]) - 40} 条，见完整 JSON 明细")
        return lines

    @staticmethod
    def _verification_result_order(result):
        order = {
            "reachable": 1,
            "auth_required": 2,
            "redirect": 3,
            "possible_fallback": 4,
            "method_not_allowed": 5,
            "not_found": 6,
            "rate_limited_or_unavailable": 7,
            "observed": 8,
            "request_error": 9,
            "skipped_cross_origin": 10,
        }
        return order.get(result, 99)

    def _write_js_verifications_json(self, target, js_verifications):
        filename = self.output_dir / f"{target}_js_verifications.json"
        data = [asdict(item) for item in js_verifications]
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        return filename
