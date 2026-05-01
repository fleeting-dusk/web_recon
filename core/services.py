import random
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
from pathlib import Path
from queue import Queue

import requests
from bs4 import BeautifulSoup
from tqdm import tqdm

from core.http_client import HttpClient
from core.models import AppAssetRecord, SiteRecord


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
                domain = item.split(",")[0].strip().lower()
                if target in domain:
                    subdomains.add(domain)

            added_count = len(subdomains) - before_count
            print(f"    <- 模块完成: {module.module_name} | 新增 {added_count} | 累计 {len(subdomains)}")

    def _run_module_with_timeout(self, module, target):
        result_queue = Queue(maxsize=1)

        def runner():
            try:
                result_queue.put(("ok", module.run(target)))
            except Exception as exc:
                result_queue.put(("error", str(exc)))

        thread = threading.Thread(target=runner, daemon=True)
        thread.start()
        thread.join(self.module_timeout)

        if thread.is_alive():
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
                            cdn_name = self.identify_cdn(response.headers)
                            soup = BeautifulSoup(response.content, "html.parser")
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
                                content=response.text,
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


class ReportService:
    def write(self, target, alive_results, port_results, app_assets, path_results):
        filename = f"{target}_final_report.txt"
        print("\n" + "=" * 120)
        print(f" 🚀 WEB 资产深度识别与网络拓扑报告: {target}")
        print("=" * 120)

        topology = defaultdict(lambda: defaultdict(list))
        for item in alive_results:
            topology[item.c_seg][item.ip].append(item)

        with open(filename, "w", encoding="utf-8") as file:
            file.write(f"Web Recon Report for {target}\n\n")

            for c_seg in sorted(topology.keys()):
                if c_seg == "Unknown":
                    continue

                seg_head = f"\n📦 C-Segment: {c_seg}"
                print(seg_head)
                file.write(seg_head + "\n")

                for ip in sorted(topology[c_seg].keys()):
                    first_site = topology[c_seg][ip][0]
                    ip_type = f"[{first_site.cdn_provider}]"
                    ports = port_results.get(ip, [])
                    ip_head = f"  ├── 🌐 IP: {ip:<15} {ip_type}"
                    if ports:
                        ip_head += f"  [{len(ports)} ports open]"
                    print(ip_head)
                    file.write(ip_head + "\n")
                    if ports:
                        ports_line = "  │    ├── 🔌 " + " | ".join(ports)
                        print(ports_line)
                        file.write(ports_line + "\n")

                    for site in topology[c_seg][ip]:
                        fp_str = ",".join(site.fingerprint[:3])
                        line = (
                            f"  │    └── {site.url:<45} "
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
                    print(f" [📱] {line}")
                    file.write(line + "\n")

            if path_results:
                print("\n[!] 发现敏感路径 (已过滤 CDN 噪音):")
                file.write("\n--- Sensitive Paths ---\n")
                for path in path_results:
                    print(f" [🔥] {path}")
                    file.write(path + "\n")

        print("\n" + "=" * 120)
        print(f"📂 拓扑报告已生成: {Path(filename).resolve()}")

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
