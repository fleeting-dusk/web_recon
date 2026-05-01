import random
import string
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue

import dns.resolver
import requests
from dns.exception import DNSException
from tqdm import tqdm

from core.base_module import BaseModule

# 泛解析探测次数
WILDCARD_PROBE_COUNT = 5

# 第1层存活检测并发数
ALIVE_CHECK_THREADS = 50

# 存活检测超时（秒）
ALIVE_CHECK_TIMEOUT = 5


def _make_resolver():
    r = dns.resolver.Resolver()
    r.nameservers = ['8.8.8.8', '114.114.114.114', '223.5.5.5']
    r.timeout = 1
    r.lifetime = 2
    return r


def _random_label(length=16):
    return ''.join(random.choices(string.ascii_lowercase, k=length))


def _ip_to_cseg(ip):
    return ".".join(ip.split(".")[:3])


class RecursiveBrute(BaseModule):
    def __init__(self):
        super().__init__()
        self.category = "active"
        self.thread_count = 60
        self.max_depth = 3

        self.main_dict = self.resolve_data_path("subdomains-200.txt")
        self.mini_dict = [
            "dev", "test", "api", "internal", "staff", "git",
            "oa", "vpn", "m", "web", "app", "admin", "mail", "ftp",
        ]

        self.found_domains = set()
        self.wildcard_cache = {}
        self.wildcard_cache_lock = threading.Lock()
        self.results_lock = threading.Lock()

    # ------------------------------------------------------------------
    # 泛解析检测（C段轮询版）
    # ------------------------------------------------------------------

    def get_wildcard_info(self, domain, resolver):
        with self.wildcard_cache_lock:
            if domain in self.wildcard_cache:
                return self.wildcard_cache[domain]

        wildcard_ips = set()
        wildcard_csegs = set()
        resolved_count = 0

        for _ in range(WILDCARD_PROBE_COUNT):
            label = _random_label()
            test_fqdn = f"{label}.{domain}"
            try:
                answers = resolver.resolve(test_fqdn, 'A')
                for rdata in answers:
                    ip = str(rdata)
                    wildcard_ips.add(ip)
                    wildcard_csegs.add(_ip_to_cseg(ip))
                resolved_count += 1
            except DNSException:
                pass

        is_wildcard = resolved_count >= (WILDCARD_PROBE_COUNT // 2 + 1)
        result = {
            "is_wildcard": is_wildcard,
            "ips": wildcard_ips,
            "csegs": wildcard_csegs,
        }

        with self.wildcard_cache_lock:
            self.wildcard_cache[domain] = result
        return result

    def is_wildcard_hit(self, resolved_ips, wildcard_info):
        if not wildcard_info["is_wildcard"]:
            return False
        resolved_csegs = {_ip_to_cseg(ip) for ip in resolved_ips}
        if resolved_ips <= wildcard_info["ips"]:
            return True
        if resolved_csegs <= wildcard_info["csegs"]:
            return True
        return False

    # ------------------------------------------------------------------
    # 轻量级HTTP存活检测（仅第1层使用）
    # ------------------------------------------------------------------

    def _http_alive(self, domain):
        """
        轻量级存活检测，只判断能否建立HTTP/HTTPS连接。
        返回 True/False，不做指纹识别。
        """
        for proto in ("https://", "http://"):
            try:
                resp = requests.head(
                    proto + domain,
                    timeout=ALIVE_CHECK_TIMEOUT,
                    allow_redirects=True,
                    verify=False,
                )
                # 只要有响应（包括4xx/5xx）都认为存活
                if resp.status_code < 600:
                    return True
            except requests.exceptions.RequestException:
                continue
        return False

    def _alive_filter(self, domains, desc="存活检测"):
        """
        对域名列表做HTTP存活过滤，返回存活的域名列表。
        """
        if not domains:
            return []

        alive = []
        alive_lock = threading.Lock()

        pbar = tqdm(total=len(domains), desc=desc, unit="url", leave=False)

        with ThreadPoolExecutor(max_workers=ALIVE_CHECK_THREADS) as executor:
            future_map = {
                executor.submit(self._http_alive, domain): domain
                for domain in domains
            }
            for future in as_completed(future_map):
                domain = future_map[future]
                try:
                    if future.result():
                        with alive_lock:
                            alive.append(domain)
                except Exception:
                    pass
                finally:
                    pbar.update(1)

        pbar.close()
        self.log(f"{desc}完成：{len(domains)} 个域名中发现 {len(alive)} 个存活。")
        return alive

    # ------------------------------------------------------------------
    # Worker（DNS爆破）
    # ------------------------------------------------------------------

    def worker(self, q, pbar):
        resolver = _make_resolver()

        while True:
            task = q.get()
            if task is None:
                q.task_done()
                break

            parent, sub = task
            target = f"{sub}.{parent}"
            try:
                wildcard_info = self.get_wildcard_info(parent, resolver)
                answers = resolver.resolve(target, 'A')
                resolved_ips = {str(r) for r in answers}

                if not self.is_wildcard_hit(resolved_ips, wildcard_info):
                    with self.results_lock:
                        self.found_domains.add(target)

            except DNSException:
                pass
            except Exception:
                pass
            finally:
                pbar.update(1)
                q.task_done()

    # ------------------------------------------------------------------
    # 单层DNS爆破
    # ------------------------------------------------------------------

    def _run_layer(self, parents, word_list, depth):
        q = Queue()
        for p in parents:
            for s in word_list:
                q.put((p, s))

        if q.qsize() == 0:
            return []

        pbar = tqdm(
            total=q.qsize(),
            desc=f"Level {depth} DNS",
            unit="q",
            leave=False,
        )

        snapshot_before = set(self.found_domains)

        threads = []
        for _ in range(self.thread_count):
            t = threading.Thread(target=self.worker, args=(q, pbar))
            t.daemon = True
            t.start()
            threads.append(t)

        q.join()
        for _ in threads:
            q.put(None)
        for t in threads:
            t.join()

        pbar.close()

        return sorted(self.found_domains - snapshot_before)

    # ------------------------------------------------------------------
    # 主流程
    # ------------------------------------------------------------------

    def run(self, target):
        if not self.main_dict.exists():
            self.log("错误：找不到主字典文件")
            return []

        with open(self.main_dict, 'r', encoding='utf-8') as f:
            full_subs = [
                line.strip()
                for line in f
                if line.strip() and not line.startswith('#')
            ]

        # 检测根域名泛解析
        probe_resolver = _make_resolver()
        root_info = self.get_wildcard_info(target, probe_resolver)
        if root_info["is_wildcard"]:
            self.log(
                f"检测到泛解析（IP池轮询型），"
                f"泛解析C段: {root_info['csegs']}，已启用C段过滤。"
            )
        else:
            self.log("未检测到泛解析，正常爆破。")

        current_parents = [target]

        for depth in range(1, self.max_depth + 1):
            self.log(
                f"--- 正在开启第 {depth} 层爆破 "
                f"(当前目标基数: {len(current_parents)}) ---"
            )

            word_list = full_subs if depth == 1 else self.mini_dict
            new_domains = self._run_layer(current_parents, word_list, depth)

            self.log(
                f"第 {depth} 层爆破结束，"
                f"目前总计发现 {len(self.found_domains)} 个域名。"
            )

            if not new_domains:
                self.log(f"第 {depth} 层未发现新资产，停止递归。")
                break

            if depth == 1:
                # 第1层做HTTP存活检测，只把存活的作为第2层父域名
                self.log(f"第 {depth} 层进行存活检测，过滤无效父域名...")
                current_parents = self._alive_filter(new_domains, desc="Layer1 存活检测")
                if not current_parents:
                    self.log("第1层存活检测后无存活域名，停止递归。")
                    break
                self.log(f"第1层存活过滤后，保留 {len(current_parents)} 个域名作为第2层父域名。")
            else:
                # 第2、3层直接用DNS结果作为下一层父域名
                current_parents = new_domains

        self.results = sorted(self.found_domains)
        return self.results