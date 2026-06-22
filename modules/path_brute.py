"""
文件名: path_brute.py
功能:   路径（目录/文件）爆破模块。核心亮点是「基准行为 + 误报过滤」：先用一批随机
        不存在的路径探测站点对 404/通配/WAF 的真实反应，建立基准画像；再用字典爆破，
        把状态码与 size/跳转落在基准范围内的响应判为误报丢弃，从而在存在通配响应或
        WAF 的站点上仍能筛出真正有意义的路径。同时识别常见 WAF、过滤自跳转噪音。
作者:   李豪
版本:   v1.0
创建时间: 2026-06
"""

import random
import re
import string
import threading
from pathlib import Path
from queue import Queue
from urllib.parse import urlparse

import requests
from tqdm import tqdm

from core.base_module import BaseModule


# 基准探测路径模板，覆盖不同路径格式（{rnd} 会被替换为随机串，保证路径必然不存在）
BASELINE_PROBES = [
    "/this_not_exist_{rnd}",
    "/wp-admin_{rnd}_fake",
    "/.env_{rnd}_fake",
    "/admin_{rnd}/login.php",
    "/.{rnd}_hidden",
    "/backup_{rnd}.zip",
    "/api/{rnd}/health",
]

# size相似判定：绝对差值 或 比例差值
SIZE_ABS_THRESHOLD = 150
SIZE_RATIO_THRESHOLD = 0.08

# 只记录这些有资产识别意义的状态码
INTERESTING_CODES = {200, 204, 301, 302, 401, 403, 405}

def _random_str(length=10):
    """生成随机字符串，用于拼出必然不存在的基准探测路径。"""
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))


def _sizes_similar(a, b):
    """判断两个响应体大小是否相近（绝对差或比例差任一达标即认为相似）。"""
    diff = abs(a - b)
    if diff < SIZE_ABS_THRESHOLD:
        return True
    if max(a, b) > 0 and diff / max(a, b) < SIZE_RATIO_THRESHOLD:
        return True
    return False


class SiteBaseline:
    """
    记录站点对随机不存在路径的响应行为。
    核心思路：对每种状态码，记录其size分布；
    扫描时如果响应的状态码+size落在基准范围内，视为误报过滤掉。
    """

    def __init__(self):
        self.waf_name = None
        # {status_code: [size1, size2, ...]}
        self._samples: dict[int, list[int]] = {}
        self._redirect_locations: dict[int, list[str]] = {}
        self.status_profiles: dict[int, dict[str, object]] = {}
        # 最终判定的通配状态码（超过半数探测返回同一状态码）
        self.dominant_status: int | None = None
        self.dominant_avg_size: float = 0

    def record(self, status, size, location=None):
        """记录一次基准探测的结果（状态码、响应体大小、跳转目标）。"""
        self._samples.setdefault(status, []).append(size)
        if location:
            self._redirect_locations.setdefault(status, []).append(location)

    def finalize(self):
        """汇总基准样本：为每个状态码算平均 size 与跳转签名，并判定是否存在通配状态码。"""
        if not self._samples:
            return

        total = sum(len(v) for v in self._samples.values())
        for status, sizes in sorted(
            self._samples.items(),
            key=lambda item: (-len(item[1]), item[0]),
        ):
            avg_size = sum(sizes) / len(sizes)
            locations = self._redirect_locations.get(status, [])
            location_signature = None
            if locations and len(locations) / len(sizes) >= 0.5:
                location_signature = _most_common(locations)
            self.status_profiles[status] = {
                "count": len(sizes),
                "avg_size": avg_size,
                "location": location_signature,
            }
            # 超过40%的探测都返回同一状态码 → 认为是通配（站点对不存在路径统一应答）
            if len(sizes) / total >= 0.4:
                self.dominant_status = status
                self.dominant_avg_size = avg_size

    def is_false_positive(self, status, size, location=None):
        """
        判断扫描中某个响应是否为误报。
        条件：状态码与基准画像一致，且响应体大小相近、或跳转目标与基准一致。
        """
        profile = self.status_profiles.get(status)
        if not profile:
            return False

        if _sizes_similar(size, profile["avg_size"]):
            return True

        baseline_location = profile.get("location")
        if baseline_location and location and baseline_location == location:
            return True

        return False


def _most_common(items):
    """返回列表中出现次数最多的元素（用于提取最常见的跳转目标作为基准签名）。"""
    counts = {}
    for item in items:
        counts[item] = counts.get(item, 0) + 1
    return max(counts, key=counts.get)


def _normalize_location(location):
    """把跳转目标 URL 归一化为「host+path+排序后的参数名」，便于跨请求比较是否同一跳转。"""
    if not location:
        return ""
    parsed = urlparse(location)
    path = parsed.path or "/"
    query_keys = "&".join(sorted(kv.split("=", 1)[0] for kv in parsed.query.split("&") if kv))
    host = parsed.netloc.lower()
    if query_keys:
        return f"{host}{path}?{query_keys}"
    return f"{host}{path}"


def _is_self_redirect_noise(request_url, location):
    """判断是否为「跳转回自身同路径」的无意义跳转（同主机同路径），用于过滤噪音。"""
    if not location:
        return False

    req = urlparse(request_url)
    loc = urlparse(location)
    if not loc.netloc:
        return False

    req_host = req.hostname or ""
    loc_host = loc.hostname or ""
    if req_host != loc_host:
        return False

    req_path = req.path or "/"
    loc_path = loc.path or "/"
    return req_path == loc_path


class PathBrute(BaseModule):
    """带基准误报过滤与 WAF 识别的路径爆破模块。"""

    def __init__(self):
        super().__init__()
        self.category = "path_scan"
        self.thread_count = 10                 # 爆破线程数（默认较保守，降低冲击）
        self.max_paths = None                  # 每站最大路径数，None 表示用完整字典
        self.dict_path = self.resolve_data_path("ai_studio_code.txt")  # 默认路径字典
        self.headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            )
        }
        self.results_lock = threading.Lock()
        self.waf_signatures = {
            "VMware NSX ALB": ["VMware NSX ALB", "Avi Vantage"],
            "Safedog": ["safedog", "404.safedog.cn"],
            "AliyunWAF": ["aliyungf_tc", "error_code_504_center"],
            "BT-Panel": ["BT-Panel", "站点创建成功", "宝塔面板"],
            "Sangfor": ["NGAF", "SANGFOR"],
            "Fortigate": ["FortiGate", "Web Filter Block"],
            "Cloudflare": ["Cloudflare RAY ID", "cf-browser-verification"],
        }

    def configure(self, dict_path=None, thread_count=None, max_paths=None):
        """由控制器下发的可选配置：自定义字典路径、线程数、每站最大路径数。"""
        if dict_path:
            candidate = Path(dict_path)
            if not candidate.is_absolute():
                candidate = self.resolve_data_path(str(dict_path))
            self.dict_path = candidate
        if thread_count:
            self.thread_count = max(1, int(thread_count))
        if max_paths:
            self.max_paths = max(1, int(max_paths))

    def identify_waf(self, content, headers):
        """根据响应正文/响应头中的特征关键字识别 WAF 厂商，命中返回名称否则 None。"""
        html_str = content.decode('utf-8', errors='ignore').lower()
        header_str = str(headers).lower()
        for waf_name, keywords in self.waf_signatures.items():
            for kw in keywords:
                if kw.lower() in html_str or kw.lower() in header_str:
                    return waf_name
        return None

    # ------------------------------------------------------------------
    # 基准探测
    # ------------------------------------------------------------------

    def get_baseline(self, base_url):
        """对单个站点发起一组随机不存在路径的探测，建立其「正常的不存在响应」基准画像。"""
        baseline = SiteBaseline()
        url_base = base_url.rstrip('/')

        for tpl in BASELINE_PROBES:
            path = tpl.format(rnd=_random_str())
            try:
                res = self.safe_request(
                    url_base + path,
                    headers=self.headers,
                    timeout=5,
                    allow_redirects=False,
                )
                if not baseline.waf_name:
                    baseline.waf_name = self.identify_waf(res.content, res.headers)
                baseline.record(
                    res.status_code,
                    len(res.content),
                    _normalize_location(res.headers.get("Location", "").strip()),
                )
            except requests.exceptions.RequestException:
                pass

        baseline.finalize()
        return baseline

    # ------------------------------------------------------------------
    # 扫描Worker
    # ------------------------------------------------------------------

    def scan_worker(self, q, pbar):
        """
        爆破工作线程：逐个请求「站点 + 字典路径」，对响应做误报过滤与分类。
        - 命中基准画像 → 误报，丢弃；
        - 200/204/401/403/405 → 记为有效路径（附带 WAF/标题/类型标签）；
        - 301/302 → 过滤自跳转等噪音后记录跳转目标。
        """
        while True:
            task = q.get()
            if task is None:  # 哨兵值，退出线程
                q.task_done()
                break

            base_url, path, baseline = task
            url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"

            try:
                res = self.safe_request(
                    url,
                    headers=self.headers,
                    timeout=5,
                    allow_redirects=False,
                )
                status = res.status_code
                size = len(res.content)
                location = _normalize_location(res.headers.get('Location', '').strip())

                if status not in INTERESTING_CODES:
                    pass

                # 误报过滤
                elif baseline.is_false_positive(status, size, location):
                    pass

                elif status in (200, 204, 401, 403, 405):
                    waf = self.identify_waf(res.content, res.headers)
                    tag = self._build_result_tag(status, res, waf)
                    with self.results_lock:
                        self.results.append(f"{url} [{tag}] (Size:{size})")

                elif status in (301, 302):
                    # 过滤跳转到自身或main.psp之类的无意义跳转
                    raw_location = res.headers.get('Location', '').strip()
                    if (
                        raw_location
                        and not raw_location.endswith('main.psp')
                        and not _is_self_redirect_noise(url, raw_location)
                    ):
                        with self.results_lock:
                            self.results.append(
                                f"{url} [{status} -> {raw_location[:80]}]"
                            )

            except requests.exceptions.RequestException:
                pass
            finally:
                pbar.update(1)
                q.task_done()

    # ------------------------------------------------------------------
    # 主流程
    # ------------------------------------------------------------------

    def run(self, alive_urls):
        """
        路径爆破主流程：加载字典 -> 为每个站点建立基准画像 -> 多线程笛卡尔积爆破 ->
        汇总有效路径。alive_urls 为待爆破的真实站点 URL 列表。
        """
        self.results = []
        dict_path = self._resolve_dict_path()
        if not dict_path.exists():
            self.log(f"错误：找不到路径字典文件: {dict_path}")
            return []

        paths = self._load_paths(dict_path)
        if self.max_paths:
            paths = paths[: self.max_paths]
        self.log(
            f"本轮路径字典: {dict_path.name} | 路径数: {len(paths)} | 线程数: {self.thread_count}"
        )

        # 基准探测
        self.log("正在对各站点进行基准行为探测...")
        baselines = {}
        for url in alive_urls:
            bl = self.get_baseline(url)
            baselines[url] = bl
            status_info = (
                f"通配状态码={bl.dominant_status} "
                f"avgSize={int(bl.dominant_avg_size)}"
                if bl.dominant_status else "无明显通配行为"
            )
            waf_info = f" | WAF={bl.waf_name}" if bl.waf_name else ""
            self.log(f"    {url} → {status_info}{waf_info}")

        # 任务分发
        q = Queue()
        for url in alive_urls:
            for p in paths:
                q.put((url, p, baselines[url]))

        pbar = tqdm(total=q.qsize(), desc="Scanning Paths", unit="req")
        threads = []
        for _ in range(self.thread_count):
            t = threading.Thread(target=self.scan_worker, args=(q, pbar))
            t.daemon = True
            t.start()
            threads.append(t)

        q.join()
        for _ in threads:
            q.put(None)
        for t in threads:
            t.join()
        pbar.close()

        self.log(f"路径扫描完成，发现 {len(self.results)} 个有效路径。")
        return self.results

    def _resolve_dict_path(self):
        """把字典路径统一解析为 Path 对象（已是 Path 直接返回，否则按 data/ 解析）。"""
        if hasattr(self.dict_path, "exists"):
            return self.dict_path
        return self.resolve_data_path(str(self.dict_path))

    @staticmethod
    def _load_paths(dict_path):
        """读取路径字典：去除空行/注释行、去掉前导斜杠并去重，返回路径列表。"""
        seen = set()
        paths = []
        with open(dict_path, 'r', encoding='utf-8') as f:
            for line in f:
                path = line.strip()
                if not path or path.startswith('#'):
                    continue
                normalized = path.lstrip('/')
                if normalized in seen:
                    continue
                seen.add(normalized)
                paths.append(normalized)
        return paths

    def _build_result_tag(self, status, res, waf):
        """为有效路径拼装展示标签：状态码 + WAF + Content-Type + 页面标题。"""
        labels = [str(status)]
        if waf:
            labels.append(f"WAF:{waf}")

        content_type = res.headers.get("Content-Type", "").split(";", 1)[0].strip()
        if content_type:
            labels.append(content_type)

        title = self._extract_title(self._decoded_text(res))
        if title:
            labels.append(title[:30])

        return " | ".join(labels)

    @staticmethod
    def _extract_title(text):
        """从 HTML 中正则提取 <title> 文本并压缩空白，无标题返回空串。"""
        match = re.search(r"<title[^>]*>(.*?)</title>", text or "", re.I | re.S)
        if not match:
            return ""
        return re.sub(r"\s+", " ", match.group(1)).strip()

    @staticmethod
    def _decoded_text(response):
        """智能解码响应正文，避免编码缺失/误判导致的中文乱码。"""
        encoding = (response.encoding or "").lower()
        if not encoding or encoding in {"iso-8859-1", "windows-1252"}:
            response.encoding = response.apparent_encoding or response.encoding
        return response.text
