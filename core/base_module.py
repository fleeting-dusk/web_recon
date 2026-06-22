"""
文件名: base_module.py
功能:   定义所有扫描模块的抽象基类 BaseModule。统一约定模块的公共属性
        （模块名、类别、结果集、HTTP 客户端）与公共方法（请求、日志、路径解析），
        并强制子类实现 run()。这是项目「插件化」设计的基础。
作者:   李豪
版本:   v1.0
创建时间: 2026-06
"""

from abc import ABC, abstractmethod
import urllib3
from core.http_client import HttpClient
from core.paths import DATA_DIR

# 禁用 HTTPS 警告（扫描大量自签名/证书异常站点时避免刷屏）
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class BaseModule(ABC):
    """
    所有功能模块的抽象基类。

    子类通过 category 属性声明自己属于哪一类（passive/active/fingerprint/
    port_scan/path_scan/app_asset/js_discovery/js_verify），控制器据此调度。
    """

    def __init__(self):
        self.module_name = self.__class__.__name__  # 模块名默认取类名
        self.category = "passive"   # 模块类别，默认被动收集；子类按需覆盖
        self.results = []           # 模块运行结果集
        self.data_dir = DATA_DIR    # 数据目录路径，便于读取字典/指纹库
        self.http = HttpClient()    # 统一 HTTP 客户端
        self._timed_out = False     # 超时标志，被控制器置位后停止打印日志

    def get_headers(self):
        """生成随机请求头"""
        return self.http.get_headers()

    def safe_request(self, url, timeout=15, **kwargs):
        """封装的请求方法，供子类统一使用 UA、超时和 TLS 配置。"""
        return self.http.get(url, timeout=timeout, **kwargs)

    @abstractmethod
    def run(self, target):
        """模块主入口，必须由子类实现。target 含义随模块类别而不同。"""
        pass

    def log(self, message):
        """带模块名前缀的日志输出；模块已超时则静默，避免污染后续输出。"""
        if getattr(self, "_timed_out", False):
            return
        print(f"[*] [{self.module_name}] {message}")

    def resolve_data_path(self, filename):
        """把数据文件名拼接为 data/ 目录下的完整路径。"""
        return self.data_dir / filename
