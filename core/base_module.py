from abc import ABC, abstractmethod
import urllib3
from core.http_client import HttpClient
from core.paths import DATA_DIR

# 禁用 HTTPS 警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class BaseModule(ABC):
    def __init__(self):
        self.module_name = self.__class__.__name__
        self.category = "passive" 
        self.results = []
        self.data_dir = DATA_DIR
        self.http = HttpClient()
        self._timed_out = False

    def get_headers(self):
        """生成随机请求头"""
        return self.http.get_headers()

    def safe_request(self, url, timeout=15, **kwargs):
        """封装的请求方法，供子类统一使用 UA、超时和 TLS 配置。"""
        return self.http.get(url, timeout=timeout, **kwargs)

    @abstractmethod
    def run(self, target):
        pass

    def log(self, message):
        if getattr(self, "_timed_out", False):
            return
        print(f"[*] [{self.module_name}] {message}")

    def resolve_data_path(self, filename):
        return self.data_dir / filename
