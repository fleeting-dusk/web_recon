import base64
from core.base_module import BaseModule
from core.domain_utils import belongs_to_domain, extract_hostname

try:
    import config
except ModuleNotFoundError:
    config = None

class FofaScanner(BaseModule):
    def run(self, target):
        # 1. 检查配置是否填写
        if config is None:
            self.log("跳过 FOFA 模块：未找到 config.py")
            return []

        invalid_markers = {
            "",
            "你的FOFA邮箱",
            "你的FOFA_API_KEY",
            "your-email@example.com",
            "your-fofa-key",
        }
        email = getattr(config, "FOFA_EMAIL", "").strip()
        key = getattr(config, "FOFA_KEY", "").strip()
        if email in invalid_markers or key in invalid_markers:
            self.log("跳过 FOFA 模块：未配置有效的 Email 或 Key")
            return []

        self.log(f"正在通过 FOFA 引擎检索 {target} 的资产...")

        # 2. 构造 FOFA 查询语句并进行 Base64 编码
        # domain="example.com" 会搜索该域名的所有子域名和相关资产
        query = f'domain="{target}"'
        query_b64 = base64.b64encode(query.encode()).decode()

        # 3. 构造请求 URL (获取 1000 条结果，字段包含 host)
        url = f"https://fofa.info/api/v1/search/all?email={email}&key={key}&qbase64={query_b64}&size=1000&fields=host"

        try:
            res = self.safe_request(url, timeout=20)
            if res.status_code == 200:
                data = res.json()
                if data.get("error"):
                    self.log(f"FOFA 报错: {data.get('errmsg')}")
                    return []

                # 4. 提取并清洗结果
                hosts = data.get("results", [])
                for host in hosts:
                    # FOFA 返回的 host 可能是 https://sub.domain.com 或 sub.domain.com:8080
                    # 我们需要提取出纯域名
                    clean_host = extract_hostname(host)
                    if belongs_to_domain(clean_host, target):
                        self.results.append(clean_host)

                self.results = sorted(set(self.results))
                self.log(f"FOFA 查询完成，发现 {len(self.results)} 个资产")
            else:
                self.log(f"FOFA 请求失败，状态码: {res.status_code}")
        except Exception as e:
            self.log(f"FOFA 模块运行出错: {e}")

        return self.results
