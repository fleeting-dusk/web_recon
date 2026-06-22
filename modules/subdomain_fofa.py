"""
文件名: subdomain_fofa.py
功能:   被动子域名收集模块——调用 FOFA 网络空间测绘引擎的 API，按 domain="目标"
        检索目标的关联资产。需要在 config.py 中配置有效的 FOFA Email 与 Key；
        未配置或配置无效时自动跳过，不影响其他模块。
作者:   李豪
版本:   v1.0
创建时间: 2026-06
"""

import base64
from core.base_module import BaseModule
from core.domain_utils import belongs_to_domain, extract_hostname

# 尝试导入密钥配置；若用户未创建 config.py 则置空，运行时优雅跳过本模块
try:
    import config
except ModuleNotFoundError:
    config = None

class FofaScanner(BaseModule):
    """通过 FOFA 测绘引擎 API 收集目标关联资产/子域名。"""

    def run(self, target):
        """校验密钥 -> 构造并 Base64 编码查询语句 -> 请求 API -> 清洗出归属子域名。"""
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
