"""
文件名: subdomain_wayback.py
功能:   被动子域名收集模块——查询 Wayback Machine（互联网档案馆）的 CDX 接口，
        从历史快照 URL 中挖掘曾经出现过的子域名，可发现一些已下线但有价值的资产。
作者:   李豪
版本:   v1.0
创建时间: 2026-06
"""

from core.base_module import BaseModule
from core.domain_utils import belongs_to_domain, extract_hostname


class WaybackSubdomain(BaseModule):
    """通过 Wayback Machine 历史归档挖掘子域名。"""

    def run(self, target):
        """请求 CDX 接口，从历史 URL 中提取归属目标的子域名。"""
        self.log("正在从 Wayback Machine 挖掘历史记录...")
        url = (
            f"http://web.archive.org/cdx/search/cdx"
            f"?url=*.{target}/*&output=json&fl=original&collapse=urlkey&limit=5000"
        )

        try:
            # timeout 必须小于全局模块超时（25秒），留出余量设为15秒
            res = self.safe_request(url, timeout=15)
            if res.status_code == 200:
                data = res.json()
                for entry in data[1:]:
                    full_url = entry[0] if isinstance(entry, list) else entry
                    domain = extract_hostname(full_url)
                    if belongs_to_domain(domain, target):
                        self.results.append(domain)

                self.results = sorted(set(self.results))
                self.log(f"Wayback 挖掘完成，发现 {len(self.results)} 个历史子域名")
        except Exception as e:
            self.log(f"Wayback 模块运行出错: {e}")

        return self.results
