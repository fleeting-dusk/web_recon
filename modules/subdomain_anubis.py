"""
文件名: subdomain_anubis.py
功能:   被动子域名收集模块——查询 Anubis（jldc.me）子域名数据库接口，直接返回
        一个子域名 JSON 数组，过滤后即为目标的子域名。
作者:   李豪
版本:   v1.0
创建时间: 2026-06
"""

from core.base_module import BaseModule
from core.domain_utils import belongs_to_domain, extract_hostname

class Anubis(BaseModule):
    """通过 Anubis 子域名数据库收集子域名。"""

    def run(self, target):
        """请求 Anubis 接口，解析 JSON 数组并过滤出归属目标的子域名。"""
        self.log(f"正在通过 Anubis 查询 {target}...")
        url = f"https://jldc.me/anubis/subdomains/{target}"
        
        try:
            res = self.safe_request(url, timeout=15)
            if res.status_code == 200:
                data = res.json()
                for sub in data:
                    host = extract_hostname(sub)
                    if belongs_to_domain(host, target):
                        self.results.append(host)
                
                self.results = list(set(self.results))
                self.log(f"查询完成，发现 {len(self.results)} 个子域名")
        except Exception as e:
            self.log(f"查询出错: {e}")
            
        return self.results
