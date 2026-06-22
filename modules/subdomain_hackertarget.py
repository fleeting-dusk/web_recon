"""
文件名: subdomain_hackertarget.py
功能:   被动子域名收集模块——调用 HackerTarget 的 hostsearch 接口，返回格式为
        「子域名,IP」的文本，从中提取子域名。该接口免费、无需密钥。
作者:   李豪
版本:   v1.0
创建时间: 2026-06
"""

from core.base_module import BaseModule
from core.domain_utils import belongs_to_domain, extract_hostname

class HackerTarget(BaseModule):
    """通过 HackerTarget 公共接口收集子域名。"""

    def run(self, target):
        """请求接口，逐行解析「子域名,IP」并过滤出归属目标的子域名。"""
        self.log(f"正在通过 HackerTarget 查询 {target}...")
        url = f"https://api.hackertarget.com/hostsearch/?q={target}"
        
        try:
            res = self.safe_request(url, timeout=15)
            if res.status_code == 200 and "error" not in res.text:
                # 返回格式是 subdomain,ip，我们需要提取 subdomain
                lines = res.text.split('\n')
                for line in lines:
                    if ',' in line:
                        subdomain = extract_hostname(line.split(',')[0])
                        if belongs_to_domain(subdomain, target):
                            self.results.append(subdomain)
                
                self.results = list(set(self.results))
                self.log(f"查询完成，发现 {len(self.results)} 个子域名")
        except Exception as e:
            self.log(f"查询出错: {e}")
            
        return self.results
