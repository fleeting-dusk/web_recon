"""
文件名: subdomain_alienvault.py
功能:   被动子域名收集模块——查询 AlienVault OTX 威胁情报平台的被动 DNS 记录
        （passive_dns），从历史解析记录中提取目标的子域名。
作者:   李豪
版本:   v1.0
创建时间: 2026-06
"""

import requests
from core.base_module import BaseModule
from core.domain_utils import belongs_to_domain, extract_hostname

class AlienVault(BaseModule):
    """通过 AlienVault OTX 被动 DNS 数据收集子域名。"""

    def run(self, target):
        """请求 OTX passive_dns 接口，提取历史解析过的归属子域名。"""
        self.log(f"正在通过 AlienVault OTX 查询 {target}...")
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{target}/passive_dns"
        
        try:
            # 直接调用父类的 safe_request，统一 UA、超时和 TLS 处理。
            res = self.safe_request(url)
            
            if res.status_code == 200:
                data = res.json()
                for record in data.get('passive_dns', []):
                    hostname = record.get('hostname')
                    host = extract_hostname(hostname)
                    if belongs_to_domain(host, target):
                        self.results.append(host)
                self.results = sorted(set(self.results))
            else:
                self.log(f"接口返回状态码: {res.status_code}")

        except Exception as e:
            self.log(f"查询失败: {e}")
            
        self.log(f"查询完成，共发现 {len(self.results)} 个子域名")
        return self.results
