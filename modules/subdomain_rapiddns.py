"""
文件名: subdomain_rapiddns.py
功能:   被动子域名收集模块——抓取 RapidDNS 网站的子域名查询页面，由于该站点返回的是
        HTML 表格而非 JSON，这里用正则从 <td> 单元格中提取子域名。
作者:   李豪
版本:   v1.0
创建时间: 2026-06
"""

from core.base_module import BaseModule
from core.domain_utils import belongs_to_domain, extract_hostname
import re

class RapidDNS(BaseModule):
    """通过爬取 RapidDNS 页面并正则提取的方式收集子域名。"""

    def run(self, target):
        """请求 RapidDNS 页面，用正则抓取表格中归属目标的域名。"""
        self.log(f"正在通过 RapidDNS 爬取数据...")
        url = f"https://rapiddns.io/subdomain/{target}?full=1"

        try:
            res = self.safe_request(url, timeout=20)
            if res.status_code == 200:
                # 用正则匹配 <td>子域名.目标域名</td> 形式的单元格，re.escape 防止目标含正则特殊字符
                pattern = r'<td>([\w\.-]+\.' + re.escape(target) + r')</td>'
                found = re.findall(pattern, res.text)
                self.results = sorted({
                    extract_hostname(item)
                    for item in found
                    if belongs_to_domain(item, target)
                })
                self.log(f"RapidDNS 查询完成，发现 {len(self.results)} 个子域名")
        except Exception as e:
            self.log(f"RapidDNS 模块出错: {e}")
            
        return self.results
