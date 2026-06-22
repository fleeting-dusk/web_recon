"""
文件名: subdomain_collector.py
功能:   被动子域名收集模块——通过 crt.sh 证书透明度日志（CT Log）查询目标域名
        申请过的 SSL 证书，从证书的 name_value 字段中提取子域名。属于无侵入的
        被动信息收集，不直接接触目标服务器。
作者:   李豪
版本:   v1.0
创建时间: 2026-06
"""

from core.base_module import BaseModule
from core.domain_utils import belongs_to_domain, extract_hostname

class SubdomainCollector(BaseModule):
    """通过 crt.sh 证书透明度日志收集子域名。"""

    def run(self, target):
        """查询 crt.sh 的 JSON 接口，解析并过滤出归属目标的子域名列表。"""
        self.log(f"正在通过 crt.sh 查询 {target} 的子域名...")
        
        # 1. 构造查询 URL (输出格式为 JSON)
        url = f"https://crt.sh/?q=%.{target}&output=json"
        
        subdomains = set() # 使用集合去重
        
        try:
            # 2. 发送请求
            response = self.safe_request(url, timeout=20)
            
            if response.status_code == 200:
                data = response.json()
                
                # 3. 解析 JSON 数据
                for entry in data:
                    # name_value 可能包含多个域名（换行符分隔）或通配符 (*)
                    name_value = entry['name_value']
                    names = name_value.split('\n')
                    
                    for name in names:
                        name = name.strip().lower()
                        # 过滤掉通配符和非目标域名的干扰项
                        host = extract_hostname(name)
                        if "*" not in name and belongs_to_domain(host, target):
                            subdomains.add(host)
                
                self.results = sorted(list(subdomains))
                self.log(f"查询完成，共发现 {len(self.results)} 个唯一子域名。")
            else:
                self.log(f"查询失败，crt.sh 返回状态码: {response.status_code}")

        except Exception as e:
            self.log(f"模块运行出错: {e}")

        return self.results
