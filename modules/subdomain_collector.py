from core.base_module import BaseModule
from core.domain_utils import belongs_to_domain, extract_hostname

class SubdomainCollector(BaseModule):
    def run(self, target):
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
