from core.base_module import BaseModule
from core.domain_utils import belongs_to_domain, extract_hostname

class Anubis(BaseModule):
    def run(self, target):
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
