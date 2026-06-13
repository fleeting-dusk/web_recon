from core.base_module import BaseModule
from core.domain_utils import belongs_to_domain, extract_hostname

class HackerTarget(BaseModule):
    def run(self, target):
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
