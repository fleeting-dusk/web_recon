from core.base_module import BaseModule
import re

class RapidDNS(BaseModule):
    def run(self, target):
        self.log(f"正在通过 RapidDNS 爬取数据...")
        url = f"https://rapiddns.io/subdomain/{target}?full=1"
        
        try:
            res = self.safe_request(url, timeout=20)
            if res.status_code == 200:
                # 使用正则简单快速地抓取表格中的域名
                pattern = r'<td>([\w\.-]+\.' + re.escape(target) + r')</td>'
                found = re.findall(pattern, res.text)
                self.results = list(set([item.lower() for item in found]))
                self.log(f"RapidDNS 查询完成，发现 {len(self.results)} 个子域名")
        except Exception as e:
            self.log(f"RapidDNS 模块出错: {e}")
            
        return self.results
