import requests
from core.base_module import BaseModule

class AlienVault(BaseModule):
    def run(self, target):
        self.log(f"正在通过 AlienVault OTX 查询 {target}...")
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{target}/passive_dns"
        
        try:
            # 直接调用父类的 safe_request，它会自动处理 UA 和 429 重试
            res = self.safe_request(url)
            
            if res.status_code == 200:
                data = res.json()
                for record in data.get('passive_dns', []):
                    hostname = record.get('hostname')
                    if hostname and hostname.endswith(target):
                        if hostname.lower() not in self.results:
                            self.results.append(hostname.lower())
                self.results = list(set(self.results))
            else:
                self.log(f"接口返回状态码: {res.status_code}")

        except Exception as e:
            # 如果 3 次重试都失败了，会走到这里
            self.log(f"查询失败（已尝试重试）: {e}")
            
        self.log(f"查询完成，共发现 {len(self.results)} 个子域名")
        return self.results