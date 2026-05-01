from core.base_module import BaseModule


class WaybackSubdomain(BaseModule):
    def run(self, target):
        self.log("正在从 Wayback Machine 挖掘历史记录...")
        url = (
            f"http://web.archive.org/cdx/search/cdx"
            f"?url=*.{target}/*&output=json&collapse=urlkey"
        )

        try:
            # timeout 必须小于全局模块超时（25秒），留出余量设为15秒
            res = self.safe_request(url, timeout=15)
            if res.status_code == 200:
                data = res.json()
                for entry in data[1:]:
                    full_url = entry[2]
                    domain = full_url.split('/')[0].split(':')[0]
                    if domain.endswith(target):
                        self.results.append(domain.lower())

                self.results = list(set(self.results))
                self.log(f"Wayback 挖掘完成，发现 {len(self.results)} 个历史子域名")
        except Exception as e:
            self.log(f"Wayback 模块运行出错: {e}")

        return self.results