import json
import re
from core.base_module import BaseModule

class FingerprintEngine(BaseModule):
    def __init__(self):
        super().__init__()
        self.category = "fingerprint"
        self.noise_keywords = ["mail", "system", "login", "admin", "portal"]
        self.rules = self._load_all_rules()

    def _load_all_rules(self):
        all_rules = []
        for path in self.data_dir.iterdir():
            if path.suffix == ".json" and ("finger" in path.name or "web" in path.name):
                try:
                    with open(path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        all_rules.extend(data if isinstance(data, list) else data.get('fingerprint', []))
                except (OSError, json.JSONDecodeError):
                    continue
        return all_rules

    def run(self, alive_results):
        self.log(f"开始加权指纹比对...")
        for item in alive_results:
            found_tags = []
            fp_score = 0
            body = item.content
            headers = str(item.headers).lower()
            title = item.title

            for rule in self.rules:
                app_name = rule.get('info', {}).get('name') or rule.get('name') or rule.get('id')
                matchers = rule.get('matchers') or []
                if 'http' in rule:
                    for h in rule['http']: matchers.extend(h.get('matchers', []))

                hit_count = 0
                for m in matchers:
                    m_type = m.get('type')
                    content = m.get('keyword') or m.get('content') or m.get('words', [""])[0]
                    if not content or content.lower() in self.noise_keywords: continue

                    part = m.get('part', 'body')
                    target = body
                    if part == 'header': target = headers
                    elif part == 'title': target = title

                    if m_type == 'word' and content.lower() in target.lower():
                        hit_count += 1
                    elif m_type == 'regex' and re.search(content, target, re.I):
                        hit_count += 1

                if hit_count > 0:
                    # 如果该组件有多个特征且命中了不止一个，说明可信度极高
                    if len(matchers) > 1 and hit_count < 2:
                        continue
                    found_tags.append(app_name)
                    fp_score += (hit_count * 20) # 每个特征命中加20分

            if len(found_tags) > 5:
                found_tags = [t for t in found_tags if t not in ["35mail", "jspxcms", "sdcms"]]
            
            item.fingerprint = list(set(found_tags))
            item.fp_score = fp_score # 存入指纹分
        return self.results
