import json
import re

from core.base_module import BaseModule


GENERIC_WORDS = {
    "admin", "api", "app", "index", "login", "mail", "portal", "system", "web",
    "加载中", "扫码登录", "首页", "登录",
}


class FingerprintEngine(BaseModule):
    def __init__(self):
        super().__init__()
        self.category = "fingerprint"
        self.min_score = 45
        self.max_tags_per_site = 5
        self.rules = self._load_all_rules()

    def _load_all_rules(self):
        normalized = []
        for path in sorted(self.data_dir.iterdir()):
            if path.suffix != ".json" or ("finger" not in path.name and "web" not in path.name):
                continue
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except (OSError, json.JSONDecodeError):
                continue

            raw_rules = data if isinstance(data, list) else data.get("fingerprint", [])
            for rule in raw_rules:
                parsed = self._normalize_rule(rule)
                if parsed and parsed["matchers"]:
                    normalized.append(parsed)

        self.log(f"已加载 {len(normalized)} 条可用指纹规则。")
        return normalized

    def _normalize_rule(self, rule):
        name = (
            rule.get("cms")
            or rule.get("info", {}).get("name")
            or rule.get("name")
            or rule.get("id")
        )
        if not name:
            return None

        metadata = rule.get("info", {}).get("metadata", {})
        verified = bool(metadata.get("verified"))
        matchers = []

        if "keyword" in rule:
            keywords = self._as_list(rule.get("keyword"))
            matchers.append({
                "type": "word",
                "part": rule.get("location", "body"),
                "condition": "and" if len(keywords) > 1 else "or",
                "values": keywords,
            })

        for matcher in rule.get("matchers") or []:
            parsed = self._normalize_matcher(matcher)
            if parsed:
                matchers.append(parsed)

        for http_rule in rule.get("http") or []:
            for matcher in http_rule.get("matchers") or []:
                parsed = self._normalize_matcher(matcher)
                if parsed:
                    matchers.append(parsed)

        return {
            "name": str(name).strip(),
            "verified": verified,
            "condition": str(rule.get("matchers-condition", "or")).lower(),
            "matchers": matchers,
        }

    def _normalize_matcher(self, matcher):
        m_type = str(matcher.get("type", "")).lower()
        if m_type not in {"word", "regex"}:
            return None

        values = []
        if m_type == "word":
            values = self._as_list(
                matcher.get("words")
                or matcher.get("word")
                or matcher.get("keyword")
                or matcher.get("content")
            )
        elif m_type == "regex":
            values = self._as_list(matcher.get("regex") or matcher.get("content"))

        values = [str(item) for item in values if str(item).strip()]
        if not values:
            return None

        return {
            "type": m_type,
            "part": matcher.get("part") or matcher.get("location") or "body",
            "condition": str(matcher.get("condition", "or")).lower(),
            "values": values,
        }

    def run(self, alive_results):
        self.log("开始加权指纹比对...")
        for item in alive_results:
            header_text = "\n".join(f"{k}: {v}" for k, v in item.headers.items())
            context = {
                "body": item.content or "",
                "header": header_text,
                "headers": header_text,
                "title": item.title or "",
            }

            scored = []
            for rule in self.rules:
                score = self._match_rule(rule, context)
                if score >= self.min_score:
                    scored.append((rule["name"], score))

            item.fingerprint = self._dedupe_tags(scored)
            item.fp_score = sum(score for _, score in scored)
        return self.results

    def _match_rule(self, rule, context):
        matcher_scores = []
        for matcher in rule["matchers"]:
            score = self._match_matcher(matcher, context)
            if score > 0:
                matcher_scores.append(score)
            elif rule["condition"] == "and":
                return 0

        if rule["condition"] == "and" and len(matcher_scores) < len(rule["matchers"]):
            return 0
        if not matcher_scores:
            return 0

        score = sum(matcher_scores)
        if rule["verified"]:
            score += 8
        return score

    def _match_matcher(self, matcher, context):
        part = self._normalize_part(matcher["part"])
        text = context.get(part, context["body"])
        values = matcher["values"]
        scores = []

        for value in values:
            if matcher["type"] == "word":
                score = self._match_word(value, text, part)
            else:
                score = self._match_regex(value, text, part)
            scores.append(score)

        if matcher["condition"] == "and":
            return sum(scores) if scores and all(score > 0 for score in scores) else 0
        return max(scores) if scores else 0

    def _match_word(self, word, text, part):
        token = word.strip()
        if self._is_generic_token(token):
            return 0
        if token.lower() not in text.lower():
            return 0

        score = 35
        if part == "title":
            score += 25
        elif part in {"header", "headers"}:
            score += 15
        if len(token) >= 12:
            score += 10
        if any(ch in token for ch in "/<>=:_-."):
            score += 10
        if self._contains_cjk(token):
            score += 8
        return score

    def _match_regex(self, pattern, text, part):
        try:
            matched = re.search(pattern, text, re.I | re.M)
        except re.error:
            return 0
        if not matched:
            return 0
        return 70 if part == "title" else 55

    def _dedupe_tags(self, scored):
        best = {}
        for name, score in scored:
            clean_name = str(name).strip()
            if not clean_name:
                continue
            key = clean_name.lower()
            if key not in best or score > best[key][1]:
                best[key] = (clean_name, score)

        return [
            name
            for name, _ in sorted(best.values(), key=lambda item: (-item[1], item[0]))
        ][: self.max_tags_per_site]

    @staticmethod
    def _normalize_part(part):
        part = str(part or "body").lower()
        if part in {"headers", "header"}:
            return "header"
        if part == "title":
            return "title"
        return "body"

    @staticmethod
    def _as_list(value):
        if value is None:
            return []
        if isinstance(value, list):
            return value
        return [value]

    @staticmethod
    def _contains_cjk(value):
        return any("\u4e00" <= char <= "\u9fff" for char in value)

    def _is_generic_token(self, value):
        token = value.strip().lower()
        if not token:
            return True
        if token in GENERIC_WORDS:
            return True
        if len(token) < 5 and token.isascii() and token.isalnum():
            return True
        return False
