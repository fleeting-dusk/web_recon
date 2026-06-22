"""
文件名: fingerprint_v4.py
功能:   Web 指纹识别引擎。加载 data/ 下的指纹库（兼容多种 JSON 格式），把每条规则
        规整为统一的匹配器结构，再对每个存活站点的 body/header/title 做「加权打分」式
        匹配：命中即累加分数，超过阈值才认定命中该指纹，并对结果去重、限量输出。
        采用加权评分而非简单关键字匹配，可有效降低误报。
作者:   李豪
版本:   v4.0
创建时间: 2026-06
"""

import json
import re

from core.base_module import BaseModule


# 过于通用的词：单独出现时不足以作为指纹依据，需排除以减少误报
GENERIC_WORDS = {
    "admin", "api", "app", "index", "login", "mail", "portal", "system", "web",
    "加载中", "扫码登录", "首页", "登录",
}


class FingerprintEngine(BaseModule):
    """加权评分式 Web 指纹识别引擎。"""

    def __init__(self):
        super().__init__()
        self.category = "fingerprint"
        self.min_score = 45          # 认定命中所需的最低分数阈值
        self.max_tags_per_site = 5   # 每个站点最多保留的指纹标签数
        self.rules = self._load_all_rules()  # 启动即加载并规整全部指纹规则

    def _load_all_rules(self):
        """扫描 data/ 下含 finger/web 字样的 JSON 指纹库，逐条规整为统一结构后汇总。"""
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
        """
        把来源格式各异的单条指纹规则规整为统一结构：
        {name, verified, condition, matchers[...]}。兼容 keyword/matchers/http 等多种写法。
        """
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
        """把单个匹配器规整为统一结构（仅保留 word/regex 两类），无有效值则返回 None。"""
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
        """
        对每个存活站点逐规则打分：累计命中分数超过阈值的规则即为命中指纹。
        命中结果去重、按分数排序后写回站点记录的 fingerprint / fp_score 字段。
        """
        self.log("开始加权指纹比对...")
        for item in alive_results:
            # 把响应头拼成文本，连同正文、标题组成可供匹配的上下文
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
        """
        计算单条规则的总得分。
        condition=and 要求所有匹配器都命中，任一不中则整条规则得 0；
        condition=or 取命中项分数之和。规则标记 verified 时额外加分。
        """
        matcher_scores = []
        for matcher in rule["matchers"]:
            score = self._match_matcher(matcher, context)
            if score > 0:
                matcher_scores.append(score)
            elif rule["condition"] == "and":  # and 模式下只要有一个不中即判 0
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
        """对单个匹配器在指定部位（body/header/title）求分；and 取和、or 取最大值。"""
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
        """
        关键字匹配并加权打分。基础分 35，命中部位越关键（title>header>body）加分越多；
        词越长、含特殊符号、含中文，越具区分度，额外加分。通用词直接判 0。
        """
        token = word.strip()
        if self._is_generic_token(token):  # 通用词不计分
            return 0
        if token.lower() not in text.lower():
            return 0

        score = 35
        if part == "title":
            score += 25            # 出现在标题中可信度最高
        elif part in {"header", "headers"}:
            score += 15            # 出现在响应头中次之
        if len(token) >= 12:
            score += 10            # 长词更具特征性
        if any(ch in token for ch in "/<>=:_-."):
            score += 10            # 含特殊符号（路径、版本号等）更可信
        if self._contains_cjk(token):
            score += 8             # 含中文一般为业务特征词
        return score

    def _match_regex(self, pattern, text, part):
        """正则匹配打分：命中标题给 70 分，命中其他部位给 55 分；正则非法则判 0。"""
        try:
            matched = re.search(pattern, text, re.I | re.M)
        except re.error:
            return 0
        if not matched:
            return 0
        return 70 if part == "title" else 55

    def _dedupe_tags(self, scored):
        """对命中标签按名称（忽略大小写）去重保留最高分，再按分数降序取前 N 个。"""
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
        """\u628a\u89c4\u5219\u91cc\u4e94\u82b1\u516b\u95e8\u7684\u5339\u914d\u90e8\u4f4d\u540d\u79f0\u5f52\u4e00\u5316\u4e3a body/header/title \u4e09\u79cd\u3002"""
        part = str(part or "body").lower()
        if part in {"headers", "header"}:
            return "header"
        if part == "title":
            return "title"
        return "body"

    @staticmethod
    def _as_list(value):
        """\u628a\u5355\u503c\u6216 None \u7edf\u4e00\u5305\u88c5\u6210\u5217\u8868\uff0c\u4fbf\u4e8e\u540e\u7eed\u904d\u5386\u3002"""
        if value is None:
            return []
        if isinstance(value, list):
            return value
        return [value]

    @staticmethod
    def _contains_cjk(value):
        """\u5224\u65ad\u5b57\u7b26\u4e32\u662f\u5426\u5305\u542b\u4e2d\u65e5\u97e9\u7edf\u4e00\u8868\u610f\u6587\u5b57\uff08\u5373\u4e2d\u6587\u5b57\u7b26\uff09\u3002"""
        return any("\u4e00" <= char <= "\u9fff" for char in value)

    def _is_generic_token(self, value):
        """判断是否为「无区分度」的通用词：空串、命中通用词表、或过短的纯英数字短词。"""
        token = value.strip().lower()
        if not token:
            return True
        if token in GENERIC_WORDS:
            return True
        if len(token) < 5 and token.isascii() and token.isalnum():  # 过短英文/数字短词
            return True
        return False
