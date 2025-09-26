# class Rule:
#     def __init__(self):
#         # Initialize any attributes here
#         self.subject = ''  # Example attribute
#         self.sender = ''  # Example attribute
#         self.body = ''    # Example attribute
#         # If you want any any other attributes, add them here

#     # Add methods for your rules here
#     def example_rule_1(self):
#         # Example rule logic
#         # return "phishing" in email_text.lower()
#         print('hello')
#         return

#     def example_rule_2(self, header, sender, body):
#         # Example rule logic
#         # return "phishing" in email_text.lower()
#         pass

#     def example_rule_3(self, header, sender, body):
#         # Example rule logic
#         # return "phishing" in email_text.lower()
#         pass

#     # Etc.

# # Allow this file to be imported without running any code

# __all__ = ['Rule']
# rules.py
# rules.py
from dataclasses import dataclass
import re
from urllib.parse import urlparse
from difflib import SequenceMatcher
import math

# --- Tunables (move to config.py later if you want) ---
SUSPICIOUS_KEYWORDS ={
    "urgent": 3, "verify": 3, "account": 2, "password": 3, "gift": 2,
    "login": 2, "security": 2, "click": 2, "update": 2, "invoice": 2
}

SAFE_WHITELIST = {
    "microsoft.com", "google.com", "sit.edu.sg", "apple.com", "paypal.com"
}

DEFAULT_WEIGHTS = {
    "whitelist_fail": 4,
    "keyword": 1,
    "keyword_subject_bonus": 2,
    "early_body_bonus": 2,
    "lookalike_domain": 4,
    "suspicious_url": 4,
}

# Approximate worst-case total (for 0–100 normalization UI)
MAX_POSSIBLE_SCORE = 30  # adjust as you refine the rules


@dataclass
class RuleResult:
    score: int
    reasons: list


class Rule:
    def __init__(self, weights=None, default_threshold_raw: int = 10):
        # default_threshold_raw = recommended starting cutoff in raw points
        self.weights = {**DEFAULT_WEIGHTS, **(weights or {})}
        self.default_threshold_raw = int(default_threshold_raw)

    # ---------- helpers ----------
    @staticmethod
    def domain_from_email(sender: str) -> str:
        # Accept “Name <email@domain.com>” or plain “email@domain.com”
        if not sender:
            return ""
        m = re.search(r'<([^>]+)>', sender)
        email = m.group(1) if m else sender
        m2 = re.search(r'@([\w\.-]+)$', email.strip(), re.I)
        return (m2.group(1) if m2 else "").lower()

    @staticmethod
    def extract_urls(text: str):
        return re.findall(r'(https?://[^\s)>\]]+)', text or "", flags=re.I)

    @staticmethod
    def looks_like_ip(host: str) -> bool:
        return bool(re.fullmatch(r'(?:\d{1,3}\.){3}\d{1,3}', host))

    @staticmethod
    def similar(a: str, b: str) -> float:
        return SequenceMatcher(None, a, b).ratio()

    # ---------- individual rule checks ----------
    def whitelist_check(self, sender: str) -> RuleResult:
        dom = self.domain_from_email(sender)
        if not dom:
            return RuleResult(0, ["No sender domain"])
        if dom in SAFE_WHITELIST:
            return RuleResult(0, [f"Whitelisted: {dom}"])
        return RuleResult(self.weights["whitelist_fail"], [f"Not whitelisted: {dom}"])

    def keyword_scoring(self, subject: str, body: str) -> RuleResult:
        score, reasons = 0, []
        subject_l = (subject or "").lower()
        body_l = (body or "").lower()
        text = f"{subject_l}\n{body_l}"
        slen = len(subject_l)
        for kw, base in SUSPICIOUS_KEYWORDS.items():
            for m in re.finditer(rf'\b{re.escape(kw)}\b', text):
                s = base * self.weights["keyword"]
                if m.start() < slen:  # subject
                    s += self.weights["keyword_subject_bonus"]
                    where = "subject"
                else:
                    pos = m.start() - slen
                    where = "early-body" if pos < 200 else "body"
                    if where == "early-body":
                        s += self.weights["early_body_bonus"]
                score += s
                reasons.append(f'Keyword "{kw}" in {where} (+{s})')
        return RuleResult(score, reasons)

    def lookalike_domain_check(self, sender: str) -> RuleResult:
        dom = self.domain_from_email(sender)
        if not dom:
            return RuleResult(0, [])
        best = max((self.similar(dom, good) for good in SAFE_WHITELIST), default=0.0)
        if best > 0.7 and dom not in SAFE_WHITELIST:
            return RuleResult(self.weights["lookalike_domain"], [f"Lookalike domain: {dom}"])
        return RuleResult(0, [])

    def suspicious_url_check(self, subject: str, body: str) -> RuleResult:
        score, reasons = 0, []
        urls = self.extract_urls(subject) + self.extract_urls(body)
        for u in urls:
            host = urlparse(u).netloc.lower()
            if self.looks_like_ip(host):
                score += self.weights["suspicious_url"]
                reasons.append(f"URL uses IP address: {u}")
            brand_hit = [b for b in SAFE_WHITELIST if b.split('.')[0] in u.lower()]
            if brand_hit and host not in SAFE_WHITELIST:
                score += self.weights["suspicious_url"]
                reasons.append(f"Brand mismatch in URL: {u} host={host}")
        return RuleResult(score, reasons)

    # ---------- final API ----------
    def evaluate(self, sender: str, subject: str, body: str, threshold=None) -> dict:
        contrib = {"whitelist": 0, "keywords": 0, "lookalike_domain": 0, "urls": 0}
        reasons_all = []
        total = 0

        r = self.whitelist_check(sender);            contrib["whitelist"] += r.score; total += r.score; reasons_all += r.reasons
        r = self.keyword_scoring(subject, body);     contrib["keywords"] += r.score; total += r.score; reasons_all += r.reasons
        r = self.lookalike_domain_check(sender);     contrib["lookalike_domain"] += r.score; total += r.score; reasons_all += r.reasons
        r = self.suspicious_url_check(subject, body);contrib["urls"] += r.score; total += r.score; reasons_all += r.reasons

        # Normalize to 0–100 for UI
        normalized_score = min(100, int((total / MAX_POSSIBLE_SCORE) * 100))

        # Interpret threshold (slider 0–100 vs raw points)
        if threshold is None:
            threshold_raw = self.default_threshold_raw
            threshold_ui = int((threshold_raw / MAX_POSSIBLE_SCORE) * 100)
        else:
            t = int(threshold)
            if t > MAX_POSSIBLE_SCORE:  # assume UI %
                threshold_ui = max(0, min(100, t))
                threshold_raw = max(0, math.ceil((threshold_ui / 100) * MAX_POSSIBLE_SCORE))
            else:                        # assume raw points
                threshold_raw = max(0, min(MAX_POSSIBLE_SCORE, t))
                threshold_ui = int((threshold_raw / MAX_POSSIBLE_SCORE) * 100)

        label = "Phishing" if total >= threshold_raw else "Safe"

        return {
                "raw_score": total,
                "normalized_score": normalized_score,
                "label": label,
                "threshold_raw": threshold_raw,
                "threshold_ui": threshold_ui,
                "reasons": reasons_all,
                "contrib": contrib
   }



