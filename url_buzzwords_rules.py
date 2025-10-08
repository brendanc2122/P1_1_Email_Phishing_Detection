import re
import hashlib
from typing import Dict, List, Tuple
from urllib.parse import urlparse

# -----------------------------
# GLOBAL INITIALIZATION
# -----------------------------

ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
url_pattern = re.compile(r'https?://[^\s<>"]+', re.IGNORECASE)

suspicious_patterns = [
    (re.compile(r'secure.*update', re.IGNORECASE), "Contains 'secure update' pattern"),
    (re.compile(r'verify.*account', re.IGNORECASE), "Contains 'verify account' pattern"),
    (re.compile(r'login.*now', re.IGNORECASE), "Contains 'login now' pattern"),
    (re.compile(r'suspended.*account', re.IGNORECASE), "Contains 'suspended account' pattern"),
    (re.compile(r'urgent.*action', re.IGNORECASE), "Contains 'urgent action' pattern"),
]

safe_domains = set()
suspicious_domains = set()
domain_cache: Dict[str, Tuple[float, List[str]]] = {}

trusted_domains = {
    'google.com','microsoft.com','apple.com','amazon.com','paypal.com','ebay.com',
    'facebook.com','twitter.com','linkedin.com','github.com','stackoverflow.com'
}

# -----------------------------
# BUZZWORD DETECTION SETUP
# -----------------------------

def compile_buzzword_patterns() -> Dict:
    categories = {
        'urgency': {
            'weight': 3,
            'words': [
                'urgent','immediate','asap','emergency','critical','deadline',
                'expires','expiring','time sensitive','act now','limited time',
                'hurry','rush','quickly','fast','instant','today only','last chance',
                'final notice',"don't wait",'time is running out'
            ]
        },
        'financial_threats': {
            'weight': 4,
            'words': [
                'suspended','blocked','frozen','locked','compromised','breach',
                'unauthorized','fraudulent','illegal','violation','penalty','fine',
                'fee','charge','payment failed','declined','overdue','debt','owe',
                'collection','lawsuit','legal action','court','seizure','garnishment',
                'bankruptcy'
            ]
        },
        'manipulation_prompts': {
            'weight': 3.5,
            'words': [
                'verify','confirm','update','validate','authenticate','click here',
                'download now','open attachment','free gift','congratulations','winner',
                'selected','exclusive offer','limited offer','act fast',"don't miss out"
            ]
        },
        'impersonation': {
            'weight': 4.5,
            'words': [
                'security team','support team','account team','fraud department',
                'billing department','customer service','technical support',
                'system administrator','it department','security alert'
            ]
        }
    }
    # Build ONE regex per category (faster than many)
    for data in categories.values():
        escaped = [re.sub(r"\s+", r"\\s+", re.escape(w)) for w in data['words']]
        data['pattern'] = re.compile(r"\b(?:%s)\b" % "|".join(escaped), re.IGNORECASE)
    return categories

buzzword_categories = compile_buzzword_patterns()

# -----------------------------
# DOMAIN AND URL UTILITIES
# -----------------------------

def load_domain_lists(suspicious: List[str], safe: List[str]):
    global suspicious_domains, safe_domains
    suspicious_domains = set(d.lower().rstrip('.') for d in suspicious)
    safe_domains = set(d.lower().rstrip('.') for d in safe)

def extract_domain(url: str) -> str:
    try:
        parsed = urlparse(url if url.startswith(('http://','https://')) else f'http://{url}')
        return parsed.netloc.rstrip('.').lower()
    except Exception:
        return url.rstrip('.').lower()

def check_homograph_attack(domain: str) -> bool:
    # Common Cyrillic lookalikes, etc.
    suspicious_chars = ['а','о','р','е','х','у','с','н','к','і']
    return any(ch in domain for ch in suspicious_chars)

def is_url_shortener(domain: str) -> bool:
    shorteners = {'bit.ly','tinyurl.com','t.co','goo.gl','ow.ly','is.gd','buff.ly'}
    return domain in shorteners

def domain_matches(base: str, host: str) -> bool:
    base = base.lower().rstrip('.')
    host = host.lower().rstrip('.')
    return host == base or host.endswith('.' + base)

# -----------------------------
# URL RISK ANALYSIS
# -----------------------------

def analyze_url_risk(url: str, is_subject: bool=False) -> Tuple[float, List[str]]:
    key = hashlib.md5(f"{url}_{is_subject}".encode()).hexdigest()
    if key in domain_cache:
        return domain_cache[key]

    m = 1.1 if is_subject else 1.0
    score = 0.0
    reasons: List[str] = []

    domain = extract_domain(url)

    # Exact/subdomain checks for trust/safe/suspicious
    if any(domain_matches(t, domain) for t in trusted_domains):
        r = (0.0, ["Trusted domain - no risk"])
        domain_cache[key] = r
        return r

    if any(domain_matches(s, domain) for s in safe_domains):
        r = (0.0, ["Safe domain - no risk"])
        domain_cache[key] = r
        return r

    if any(domain_matches(s, domain) for s in suspicious_domains):
        score += 3 * m
        reasons.append("Known suspicious domain")

    # IP-in-URL
    if ip_pattern.search(url):
        score += 4 * m
        reasons.append("Uses IP address instead of domain name")

    # Too many subdomains
    sub_count = domain.count('.')
    if sub_count > 3:
        score += 2 * m
        reasons.append(f"Too many subdomains ({sub_count})")

    # Suspicious URL phrase patterns
    for pat, desc in suspicious_patterns:
        if pat.search(url):
            score += 2 * m
            reasons.append(desc)

    # Length checks
    L = len(url)
    if L > 150:
        score += 2 * m
        reasons.append("Extremely long URL")
    elif L > 75:
        score += 1 * m
        reasons.append("Unusually long URL")

    # Hyphen count
    hy = domain.count('-')
    if hy > 3:
        score += 1.5 * m
        reasons.append(f"Too many hyphens in domain ({hy})")

    # Homograph lookalikes
    if check_homograph_attack(domain):
        score += 3 * m
        reasons.append("Potential homograph attack")

    # Shortener
    if is_url_shortener(domain):
        score += 1.5 * m
        reasons.append("Uses URL shortener")

    r = (round(score, 2), reasons)
    domain_cache[key] = r
    return r

# -----------------------------
# BUZZWORD DETECTION LOGIC
# -----------------------------

def analyze_text_patterns(text: str, weight_multiplier: float=1.0) -> Tuple[float, List[str]]:
    total = 0.0
    notes: List[str] = []
    for name, data in buzzword_categories.items():
        matches = data['pattern'].findall(text)
        if matches:
            add = len(matches) * data['weight'] * weight_multiplier
            total += add
            notes.append(f"{len(matches)} {name} hit(s), +{add:g}")
    return total, notes

# -----------------------------
# COMPREHENSIVE PHISHING DETECTION
# -----------------------------

def risk_bucket(score: float) -> str:
    # Tweak thresholds as you like
    if score >= 6.0:
        return "high"
    if score >= 2.5:
        return "medium"
    return "low"

def detect_phishing_comprehensive(subject: str, body: str, urls: List[str] = None) -> Dict:
    if urls is None:
        urls = url_pattern.findall(subject + " " + body)

    s_score, s_patterns = analyze_text_patterns(subject, 1.2)
    b_score, b_patterns = analyze_text_patterns(body, 1.0)

    total_url = 0.0
    url_reasons: List[str] = []
    for u in urls:
        url_score, reasons = analyze_url_risk(u, is_subject=(u in subject))
        total_url += url_score
        url_reasons.extend(reasons)

    total = round(s_score + b_score + total_url, 2)
    reasons = [s_patterns, b_patterns, url_reasons]
    return total, reasons
# -----------------------------
# BATCH AND CACHE UTILITIES
# -----------------------------

def batch_analyze(emails: List[Dict]) -> List[Dict]:
    results = []
    for i, e in enumerate(emails):
        r = detect_phishing_comprehensive(
            e.get('subject', ''),
            e.get('body', ''),
            e.get('urls', [])
        )
        r['email_id'] = e.get('id', i)
        results.append(r)
    return results

def clear_cache():
    domain_cache.clear()

# -----------------------------
# MAIN EXECUTION FOR TESTING
# -----------------------------

if __name__ == "__main__":
    load_domain_lists(
        ["phishing-site.com","fake-bank.net","suspicious.org"],
        ["legitimate-bank.com","trusted-site.org"]
    )
    subj = "URGENT: Your account will be suspended - Act now!"
    body = "Verify immediately at http://fake-bank.net/login-verify-urgent"
    res = detect_phishing_comprehensive(subj, body)  # no sender passed
    print(res["risk_level"], res["total_risk_score"], res["body_analysis"])
