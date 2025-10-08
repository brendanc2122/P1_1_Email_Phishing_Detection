import re
import hashlib
from typing import Dict, List, Tuple
from datetime import datetime
from urllib.parse import urlparse

### ------------------------------------------------------
### GLOBAL INITIALIZATION
### ------------------------------------------------------

ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
url_pattern = re.compile(r'https?://[^\s<>"]+', re.IGNORECASE)
suspicious_patterns = [
    (re.compile(r'secure.*update', re.IGNORECASE), "Contains 'secure update' pattern"),
    (re.compile(r'verify.*account', re.IGNORECASE), "Contains 'verify account' pattern"),
    (re.compile(r'login.*now', re.IGNORECASE), "Contains 'login now' pattern"),
    (re.compile(r'suspended.*account', re.IGNORECASE), "Contains 'suspended account' pattern"),
    (re.compile(r'urgent.*action', re.IGNORECASE), "Contains 'urgent action' pattern")
]
safe_domains = set()
suspicious_domains = set()
domain_cache: Dict[str, Tuple[float, List[str]]] = {}
trusted_domains = {
    'google.com','microsoft.com','apple.com','amazon.com','paypal.com','ebay.com',
    'facebook.com','twitter.com','linkedin.com','github.com','stackoverflow.com'
}

### ------------------------------------------------------
### BUZZWORD DETECTION SETUP
### ------------------------------------------------------

def compile_buzzword_patterns() -> Dict:
    categories = {
        'urgency': {'weight': 3, 'words': ['urgent','immediate','asap','emergency','critical','deadline','expires','expiring','time sensitive','act now','limited time','hurry','rush','quickly','fast','instant','today only','last chance','final notice',"don't wait",'time is running out']},
        'financial_threats': {'weight': 4, 'words': ['suspended','blocked','frozen','locked','compromised','breach','unauthorized','fraudulent','illegal','violation','penalty','fine','fee','charge','payment failed','declined','overdue','debt','owe','collection','lawsuit','legal action','court','seizure','garnishment','bankruptcy']},
        'social_engineering': {'weight': 3.5, 'words': ['verify','confirm','update','validate','authenticate','click here','download now','open attachment','free gift','congratulations','winner','selected','exclusive offer','limited offer','act fast',"don't miss out"]},
        'impersonation': {'weight': 4.5, 'words': ['security team','support team','account team','fraud department','billing department','customer service','technical support','system administrator','it department','security alert']}
    }
    for category, data in categories.items():
        data['patterns'] = [re.compile(r'\b' + re.escape(w) + r'\b', re.IGNORECASE) for w in data['words']]
    return categories

buzzword_categories = compile_buzzword_patterns()

### ------------------------------------------------------
### DOMAIN AND URL UTILITIES
### ------------------------------------------------------

def load_domain_lists(suspicious: List[str], safe: List[str]):
    global suspicious_domains, safe_domains
    suspicious_domains = set(d.lower() for d in suspicious)
    safe_domains = set(d.lower() for d in safe)

def extract_domain(url: str) -> str:
    try:
        parsed = urlparse(url if url.startswith(('http://','https://')) else f'http://{url}')
        return parsed.netloc.lower()
    except Exception:
        return url.lower()

def check_homograph_attack(domain: str) -> bool:
    suspicious_chars = ['а','о','р','е','х','у','с','н','к','і']
    return any(ch in domain for ch in suspicious_chars)

def is_url_shortener(domain: str) -> bool:
    shorteners = {'bit.ly','tinyurl.com','t.co','goo.gl','ow.ly','is.gd','buff.ly'}
    return domain in shorteners

### ------------------------------------------------------
### URL RISK ANALYSIS
### ------------------------------------------------------

def analyze_url_risk(url: str, is_subject: bool=False) -> Tuple[float, List[str]]:
    key = hashlib.md5(f"{url}_{is_subject}".encode()).hexdigest()
    if key in domain_cache:
        return domain_cache[key]
    m = 1.1 if is_subject else 1.0
    score = 0.0
    reasons: List[str] = []
    u = url.lower()
    domain = extract_domain(url)
    if any(t in domain for t in trusted_domains):
        r = (0.0, ["Trusted domain - no risk"])
        domain_cache[key] = r
        return r
    if any(s in u for s in safe_domains):
        r = (0.0, ["Safe domain - no risk"])
        domain_cache[key] = r
        return r
    for sd in suspicious_domains:
        if sd in u:
            score += 3 * m
            reasons.append(f"Known suspicious domain: {sd}")
            break
    if ip_pattern.search(url):
        score += 4 * m
        reasons.append("Uses IP address instead of domain name")
    sub_count = domain.count('.')
    if sub_count > 3:
        score += 2 * m
        reasons.append(f"Too many subdomains ({sub_count})")
    for pat, desc in suspicious_patterns:
        if pat.search(url):
            score += 2 * m
            reasons.append(desc)
    L = len(url)
    if L > 150:
        score += 2 * m
        reasons.append("Extremely long URL")
    elif L > 75:
        score += 1 * m
        reasons.append("Unusually long URL")
    hy = domain.count('-')
    if hy > 3:
        score += 1.5 * m
        reasons.append(f"Too many hyphens in domain ({hy})")
    if check_homograph_attack(domain):
        score += 3 * m
        reasons.append("Potential homograph attack")
    if is_url_shortener(domain):
        score += 1.5 * m
        reasons.append("Uses URL shortener")
    r = (round(score, 2), reasons)
    domain_cache[key] = r
    return r

### ------------------------------------------------------
### BUZZWORD DETECTION LOGIC
### ------------------------------------------------------

def analyze_text_patterns(text: str, weight_multiplier: float=1.0) -> Tuple[float, List[str]]:
    s = 0.0
    matches: List[str] = []
    for n, data in buzzword_categories.items():
        c = 0
        for p in data['patterns']:
            if p.search(text):
                c += 1
        if c > 0:
            s += c * data['weight'] * weight_multiplier
            matches.append(f"{n}: {c} matches")
    return s, matches

### ------------------------------------------------------
### EMAIL SENDER ANALYSIS
### ------------------------------------------------------

def analyze_sender(sender_email: str) -> float:
    if not sender_email or '@' not in sender_email:
        return 1.0
    domain = sender_email.split('@')[1].lower()
    if any(t in domain for t in trusted_domains):
        return 0.0
    score = 0.0
    if re.search(r'\d{3,}', domain):
        score += 1.5
    if domain.count('-') > 2:
        score += 1.0
    if len(domain.split('.')) > 3:
        score += 1.0
    return score

### ------------------------------------------------------
### COMPREHENSIVE PHISHING DETECTION
### ------------------------------------------------------

def detect_phishing_comprehensive(subject: str, body: str, urls: List[str]=None) -> Dict:
    if urls is None:
        urls = url_pattern.findall(subject + " " + body)
    s_score, s_patterns = analyze_text_patterns(subject, 1.2)
    b_score, b_patterns = analyze_text_patterns(body, 1.0)

    url_scores, url_risks = [], []
    total_url = 0.0
    for u in urls:
        risk, reasons = analyze_url_risk(u, u in subject)
        url_scores.append(risk)
        url_risks.extend(reasons)
        total_url += risk
    
    # Round to 2 decimal places
    total = s_score + b_score + total_url
    total_rounded = round(total, 2)

    reasons_list = [
        [s_patterns], [b_patterns], [url_risks]
    ]
    return total_rounded, reasons_list

### ------------------------------------------------------
### BATCH AND CACHE UTILITIES
### ------------------------------------------------------

def batch_analyze(emails: List[Dict]) -> List[Dict]:
    results = []
    for i, e in enumerate(emails):
        r = detect_phishing_comprehensive(
            e.get('subject',''),
            e.get('body',''),
            e.get('sender',''),
            e.get('urls', [])
        )
        r['email_id'] = e.get('id', i)
        results.append(r)
    return results

def clear_cache():
    domain_cache.clear()

### ------------------------------------------------------
### MAIN EXECUTION FOR TESTING
### ------------------------------------------------------

if __name__ == "__main__":
    load_domain_lists(["phishing-site.com","fake-bank.net","suspicious.org"],["legitimate-bank.com","trusted-site.org"])
    subj = "URGENT: Your account will be suspended - Act now!"
    body = "Verify immediately at http://fake-bank.net/login-verify-urgent"
    sender = "security@fak3-bank.com"
    res = detect_phishing_comprehensive(subj, body, sender)
    print(res['risk_level'], res['total_risk_score'], res['body_analysis'])
