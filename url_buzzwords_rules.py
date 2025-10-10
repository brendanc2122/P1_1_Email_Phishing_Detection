import re
import json
import hashlib
from math import log2
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from urllib.parse import urlparse, urlsplit

# =============================
# GLOBAL INITIALIZATION
# =============================

ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
# Strict scheme URLs (http/https)
url_pattern = re.compile(r'https?://[^\s<>"]+', re.IGNORECASE)
# Bare domains + optional path; also catches www.*
bare_domain_pattern = re.compile(
    r'''(?ix)
    \b
    (?:www\.)?
    (?:[a-z0-9-]+\.)+[a-z]{2,}
    (?:/[^\s<>"']*)?
    \b
    '''
)

# URL phrase patterns (kept separate for clarity)
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

# These are full domains; subdomains will be matched via domain_matches()
trusted_domains = {
    'google.com','microsoft.com','apple.com','amazon.com','paypal.com','ebay.com',
    'facebook.com','twitter.com','linkedin.com','github.com','stackoverflow.com'
}

# TLDs frequently abused in phishing (tune for your dataset)
SUSPICIOUS_TLDS = {
    '.zip','.mov','.top','.xyz','.click','.country','.support',
    '.gq','.tk','.ml','.cf','.ga'
}

# =============================
# BUZZWORD DETECTION SETUP
# =============================

def compile_buzzword_patterns() -> Dict:
    categories = {
        'urgency': {
            'weight': 3,
            'words': [
                'urgent','immediate','asap','emergency','critical','deadline',
                'expires','expiring','time sensitive','act now','limited time',
                'hurry','rush','quickly','fast','instant','today only','last chance',
                'final notice',"don't wait",'time is running out',
                'action required','respond now','respond immediately','verify now',
                'update now','within 24 hours','within 48 hours','right away',
                'before it is too late','avoid suspension','avoid deactivation',
                'final warning','final reminder','immediate attention',
                'requires attention','take action','time-critical','time critical',
                'time limited','ends today','offer ends soon','act immediately',
                'review immediately','confirm immediately','secure immediately',
                'pay immediately','call immediately','contact immediately',
                'limited availability','while supplies last','only a few left',
                'exclusive access','exclusive deal','exclusive offer','special access',
            ]
        },
        'financial_threats': {
            'weight': 4,
            'words': [
                'suspended','blocked','frozen','locked','compromised','breach',
                'unauthorized','fraudulent','illegal','violation','penalty','fine',
                'fee','charge','payment failed','declined','overdue','debt','owe',
                'collection','lawsuit','legal action','court','seizure','garnishment',
                'bankruptcy','repossession','foreclosure','taxes owed','audit',
                'refund','rebate','chargeback','billing issue','payment issue',
                'payment problem','credit card issue','credit card problem',
                'account suspension','account deactivation','account restricted',
                'account on hold','limited access','account review',
                'unusual activity','suspicious activity','security alert',
                'invoice overdue','outstanding balance','past due','past-due',
                'settlement required','update billing','update payment method',
                'payment verification','card declined','card expired','verify payment',
                'delivery fee','customs fee','shipping fee'
            ]
        },
        'manipulation_prompts': {
            'weight': 3.5,
            'words': [
                'verify','confirm','update','validate','authenticate','click here',
                'download now','open attachment','free gift','congratulations','winner',
                'selected','exclusive offer','limited offer','act fast',"don't miss out",
                'special promotion','bonus','reward','gift card','voucher','coupon',
                'click link','follow link','link below','see details','more info',
                'learn more','read more','visit site','visit website','go to site',
                'go to website','access account','manage account','account settings',
                'change password','reset password','security settings','update settings',
                'login','logon','sign on','sign-in','log-in','account login',
                'account logon','account sign-in','account sign on',
                'log in','sign in','password reset','password expires',
                'unlock account','re-activate account',
                'complete verification','verify your identity','identity verification',
                'one-time password','otp','2fa','two-factor','multi-factor',
                'enter code','verification code','security code',
                'track package','reschedule delivery','view invoice','view document',
                'approve request','authorize transaction','review details',
                'confirm your details','confirm information','update information',
                'contact support','call support','chat with support',
                'start now','get started','proceed now'
            ]
        },
        'impersonation': {
            'weight': 4.5,
            'words': [
                'security team','support team','account team','fraud department',
                'billing department','customer service','technical support',
                'system administrator','it department','security alert',
                'it security','it help desk','it helpdesk','help desk',
                'it support','security operations','security operations center','soc',
                'network operations','administrator','admin team','sysadmin',
                'compliance team','risk management','accounts payable','payroll',
                'hr department','bank support','card services','billing team',
                'collections team','service desk','service center','customer care',
                'trust and safety','legal department','law enforcement',
                'police department','federal bureau','internal revenue service','irs',
                'social security administration','department of motor vehicles','dmv',
                'united states postal service','usps','shipping department',
                'delivery team','courier service','parcel service'
            ]
        },
        'tier1_blacklist': {
            'weight': 10,
            'words': [
                # adult / explicit
                "sex", "sexy", "porn", "pornstar", "pr0n", "xxx", "nude", "nudes",
                "erotic", "escort", "cam", "camgirl", "camguy", "onlyfans", "ofans",
                "sugarbaby", "sugardaddy", "milf", "bdsm", "fetish", "asshole", "blowjob", "cum", "cocksuck",

                # piracy / hacking
                "pirate", "piracy", "warez", "crack", "cracked", "keygen", "serials",
                "torrent", "leak", "leaker", "leakz", "hack", "hacker", "h4ck",
                "exploit", "zeroday", "botnet", "stealer", "phish", "scammer", "spammer",

                # urgent / scammy
                "urgent", "immediate", "asap", "attention", "important", "alert", "alerts",
                "winner", "winners", "prize", "prizes", "congrats", "lottery", "lotto",
                "claim", "claims", "reward", "rewards", "bonus", "bonuses", "cash", "money", "rich", "wealth", "million", "billion"
            ]
        },
    }

    # Compile regex per category; treat spaces as whitespace OR hyphen OR underscore.
    for data in categories.values():
        escaped = []
        joiner = r"(?:\s+|[-_])+"
        for w in data['words']:
            parts = re.split(r"\s+", w.strip())
            parts_esc = [re.escape(p) for p in parts if p]
            if not parts_esc:
                continue
            escaped.append(joiner.join(parts_esc))
        data['pattern'] = re.compile(r"\b(?:%s)\b" % "|".join(escaped), re.IGNORECASE)

    return categories


buzzword_categories = compile_buzzword_patterns()

# =============================
# DOMAIN & URL UTILITIES
# =============================

def load_domain_lists(suspicious: List[str], safe: List[str]):
    """Load your custom suspicious/safe domains (kept as full domains)."""
    global suspicious_domains, safe_domains
    suspicious_domains = set(d.lower().rstrip('.') for d in suspicious)
    safe_domains = set(d.lower().rstrip('.') for d in safe)

def load_trusted_from_json(path: str = "whitelist.json", replace: bool = False) -> None:
    global trusted_domains
    p = Path(path)
    data = json.loads(p.read_text(encoding="utf-8"))

    if isinstance(data, dict):
        domains = data.get("domains") or data.get("trusted_domains") or data.get("whitelist") or []
    else:
        domains = data

    if isinstance(domains, list) and domains and isinstance(domains[0], dict):
        domains = [item.get("domain", "") for item in domains]

    if not isinstance(domains, list):
        raise ValueError("Invalid whitelist schema; expected list under 'domains' or a top-level list.")

    cleaned = {
        d.strip().lower().rstrip('.')
        for d in domains
        if isinstance(d, str) and d.strip()
    }

    if replace:
        trusted_domains = set(cleaned)
    else:
        trusted_domains.update(cleaned)

def extract_domain(url: str) -> str:
    try:
        parsed = urlparse(url if url.startswith(('http://','https://')) else f'http://{url}')
        return parsed.netloc.rstrip('.').lower()
    except Exception:
        return url.rstrip('.').lower()

def domain_matches(base: str, host: str) -> bool:
    """Exact match, or host is a subdomain of base."""
    base = base.lower().rstrip('.')
    host = host.lower().rstrip('.')
    return host == base or host.endswith('.' + base)

def check_homograph_attack(domain: str) -> bool:
    # Common Cyrillic lookalikes, etc. (quick heuristic)
    suspicious_chars = ['а','о','р','е','х','у','с','н','к','і']
    return any(ch in domain for ch in suspicious_chars)

def is_url_shortener(domain: str) -> bool:
    shorteners = {'bit.ly','tinyurl.com','t.co','goo.gl','ow.ly','is.gd','buff.ly'}
    return domain in shorteners

def shannon_entropy(s: str) -> float:
    if not s: return 0.0
    freqs = {}
    for ch in s: freqs[ch] = freqs.get(ch,0)+1
    return -sum((c/len(s))*log2(c/len(s)) for c in freqs.values())

def defang_to_urlish(text: str) -> str:
    """
    Turn defanged indicators into URL-ish text so extractors can catch them.
    Handles: hxxp(s)://, [.] , (.) , {dot} , [dot] , ' dot ', spaced 'www . '
    """
    t = text
    # hxxp / hxxps -> http / https
    t = re.sub(r'(?i)\bhx+tp(s?)://', r'http\1://', t)
    # [.] (.) {dot} [dot] " dot " -> .
    t = re.sub(r'(?i)\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*dot\s*\}|\[\s*dot\s*\]|\s+dot\s+', '.', t)
    # recover "www . example . com" -> "www.example.com"
    t = re.sub(r'(?i)\bwww\s*\.\s*(?=\w)', 'www.', t)
    return t

def extract_urls(subject: str, body: str) -> List[str]:
    """
    Extract URLs from subject/body, including defanged and bare domains.
    Normalizes bare domains to http:// for consistent downstream parsing.
    """
    merged = defang_to_urlish(subject + " " + body)

    hits = set(url_pattern.findall(merged))

    # pick up bare domains & www.*
    for m in bare_domain_pattern.findall(merged):
        if not m.lower().startswith(('http://', 'https://')):
            hits.add('http://' + m)
        else:
            hits.add(m)

    # strip trivial trailing punctuation
    cleaned = [u.rstrip('.,);]}>') for u in hits]
    return sorted(set(cleaned))

# =============================
# URL RISK ANALYSIS
# =============================

def analyze_url_risk(url: str, is_subject: bool=False) -> Tuple[float, List[str]]:
    key = hashlib.md5(f"{url}_{is_subject}".encode()).hexdigest()
    if key in domain_cache:
        return domain_cache[key]

    m = 1.1 if is_subject else 1.0
    score = 0.0
    reasons: List[str] = []

    domain = extract_domain(url)
    pathq = ''
    try:
        sp = urlsplit(url if url.startswith(('http://','https://')) else f'http://{url}')
        pathq = (sp.path or '') + (('?' + sp.query) if sp.query else '')
    except Exception:
        pass

    # Trusted / safe (exact or subdomain)
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

    # Suspicious phrases in full URL
    for pat, desc in suspicious_patterns:
        if pat.search(url):
            score += 2 * m
            reasons.append(desc)

    # Suspicious TLDs (simple last-label check)
    tld = '.' + domain.split('.')[-1] if '.' in domain else ''
    if tld in SUSPICIOUS_TLDS:
        score += 1.5 * m
        reasons.append(f"Suspicious TLD ({tld})")

    # Entropy & sensitive terms in path/query
    if len(pathq) >= 20 and shannon_entropy(pathq) >= 4.0:
        score += 1.5 * m
        reasons.append("High-entropy path/query")

    SUSP_PATH_TERMS = {'login','signin','verify','account','secure','auth','update','confirm','password','reset'}
    pq = (pathq or '').lower()
    path_hits = [w for w in SUSP_PATH_TERMS if w in pq]
    if path_hits:
        add = min(len(path_hits), 3) * 0.8 * m
        score += add
        reasons.append(f"Sensitive terms in path/query: {', '.join(sorted(path_hits))} (+{add:g})")

    # Hyphen count (domain only)
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

# =============================
# BUZZWORD DETECTION LOGIC
# =============================

def has_proximity(text: str, patA: re.Pattern, patB: re.Pattern, max_chars: int = 80) -> bool:
    for m in patA.finditer(text):
        start = max(0, m.start() - max_chars)
        end   = m.end() + max_chars
        if patB.search(text[start:end]):
            return True
    return False

def analyze_text_patterns(text: str, weight_multiplier: float=1.0) -> Tuple[float, List[str]]:
    total = 0.0
    notes: List[str] = []
    # Count with per-category cap to avoid repetition inflation
    for name, data in buzzword_categories.items():
        matches = data['pattern'].findall(text)
        if matches:
            capped = min(len(matches), 3)
            add = capped * data['weight'] * weight_multiplier
            total += add
            notes.append(f"{len(matches)} {name} hit(s), +{add:g}")

    # Proximity bonus: urgency near manipulation prompts
    bc = buzzword_categories
    if 'urgency' in bc and 'manipulation_prompts' in bc:
        if has_proximity(text, bc['urgency']['pattern'], bc['manipulation_prompts']['pattern'], 80):
            total += 0.8 * weight_multiplier
            notes.append("Urgency ~ Manipulation proximity (+0.8)")

    return total, notes

# =============================
# COMPREHENSIVE PHISHING DETECTION
# =============================

def risk_bucket(score: float) -> str:
    # Tweak thresholds as you gather data
    if score >= 7.0:
        return "high"
    if score >= 3.0:
        return "medium"
    return "low"

def detect_phishing_comprehensive(subject: str, body: str, urls: Optional[List[str]] = None) -> Dict:
    # Auto-extract if urls is None; if caller passes [], we still respect it
    if urls is None:
        urls = extract_urls(subject, body)

    s_score, s_patterns = analyze_text_patterns(subject, 1.2)
    b_score, b_patterns = analyze_text_patterns(body, 1.0)

    # --- Tier-1 buzzword: add extra score (no auto-high) ---
    tier1_pat = buzzword_categories['tier1_blacklist']['pattern']
    tier1_hits_subj = len(tier1_pat.findall(subject))
    tier1_hits_body = len(tier1_pat.findall(body))
    tier1_hits = tier1_hits_subj + tier1_hits_body

    TIER1_BONUS_PER_HIT = 2.0
    TIER1_BONUS_CAP = 6.0  # max extra

    tier1_bonus = min(tier1_hits * TIER1_BONUS_PER_HIT, TIER1_BONUS_CAP)
    if tier1_bonus:
        b_score += tier1_bonus
        b_patterns.append(f"Tier-1 blacklist bonus: {tier1_hits} hit(s) (+{tier1_bonus:g})")

    total_url = 0.0
    url_reasons: List[str] = []
    hard_high = False

    for u in urls:
        url_score, reasons = analyze_url_risk(u, is_subject=(u in subject))
        total_url += url_score
        # Always record a readable line per URL
        if reasons:
            url_reasons.append(f"URL: {u} — " + "; ".join(reasons) + f" ( +{round(url_score, 2)} )")
        else:
            url_reasons.append(f"URL: {u} — no obvious risk ( +0 )")

        d = extract_domain(u)
        if ip_pattern.search(u) or check_homograph_attack(d) or any(domain_matches(s, d) for s in suspicious_domains):
            hard_high = True

    total = round(s_score + b_score + total_url, 2)
    bucket = "high" if hard_high else risk_bucket(total)

    return {
        "total_risk_score": total,
        "risk_level": bucket,
        "subject_analysis": s_patterns,
        "body_analysis": b_patterns,
        "url_analysis": url_reasons,
        "urls_found": urls,
        "hard_high_triggered": hard_high,
    }

# -----------------------------
# BATCH AND CACHE UTILITIES
# -----------------------------

def batch_analyze(emails: List[Dict]) -> List[Dict]:
    results = []
    for i, e in enumerate(emails):
        provided_urls = e.get('urls')
        # If missing or empty list, use auto-extraction by passing None
        urls_arg = None if (provided_urls is None or provided_urls == []) else provided_urls
        r = detect_phishing_comprehensive(
            e.get('subject', ''),
            e.get('body', ''),
            urls=urls_arg
        )
        r['email_id'] = e.get('id', i)
        results.append(r)
    return results

def clear_cache():
    domain_cache.clear()

# =============================
# MAIN (quick demo)
# =============================

if __name__ == "__main__":
    # Load your JSON whitelist next to this file (optional)
    try:
        load_trusted_from_json(Path(__file__).with_name("whitelist.json"), replace=True)
    except Exception as e:
        print("Whitelist load note:", e)

    # Example with defanged URL
    subj = "URGENT: Your account will be suspended - Act now!"
    body = """Verify immediately at hxxp://fake-bank[.]net/login-verify-urgent
              Use your one-time password: 123456 to confirm."""

    res = detect_phishing_comprehensive(subj, body)
    print(res["risk_level"], res["total_risk_score"])
    for line in res["subject_analysis"] + res["body_analysis"] + res["url_analysis"]:
        print("-", line)
