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

# Matches raw IPv4 addresses inside text (e.g., "http://192.168.0.5/...").
# Raw IP links are a common phishing tactic.
ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

# Matches full URLs that start with http:// or https:// (case-insensitive).
url_pattern = re.compile(r'https?://[^\s<>"]+', re.IGNORECASE)

# Matches "bare" domains like "www.paypal.com" or "foo.example.com/path"
# even without a scheme. This lets us catch links that aren't clickable yet.
bare_domain_pattern = re.compile(
    r'''(?ix)
    \b
    (?:www\.)?
    (?:[a-z0-9-]+\.)+[a-z]{2,}
    (?:/[^\s<>"']*)?
    \b
    '''
)

# Phrases that are suspicious when they appear in the *URL itself*.
# If a URL text matches any of these (e.g., ".../secure-account-update"),
# we nudge the risk score up.
suspicious_patterns = [
    (re.compile(r'secure.*update', re.IGNORECASE), "Contains 'secure update' pattern"),
    (re.compile(r'verify.*account', re.IGNORECASE), "Contains 'verify account' pattern"),
    (re.compile(r'login.*now', re.IGNORECASE), "Contains 'login now' pattern"),
    (re.compile(r'suspended.*account', re.IGNORECASE), "Contains 'suspended account' pattern"),
    (re.compile(r'urgent.*action', re.IGNORECASE), "Contains 'urgent action' pattern"),
]

# These sets can be populated at runtime to override risk for certain domains.
safe_domains = set()
suspicious_domains = set()

# Cache {md5(url+is_subject): (score, reasons)} to avoid re-scoring repeats.
domain_cache: Dict[str, Tuple[float, List[str]]] = {}

# If a domain (or its subdomain) is in this set, the URL score is forced to 0.
trusted_domains = {
    'google.com','microsoft.com','apple.com','amazon.com','paypal.com','ebay.com',
    'facebook.com','twitter.com','linkedin.com','github.com','stackoverflow.com'
}

# TLDs that frequently show up in phishing campaigns.
SUSPICIOUS_TLDS = {
    '.zip','.mov','.top','.xyz','.click','.country','.support',
    '.gq','.tk','.ml','.cf','.ga'
}

# =============================
# BUZZWORD DETECTION SETUP
# =============================

def compile_buzzword_patterns() -> Dict:
    # Categories of context words. They score the *subject* a bit higher
    # than the body later (because scary words in the subject are extra alarming).
    categories = {
        'urgency': { 'weight': 3, 'words': [ ... ] },
        'financial_threats': { 'weight': 4, 'words': [ ... ] },
        'manipulation_prompts': { 'weight': 3.5, 'words': [ ... ] },
        'impersonation': { 'weight': 4.5, 'words': [ ... ] },
        'tier1_blacklist': { 'weight': 10, 'words': [ ... ] },
    }

    # Compile each category to a single regex that tolerates "log in" / "log-in" / "log_in".
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
    """Load your custom suspicious/safe domains (full roots; subdomain-aware matching later)."""
    global suspicious_domains, safe_domains
    suspicious_domains = set(d.lower().rstrip('.') for d in suspicious)
    safe_domains = set(d.lower().rstrip('.') for d in safe)

def load_trusted_from_json(path: str = "whitelist.json", replace: bool = False) -> None:
    """Whitelist loader so official domains get 0 risk quickly."""
    global trusted_domains
    p = Path(path)
    data = json.loads(p.read_text(encoding="utf-8"))
    # ...parsing schema variations (list or dict with "domains"/etc.)...
    # result goes into trusted_domains (replace or update).

def extract_domain(url: str) -> str:
    """Robustly get host from URL; add http:// if missing; normalize casing/trailing dot."""
    try:
        parsed = urlparse(url if url.startswith(('http://','https://')) else f'http://{url}')
        return parsed.netloc.rstrip('.').lower()
    except Exception:
        return url.rstrip('.').lower()

def domain_matches(base: str, host: str) -> bool:
    """True if host == base or host ends with '.base' (so subdomains match)."""
    base = base.lower().rstrip('.')
    host = host.lower().rstrip('.')
    return host == base or host.endswith('.' + base)

def check_homograph_attack(domain: str) -> bool:
    """Quick heuristic: flag suspicious Unicode lookalike characters in the domain."""
    suspicious_chars = ['а','о','р','е','х','у','с','н','к','і']  # Cyrillic-like, etc.
    return any(ch in domain for ch in suspicious_chars)

def is_url_shortener(domain: str) -> bool:
    """Known shorteners hide the real destination → small risk bump."""
    shorteners = {'bit.ly','tinyurl.com','t.co','goo.gl','ow.ly','is.gd','buff.ly'}
    return domain in shorteners

def shannon_entropy(s: str) -> float:
    """Measures randomness; very random long path/query → mild suspicion."""
    if not s: return 0.0
    freqs = {}
    for ch in s: freqs[ch] = freqs.get(ch,0)+1
    return -sum((c/len(s))*log2(c/len(s)) for c in freqs.values())

def defang_to_urlish(text: str) -> str:
    """
    Turn 'defanged' IOCs into catchable URLs.
    - hxxp(s)://  -> http(s)://
    - [.] (.) {dot} [dot] ' dot ' -> .
    - "www . example . com" -> "www.example.com"
    """
    t = text
    t = re.sub(r'(?i)\bhx+tp(s?)://', r'http\1://', t)       # hxxp:// -> http://
    t = re.sub(r'(?i)\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*dot\s*\}|\[\s*dot\s*\]|\s+dot\s+', '.', t)
    t = re.sub(r'(?i)\bwww\s*\.\s*(?=\w)', 'www.', t)        # www . x -> www.x
    return t

def extract_urls(subject: str, body: str) -> List[str]:
    """
    Extract URLs from subject & body (including defanged & bare domains).
    Normalize bare domains to http:// so downstream parsing is consistent.
    """
    merged = defang_to_urlish(subject + " " + body)

    # 1) Strict http(s) URLs.
    hits = set(url_pattern.findall(merged))

    # 2) Bare domains / www.* (turn into http://... if no scheme).
    for m in bare_domain_pattern.findall(merged):
        if not m.lower().startswith(('http://', 'https://')):
            hits.add('http://' + m)
        else:
            hits.add(m)

    # 3) Trim trivial trailing punct that often sticks to copied URLs.
    cleaned = [u.rstrip('.,);]}>') for u in hits]

    # 4) Return sorted unique list.
    return sorted(set(cleaned))

# =============================
# URL RISK ANALYSIS
# =============================

def analyze_url_risk(url: str, is_subject: bool=False) -> Tuple[float, List[str]]:
    """
    Score a single URL. If it's literally present in the subject, apply a 1.1x multiplier
    (subject links are riskier). Return (score, list_of_reasons).
    """
    # Cache key includes whether the URL appeared in subject.
    key = hashlib.md5(f"{url}_{is_subject}".encode()).hexdigest()
    if key in domain_cache:
        return domain_cache[key]

    # Subject URLs get a small multiplier (m=1.1). Body URLs m=1.0.
    m = 1.1 if is_subject else 1.0
    score = 0.0
    reasons: List[str] = []

    # Parse domain and path/query (works even if scheme was missing).
    domain = extract_domain(url)
    pathq = ''
    try:
        sp = urlsplit(url if url.startswith(('http://','https://')) else f'http://{url}')
        pathq = (sp.path or '') + (('?' + sp.query) if sp.query else '')
    except Exception:
        pass

    # --- Early exits: anything trusted/safe is forced to 0 risk ---
    if any(domain_matches(t, domain) for t in trusted_domains):
        r = (0.0, ["Trusted domain - no risk"])
        domain_cache[key] = r
        return r

    if any(domain_matches(s, domain) for s in safe_domains):
        r = (0.0, ["Safe domain - no risk"])
        domain_cache[key] = r
        return r

    # --- Positive risk signals (each adds to score * m) ---

    # Known-bad root or its subdomain.
    if any(domain_matches(s, domain) for s in suspicious_domains):
        score += 3 * m
        reasons.append("Known suspicious domain")

    # URLs that contain an IP address.
    if ip_pattern.search(url):
        score += 4 * m
        reasons.append("Uses IP address instead of domain name")

    # Deep subdomain chains (e.g., a.b.c.d.example.com).
    sub_count = domain.count('.')
    if sub_count > 3:
        score += 2 * m
        reasons.append(f"Too many subdomains ({sub_count})")

    # Suspicious phrases inside the full URL text.
    for pat, desc in suspicious_patterns:
        if pat.search(url):
            score += 2 * m
            reasons.append(desc)

    # Suspicious TLD (e.g., .zip).
    tld = '.' + domain.split('.')[-1] if '.' in domain else ''
    if tld in SUSPICIOUS_TLDS:
        score += 1.5 * m
        reasons.append(f"Suspicious TLD ({tld})")

    # Long + high-entropy path/query looks obfuscated or token-heavy.
    if len(pathq) >= 20 and shannon_entropy(pathq) >= 4.0:
        score += 1.5 * m
        reasons.append("High-entropy path/query")

    # Sensitive path terms suggest credential capture or account control.
    SUSP_PATH_TERMS = {'login','signin','verify','account','secure','auth','update','confirm','password','reset'}
    pq = (pathq or '').lower()
    path_hits = [w for w in SUSP_PATH_TERMS if w in pq]
    if path_hits:
        add = min(len(path_hits), 3) * 0.8 * m  # cap at 3 terms
        score += add
        reasons.append(f"Sensitive terms in path/query: {', '.join(sorted(path_hits))} (+{add:g})")

    # Hyphen-spam in domain (common in fake-brand lookalikes).
    hy = domain.count('-')
    if hy > 3:
        score += 1.5 * m
        reasons.append(f"Too many hyphens in domain ({hy})")

    # Unicode lookalikes (homograph risk).
    if check_homograph_attack(domain):
        score += 3 * m
        reasons.append("Potential homograph attack")

    # URL shorteners hide the destination.
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
    """True if a hit from A is within ~80 chars of a hit from B (e.g., 'urgent' near 'click here')."""
    for m in patA.finditer(text):
        start = max(0, m.start() - max_chars)
        end   = m.end() + max_chars
        if patB.search(text[start:end]):
            return True
    return False

def analyze_text_patterns(text: str, weight_multiplier: float=1.0) -> Tuple[float, List[str]]:
    """
    Score context words in a block of text (subject or body).
    - Cap each category at 3 hits (prevents repetition inflation).
    - Subject will call this with multiplier=1.2; body uses 1.0.
    - Add a small proximity bonus if 'urgency' is near 'manipulation_prompts'.
    """
    total = 0.0
    notes: List[str] = []

    for name, data in buzzword_categories.items():
        matches = data['pattern'].findall(text)
        if matches:
            capped = min(len(matches), 3)
            add = capped * data['weight'] * weight_multiplier
            total += add
            notes.append(f"{len(matches)} {name} hit(s), +{add:g}")

    # Proximity makes "hurry + click" combos a bit riskier.
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
    """Final label from the combined score (URL + subject + body)."""
    if score >= 7.0:
        return "high"
    if score >= 3.0:
        return "medium"
    return "low"

def detect_phishing_comprehensive(subject: str, body: str, urls: Optional[List[str]] = None) -> Dict:
    """
    End-to-end for one email:
    1) Extract URLs from subject+body (unless urls provided).
    2) Score subject & body buzzwords (subject gets higher weight).
    3) Apply Tier-1 bonus (doesn't auto-force 'high').
    4) Score each URL (subject URLs get 1.1x).
    5) Combine; apply 'hard-high' tripwires; return details.
    """
    # If caller didn't pass URLs, auto-extract from subject+body (defang-aware).
    if urls is None:
        urls = extract_urls(subject, body)

    # Subject weighs more than body in buzzword context.
    s_score, s_patterns = analyze_text_patterns(subject, 1.2)
    b_score, b_patterns = analyze_text_patterns(body, 1.0)

    # --- Tier-1 blacklist (adult/piracy/urgent/scammy). Adds to BODY score only. ---
    # This raises the overall score but does NOT by itself force the final label to 'High'.
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
    hard_high = False  # any tripwire sets this and forces final label to "high"

    for u in urls:
        # If the *exact* URL string appears in the subject, apply the URL subject-multiplier (1.1x).
        url_score, reasons = analyze_url_risk(u, is_subject=(u in subject))
        total_url += url_score

        # Store a human-readable breakdown for each URL (for UI/explanations).
        if reasons:
            url_reasons.append(f"URL: {u} — " + "; ".join(reasons) + f" ( +{round(url_score, 2)} )")
        else:
            url_reasons.append(f"URL: {u} — no obvious risk ( +0 )")

        # 'Hard-high' tripwires: IP link, homograph domain, or known-bad domain.
        d = extract_domain(u)
        if ip_pattern.search(u) or check_homograph_attack(d) or any(domain_matches(s, d) for s in suspicious_domains):
            hard_high = True

    # Final combined score (rounded), then risk bucket.
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
    """Run the detector over a list of {subject, body, urls?, id?} items."""
    results = []
    for i, e in enumerate(emails):
        provided_urls = e.get('urls')
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
    """Reset per-URL memoization."""
    domain_cache.clear()
