import json
import re
import ipaddress
import sys
import math
from pathlib import Path
from typing import Tuple, List, Set, Dict
reasons =[]

PUBLIC_SUFFIXES_2LABEL = {
    # Singapore
    "com.sg", "net.sg", "org.sg", "edu.sg", "gov.sg",
    "co.uk", "com.au", "com.my", "com.hk", "co.jp", "com.br"
}

BRAND_KEYWORDS = ["amazon", "paypal", "azure", "gmail", "icloud", "outlook" "office", "office365", "microsoftonline", "ebay", "shopify","Eventbrite", "interactivebrokers",
    "yahoo", "google", "gmail", "apple", "microsoft", "dbs", "posb", "ocbc", "uobgroup", "Lazada", "shopee", "grab", "trustbank", "nlb", "gov", "singpass", "iras"
    "hdb", "mysingapore", "sit", "np", "nyp", "nus" "ntu", "smu", "sutd", "suss", "moe", "simba", "coursera", "edx", "facebook", "facebookmail", "meta", "twitter"
    "linkedin", "Instagram", "youtube", "Netflix", "yahoo", "nike", "adidas", "puma", "reebok", "underarmour", "walmart", "target", "bestbuy", "costco", "homedepot", "lowes", "ikea"
    "starbucks", "mcdonalds", "burgerking", "kfc", "subway", "dunkindonuts", "pizzahut", "dominos", "chipotle", "tacobell", "wendys", "kohl's", "sephora", "ulta", "macys", "nordstrom"
    "zara", "hm", "uniqlo", "gap", "forever21", "oldnavy", "bananarepublic", "jcrew", "costco", "wayfair", "overstock", "chewy", "petsmart", "petco", "decathalon", "sportsdirect", "footlocker"]

actions = [
    "action", "secure", "security", "login", "signin", "verify", "update", "confirm", "account",
    "billing", "invoice", "payment", "wallet", "transaction", "refund", "bank",
    "alert", "urgent", "notice", "warning", "suspend", "blocked", "deactivate",
    "activate", "reset", "unlock", "support", "helpdesk", "service", "required","notify"
]

FREEMAIL_DEFAULT = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "icloud.com", "aol.com", "protonmail.com", "mail.com", "live.com", "msn.com"
}

ROLE_KEYWORDS = {
    "admin", "administrator", "root", "sysadmin",
    "support", "helpdesk", "service", "customerservice", "customer-service",
    "billing", "payroll", "hr", "finance", "accounts", "accounting",
    "security", "compliance", "itdesk", "it-support", "updates",
    "noreply", "no-reply", "notifications", "notify",
    "alert", "alerts", "claims", "dispute", "collections"
}

TIER1_BLACKLIST = {
    # adult / explicit
    "sex", "sexy", "porn", "pornstar", "pr0n", "xxx", "nude", "nudes",
    "erotic", "escort", "cam", "camgirl", "camguy", "onlyfans", "ofans",
    "sugarbaby", "sugardaddy", "milf", "bdsm", "fetish", "asshole", "blowjob", "cum", "cocksuck",

    # piracy / hacking
    "pirate", "piracy", "warez", "crack", "cracked", "keygen", "serials",
    "torrent", "leak", "leaker", "leakz", "hack", "hacker", "h4ck",
    "exploit", "zeroday", "botnet", "stealer", "phish", "scammer", "spammer",

    #urgent / scammy
    "urgent", "immediate", "asap", "attention", "important", "alert", "alerts",
    "winner", "winners", "prize", "prizes", "congrats", "lottery", "lotto",
    "claim", "claims", "reward", "rewards", "bonus", "bonuses", "cash", "money", "rich", "wealth", "million", "billion"
}

#---------------------------------------------------------------------------------HELPER FUNCTIONS---------------------------------------------------------------------------------
# --- helper: normalize common homoglyphs (very small, fast) ---
def _normalize_homoglyphs(s: str) -> str:
    s = s.lower()
    # multi-char swaps first
    s = s.replace("rn", "m").replace("vv", "w")
    # single-char swaps
    table = str.maketrans({
        "0": "o", "1": "l", "3": "e", "5": "s", "7": "t", "8": "b",
        "@": "a", "$": "s"
    })
    return s.translate(table)

# --- helper: Levenshtein distance with early-exit bound ---
def _levenshtein_bounded(a: str, b: str, max_dist: int = 2) -> int | None:
    """
    Returns edit distance if <= max_dist, else None (early exit).
    O(len(a)*len(b)) worst-case but tiny strings so it's fast.
    """
    global BRAND_KEYWORDS
    la, lb = len(a), len(b)
    # quick bound checks
    if abs(la - lb) > max_dist:
        return None
    # ensure a is shorter
    if la > lb:
        a, b = b, a
        la, lb = lb, la
    prev = list(range(lb + 1))
    for i in range(1, la + 1):
        cur = [i] + [0] * lb
        # track the smallest value in this row for early exit
        row_min = cur[0]
        ca = a[i - 1]
        for j in range(1, lb + 1):
            cost = 0 if ca == b[j - 1] else 1
            cur[j] = min(
                prev[j] + 1,      # deletion
                cur[j - 1] + 1,   # insertion
                prev[j - 1] + cost  # substitute
            )
            if cur[j] < row_min:
                row_min = cur[j]
        if row_min > max_dist:
            return None
        prev = cur
    return prev[-1] if prev[-1] <= max_dist else None

# --- helper: extract SLD (second-level domain) from full domain ---
def extract_sld(domain: str) -> str | None:
    """
    Return the registrable SLD (the label immediately left of the public suffix).
    Works for normal TLDs (e.g., example.com -> example) and common 2-label
    public suffixes (e.g., yah00.com.sg -> yah00). Returns None if not enough labels.
    """
    if not domain:
        return None
    parts = domain.strip().lower().split(".")
    if len(parts) < 2:
        return None

    # try 2-label public suffix match
    if len(parts) >= 3:
        suffix2 = ".".join(parts[-2:])       # e.g., com.sg
        suffix2_alt = ".".join(parts[-2:])   # alias to keep readable
        if suffix2 in PUBLIC_SUFFIXES_2LABEL:
            return parts[-3]                 # the label before the 2-label suffix

    # fallback: simple 1-label suffix (example.com -> example)
    return parts[-2]

# simple leetspeak map for common substitutions
LEET_MAP = str.maketrans({
    "0": "o",
    "1": "i",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "$": "s",
    "@": "a"
})

#Add points to the score
def add_points(points):
    global score        # tells Python you want to modify the global, not a local copy
    score = score + points

#Helper to Load Whitelist
def load_whitelist(path="whitelist.json"):
    """Load whitelist domains from JSON file. Returns a set of domains (lowercased)."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        # ensure everything is normalized to lowercase and trimmed
        domains = {d.strip().lower() for d in data.get("domains", []) if isinstance(d, str)}
        return domains
    #error handling
    except FileNotFoundError:
        print(f"Error: {path} not found. Treating whitelist as empty.")
        return set()
    except json.JSONDecodeError as e:
        print(f"Error decoding {path}: {e}. Treating whitelist as empty.")
        return set()

#Helper to read sender email from input (for testing purposes)
def read_sender():
    """Read a sender email from console and return lowercased trimmed string or None."""
    s = input("Enter sender email (or press Enter to cancel): ").strip()
    if s == "":
        print("No input provided.")
        return None
    return s.lower()

#Splits sender email into local part and domain
def split_sender(email: str):
    """
    Split email into (local_part, domain) using partition (splits at the last @).
    Returns (local, domain) or (None, None) on invalid address.
    """
    if email is None:
        return None, None
    # partition returns (before, sep, after)
    local, sep, domain = email.rpartition("@")
    if sep != "@" or local == "" or domain == "":
        return None, None
    return local, domain

# Helper to load bad domain list from text file
def load_bad_domains(file_path: str) -> set:
    """
    Reads a text file line by line and loads domains into a Python set.
    Skips empty lines and lines starting with '#'.
    Returns a set of domains (all lowercase).
    """
    bad_domains = set()
    path = Path(file_path)

    with path.open("r", encoding="utf-8") as f:
        for line in f:
            domain = line.strip().lower()
            if not domain or domain.startswith("#"):
                continue
            bad_domains.add(domain)

    print(f"[badlist] Loaded {len(bad_domains)} domains from {file_path}")
    return bad_domains

# Helper to extract registrable domain and SLD without external dependencies, for RULE 1
def _registrable_and_sld(domain: str) -> Tuple[str, str]:
    """
    Heuristic registrable domain & SLD extractor without external deps.
    Returns (registrable_domain, sld).
    Examples:
      'secure.paypal.com'         -> ('paypal.com', 'paypal')
      'updates.amazon.co.uk'      -> ('amazon.co.uk', 'amazon')    # via _TWO_LEVEL_PSL
      'service.gov.sg'            -> ('gov.sg', 'gov')
      'weird.tld'                 -> ('weird.tld', 'weird')
    """
    d = (domain or "").lower().strip(".")
    parts = d.split(".")
    if len(parts) < 2:
        return d, parts[0] if parts else ""

    last2 = ".".join(parts[-2:])
    if last2 in BRAND_KEYWORDS and len(parts) >= 3:
        # e.g., foo.amazon.co.uk -> registrable = amazon.co.uk, sld = amazon
        return ".".join(parts[-3:]), parts[-3]
    else:
        # e.g., secure.paypal.com -> registrable = paypal.com, sld = paypal
        return ".".join(parts[-2:]), parts[-2]

# Helper to tokenize local-part for RULE 1
def _tokenize_local(local: str) -> List[str]:
    """Split local-part into tokens on common separators (case-folded)."""
    return [t for t in re.split(r"[._+\-]", (local or "").lower()) if t]

# Helper to compute Shannon entropy of a string For RULE 2 for Local Part
def shannon_entropy(s: str) -> float:
    """Compute Shannon entropy per character."""
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)
#---------------------------------------------------------------------------------HELPER FUNCTIONS END---------------------------------------------------------------------------------

#------------------------------------------------------------------------------------DOMAIN CHECK FNS-------------------------------------------------------------------------------------
# 0TH Check for Local-part & Domain — Tier-1 blacklist terms (with leetspeak and separators).
def check_tier1_blacklist_multi(domain: str, weight: int = 10, aggregate: bool = False):
    if not domain:
        return 0, []

    SEP_RX = r"[-._|+]+"  # same as in local-part cleanup

    # Normalize the local part
    normalized = domain.lower().translate(LEET_MAP)
    normalized = re.sub(SEP_RX, "", normalized)

    score, reasons = 0, []

    for term in TIER1_BLACKLIST:
        # Normalize the term the same way
        term_norm = term.lower().translate(LEET_MAP)
        term_norm = re.sub(SEP_RX, "", term_norm)

        if not term_norm:
            continue  # skip empty after stripping

        count = len(re.findall(re.escape(term_norm), normalized))
        if count == 0:
            continue

        if aggregate:
            inc = weight * count
            score += inc
            reasons.append(f"Local-part contains '{term}' x{count} (+{inc})")
        else:
            for _ in range(count):
                score += weight
                reasons.append(f"'{term}' (+{weight})")

    return score, reasons

# 1ST Check for Domain to check if domain is in bad domain BLACKLIST
def is_bad_domain(domain: str, bad_domains: set) -> bool:
    """
    Check if a domain is in the bad domain set (exact match).
    """
    return domain.lower().strip() in bad_domains

# 2ND Check for Domain — Very long domain / very many labels.
def check_domain_length(domain: str) -> tuple[int, list[str]]:
    """
    Heuristic #8 — Very long domain / very many labels.
    Returns: (points, reasons)

    Default thresholds (tune as needed):
      - TOTAL_LEN_WARN / TOTAL_LEN_HIGH: overall domain length triggers
      - LABELS_WARN / LABELS_HIGH: number of dot-separated labels (parts)
    Scoring (suggested mild-to-moderate):
      - +3 if length >= TOTAL_LEN_WARN, +6 if length >= TOTAL_LEN_HIGH
      - +2 if labels >= LABELS_WARN, +4 if labels >= LABELS_HIGH
      - +1 if any empty label detected (e.g., consecutive dots)
      - Cap total from this check at MAX_POINTS (default 8)
    """
    # ---------- thresholds (edit these) ----------
    TOTAL_LEN_WARN = 60
    TOTAL_LEN_HIGH = 80
    LABELS_WARN = 6
    LABELS_HIGH = 8
    MAX_POINTS = 30
    # --------------------------------------------

    pts = 0
    reasons = []

    if not domain:
        return 0, ["no domain provided for length/labels check"]

    d = domain.strip().lower()
    total_len = len(d)

    # split on '.'; keep empty parts to detect consecutive dots like 'a..b.com'
    parts = d.split(".")
    label_count = len(parts)

    # empty labels (consecutive dots or leading/trailing dot)
    empty_labels = sum(1 for p in parts if p == "")
    if empty_labels > 0:
        pts += 10
        reasons.append(f"{empty_labels} empty label(s) detected (consecutive/edge dots) (+1)")

    # length-based scoring
    if total_len >= TOTAL_LEN_HIGH:
        pts += 20
        reasons.append(f"very long domain ({total_len} chars) (+20)")
    elif total_len >= TOTAL_LEN_WARN:
        pts += 15
        reasons.append(f"long domain ({total_len} chars) (+15)")

    # label-count scoring
    if label_count >= LABELS_HIGH:
        pts += 10
        reasons.append(f"many labels ({label_count}) (+10)")
    elif label_count >= LABELS_WARN:
        pts += 15
        reasons.append(f"several labels ({label_count}) (+15)")

    # cap points from this heuristic
    if pts > MAX_POINTS:
        pts = MAX_POINTS

    return pts, reasons

# 3RD Check for Domain — Brand token in a wrong domain.
def check_brand_token(domain: str, WHITELIST: set = None) -> tuple[int, list[str]]:
    """
    Heuristic #1 — Brand token in a wrong domain. e.g., paypal-security.com
    Returns: (points, reasons)

    Logic:
      - Look for brand keywords inside the domain.
      - If found, and domain is not an official safe brand domain,
        then mark as suspicious.
    """
    pts, reasons = 0, []
    if not domain:
        return 0, ["no domain provided for brand-token check"]

    d = domain.lower().strip()

    for brand in BRAND_KEYWORDS:
        if brand in d:
            if d not in WHITELIST:
                pts += 30
                reasons.append(f"brand token '{brand}' found in suspicious domain '{d}' (+30)")

    return pts, reasons

# 4TH Check for Domain — Brand + action/update tokens/ 1ST CHECK FOR LOCAL PART
def check_brand_action_domain(domain: str, whitelist: set = None) -> tuple[int, list[str]]:
    global BRAND_KEYWORDS, actions
    """
    Heuristic #2 — Detect domains that append "action/update" tokens to brand names
    (e.g., paypal-security.com, secure-paypal-login.net, amazon.update.info).

    Parameters:
      - domain: the domain string to check (e.g., "paypal-security.com")
      - brands: list of brand keywords (e.g., ["paypal","amazon"])
      - actions: list of action/update words (e.g., ["secure","verify","login","update"])
      - whitelist: set of exact-whitelisted domains (skip check if domain exactly in whitelist)

    Returns:
      (points:int, reasons:list[str])

    Scoring (tunable):
      - +20 for brand+action in the same label (very strong)
      - +15 for adjacent labels like "brand.action.tld" or "action.brand.tld" (strong)
      - +8  for brand present anywhere and action present anywhere (weak)
    """

    if not domain:
        return 0, ["no domain provided"]

    d = domain.strip().lower()

    # whitelist exact-match shortcut
    if whitelist and d in whitelist:
        return 0, [f"domain '{d}' is whitelisted (skip brand+action check)"]

    pts = 0
    reasons = []

    # prebuild regex-safe lists
    escaped_brands = [re.escape(b.lower()) for b in BRAND_KEYWORDS if b]
    escaped_actions = [re.escape(a.lower()) for a in actions if a]

    if not escaped_brands or not escaped_actions:
        return 0, ["no brands/actions provided"]

    # Split domain into labels (preserve labels like 'paypal-security' etc.)
    labels = d.split(r"[-_./+]")

    # 1) Strong: brand and action appear in the same label (e.g., paypal-secure)
    #    Pattern: within a label, brand and action appear with optional separators [-_.] or directly concatenated
    same_label_hit = False
    same_label_re = re.compile(
        r"(?:{brand}).{{0,10}}(?:{action})|(?:{action}).{{0,10}}(?:{brand})".format(
            brand="|".join(escaped_brands),
            action="|".join(escaped_actions)
        ),
        flags=re.IGNORECASE
    )
    for lab in labels:
        if same_label_re.search(lab):
            same_label_hit = True
            pts += 20
            reasons.append(f"brand+action in same label '{lab}' (+20)")
            break  # one strong hit is sufficient

    # 2) Strong-medium: adjacent labels (e.g., brand.action.tld or action.brand.tld)
    if not same_label_hit:
        adjacent_hit = False
        for i in range(len(labels)-1):
            left = labels[i]
            right = labels[i+1]
            # check if left contains brand and right contains action (or vice versa)
            if any(b in left for b in [bb.lower() for bb in BRAND_KEYWORDS]) and any(a in right for a in [aa.lower() for aa in actions]):
                adjacent_hit = True
                pts += 15
                reasons.append(f"brand in label '{left}' adjacent to action in label '{right}' (+15)")
                break
            if any(a in left for a in [aa.lower() for aa in actions]) and any(b in right for b in [bb.lower() for bb in BRAND_KEYWORDS]):
                adjacent_hit = True
                pts += 15
                reasons.append(f"action in label '{left}' adjacent to brand in label '{right}' (+15)")
                break

    # 3) Weak: brand anywhere in domain AND action anywhere in domain (not necessarily same label)
    if not same_label_hit and 'adjacent_hit' not in locals():
        # If not earlier hits, check global presence
        domain_has_brand = any(b in d for b in [bb.lower() for bb in BRAND_KEYWORDS])
        domain_has_action = any(a in d for a in [aa.lower() for aa in actions])
        if domain_has_brand and domain_has_action:
            pts += 8
            reasons.append("brand present AND action token present somewhere in domain (+8)")

    return pts, reasons

# 5TH Check for Domain — Typosquat detection via edit distance and homoglyphs.
def check_typosquat_domain(domain: str,
                           whitelist: set | None = None,
                           brands: list[str] | None = None) -> tuple[int, list[str]]:
    if not domain:
        return 0, ["no domain provided for typosquat check"]

    d = domain.strip().lower()
    if whitelist and d in whitelist:
        return 0, [f"domain '{d}' is whitelisted (skip typosquat check)"]

    labels = d.split(".")
    if len(labels) < 2:
        return 0, ["domain has no TLD; cannot compute SLD for typosquat"]

    sld = extract_sld(d)
    if not sld:
     return 0, ["cannot determine SLD for typosquat"]
    # raw (no homoglyph normalization), just remove separators
    sld_raw = sld.replace("-", "").replace("_", "").lower()
    # homoglyph-normalized
    sld_norm = _normalize_homoglyphs(sld_raw)

    brand_list = brands if brands is not None else globals().get("BRAND_KEYWORDS", [])
    if not brand_list:
        return 0, ["no brand list configured for typosquat check"]

    pts = 0
    reasons: list[str] = []

    for brand in brand_list:
        b = brand.lower()
        b_norm = _normalize_homoglyphs(b)

        # 1) If normalization changes SLD to exactly equal brand (or brand_norm) -> flag
        if sld_raw != sld_norm and (sld_norm == b or sld_norm == b_norm):
            pts += 30
            reasons.append(f"SLD '{sld}' equals brand '{brand}' only after homoglyph normalization (+15)")
            break

        # 2) Raw small edit distance (no normalization)
        dist_raw = _levenshtein_bounded(sld_raw, b, max_dist=2)
        if dist_raw == 1:
            pts += 30
            reasons.append(f"SLD '{sld}' close to brand '{brand}' (edit distance 1) (+15)")
            break
        if dist_raw == 2 and len(b) >= 6:
            pts += 25
            reasons.append(f"SLD '{sld}' close to brand '{brand}' (edit distance 2) (+12)")
            break

        # 3) Normalized distance fallback (handles rn→m, vv→w, 0→o etc.)
        dist_norm = _levenshtein_bounded(sld_norm, b_norm, max_dist=2)
        if dist_norm == 1:
            pts += 25
            reasons.append(f"SLD '{sld}' resembles brand '{brand}' after homoglyph normalization (+15)")
            break
        if dist_norm == 2 and len(b_norm) >= 6:
            pts += 22
            reasons.append(f"SLD '{sld}' somewhat resembles brand '{brand}' after normalization (+12)")
            break

    return pts, reasons

# 6TH Check for Domain — Suspicious TLDs.
def check_suspicious_tld(domain: str) -> tuple[int, str]:
    """
    Heuristic #4 — Suspicious TLDs.
    Returns: (points, reason_string)

    - HIGH_RISK_TLDS get +10
    - MEDIUM_RISK_TLDS get +8
    """
    if not domain:
        return 0, "no domain provided for TLD check"

    d = domain.strip().lower()
    if "." not in d:
        return 0, "no dot in domain; no TLD found"

    tld = d.rsplit(".", 1)[-1]

    HIGH_RISK_TLDS = {
        "xyz", "top", "gq", "tk", "ml", "cf", "ga"
    }
    MEDIUM_RISK_TLDS = {
        "club", "online", "site", "info", "click", "link",
        "work", "live", "buzz", "rest", "zip"
    }

    if tld in HIGH_RISK_TLDS:
        return 10, f"suspicious TLD '.{tld}' (+10)"
    if tld in MEDIUM_RISK_TLDS:
        return 8, f"suspicious TLD '.{tld}' (+8)"

    return 0, "TLD not suspicious"

# 7TH Check for Domain — Many hyphens / long multi-part SLDs.
def check_hyphenated_sld(domain: str) -> tuple[int, str]:
    """
    Heuristic #5 — Many hyphens / long multi-part SLDs.
    Returns: (points, reason_string)

    Rules (tunable):
      - If hyphen count >= 3 in SLD -> +6
      - If hyphen count == 2 in SLD -> +4
      - If SLD length >= 25 chars   -> +6
      - If SLD length >= 15 chars   -> +3
    """
    if not domain:
        return 0, "no domain provided for hyphen/length check"

    d = domain.strip().lower()
    labels = d.split(".")
    if len(labels) < 2:
        return 0, "no SLD found"

    sld = labels[-2]  # basic SLD extraction
    hyphens = sld.count("-")
    length = len(sld)

    pts = 0
    reason = "no issues"

    if hyphens >= 3:
        pts += 6
        reason = f"SLD '{sld}' has {hyphens} hyphens (+6)"
    elif hyphens == 2:
        pts += 4
        reason = f"SLD '{sld}' has 2 hyphens (+4)"

    if length >= 25:
        pts += 6
        reason = f"SLD '{sld}' is very long ({length} chars) (+6)"
    elif length >= 15:
        pts += 3
        reason = f"SLD '{sld}' is long ({length} chars) (+3)"

    return pts, reason

# 8TH Check for Domain — IP-as-domain.
def check_ip_as_domain(domain: str) -> tuple[int, str]:
    """
    Heuristic — IP-as-domain.
    Returns: (points, reason_string)

    Flags when the domain is an IP literal (IPv4/IPv6), e.g.:
      - 192.168.1.10
      - [192.0.2.5]
      - [IPv6:2001:db8::1]
      - 2001:db8::2
    """
    if not domain:
        return 0, "no domain provided for IP check"

    d = domain.strip().lower()

    # Strip RFC-style brackets and optional 'ipv6:' prefix
    bracketed = False
    if d.startswith("[") and d.endswith("]"):
        bracketed = True
        d = d[1:-1]
        if d.startswith("ipv6:"):
            d = d[5:]

    try:
        ipaddress.ip_address(d)  # validates IPv4 or IPv6
        pts = 25
        kind = "IPv6" if ":" in d else "IPv4"
        where = "bracketed" if bracketed else "bare"
        return pts, f"{kind} {where} address used as domain (+{pts})"
    except ValueError:
        return 0, "not an IP literal domain"
#------------------------------------------------------------------------------------DOMAIN CHECK FNS END-------------------------------------------------------------------------------------

#------------------------------------------------------------------------------------LOCAL CHECK FNS-----------------------------------------------------------------------------------------

# 2ND Check for Local-part — Local Brand name does not match domain.
def local_equals_brand_rule(
    local: str,
    domain: str,
    brands: Set[str],
    whitelist: Set[str] | None = None,
    freemail: Set[str] | None = None,
) -> Tuple[int, List[str]]:
    """
    Rule: If local-part equals a brand name but the domain is not that brand's domain, flag it.

    Scoring (tunable via `weights`):
      - brand_local_sld_mismatch: +35  (local == brand, but domain SLD != brand)
      - brand_local_domain_contains: +20 (local == brand, domain contains brand elsewhere)
      - brand_local_freemail: +25   (local == brand on freemail domain)
    """
    brands = {b.lower() for b in (brands or set())}
    whitelist = {w.lower() for w in (whitelist or set())}
    freemail = {f.lower() for f in (freemail or FREEMAIL_DEFAULT)}
    weights =  {
        "brand_local_sld_mismatch": 35,
        "brand_local_domain_contains": 20,
        "brand_local_freemail": 25,
    }

    reasons: List[str] = []
    score = 0

    if not local or not domain:
        return 0, ["invalid email parts for local-brand rule"]

    d = domain.lower().strip()
    if d in whitelist:
        return 0, [f"domain '{d}' is whitelisted; skipping local-brand rule"]

    tokens = _tokenize_local(local)           # e.g., "paypal+notify" -> ["paypal","notify"]
    if not tokens:
        return 0, []

    registrable, sld = _registrable_and_sld(d)
    domain_labels = d.split(".")

    # Check: any token equals a brand
    matched_brand = next((b for b in brands if b in tokens), None)
    if not matched_brand:
        return 0, []  # no brand token in local-part

    b = matched_brand  # canonical brand token found in local-part

    # If SLD matches the brand (paypal@paypal.com) -> benign
    if sld == b:
        return 0, [f"local-part equals brand '{b}' with matching brand domain '{registrable}' (benign)"]

    # Freemail case (paypal@gmail.com)
    if d in freemail:
        w = weights["brand_local_freemail"]
        score += w
        reasons.append(f"local-part equals brand '{b}' on freemail domain '{d}' (+{w})")
        return score, reasons

    # Domain contains the brand somewhere (secure-paypal-login.com), but SLD differs
    if any(b in label for label in domain_labels):
        w = weights["brand_local_domain_contains"]
        score += w
        reasons.append(f"local-part equals brand '{b}'; domain contains brand in labels ('{d}') (+{w})")
        return score, reasons

    # Most suspicious: SLD mismatch and no brand anywhere in domain (paypal@random.xyz)
    w = weights["brand_local_sld_mismatch"]
    score += w
    reasons.append(f"local-part equals brand '{b}' but domain SLD '{sld}' != '{b}' ('{registrable}') (+{w})")
    return score, reasons

# 3RD Check for Local Part - Check Long and Random Local example: x8v49kz0qwe23@domain.com
def check_long_random_local(local: str,
                            min_len: int = 15,
                            digit_ratio_thresh: float = 0.5,
                            entropy_thresh: float = 3.5,
                            weight: int = 15) -> Tuple[int, List[str]]:
    """
    Detect long random / high-entropy local-parts.
    Returns (score, reasons).
    """
    if not local:
        return 0, []

    reason, score = [], 0
    lp = local.lower()

    # 1. Length check
    if len(lp) >= min_len:
        score += weight
        reason.append(f"local-part length {len(lp)} >= {min_len} (+{weight})")

    # 2. Digit ratio
    digits = sum(c.isdigit() for c in lp)
    if len(lp) >= 6:  # avoid trivial short cases
        digit_ratio = digits / len(lp)
        if digit_ratio >= digit_ratio_thresh:
            score += weight
            reason.append(f"digit ratio {digit_ratio:.2f} >= {digit_ratio_thresh} (+{weight})")

    # 3. Entropy
    ent = shannon_entropy(lp)
    if ent >= entropy_thresh and len(lp) >= 10:  # avoid short names
        score += weight
        reason.append(f"entropy {ent:.2f} >= {entropy_thresh} (+{weight})")

    # 4. Base64-like pattern
    if re.fullmatch(r"[A-Za-z0-9+/=]{12,}", lp) and len(lp) % 4 == 0:
        score += weight
        reason.append(f"local-part looks base64-like '{local}' (+{weight})")

    return score, reason

# 4th Check for Local Part - Check for unusual Local Part patterns (e.g., single-letter, repeated chars)
def check_unusual_local(local: str,
                        max_separators: int = 3,
                        weight: int = 10,
                        max_score: int = 20) -> Tuple[int, List[str]]:
    """
    Detect many dots/punctuation/unusual chars in local-part.
    Returns (score, reasons).
    Low–Medium signal.
    """
    if not local:
        return 0, []

    reasons, score = [], 0
    lp = local.lower()

    # 1. Consecutive separators (.., --, __)
    if re.search(r"[.\-_]{2,}", lp):
        score += weight
        reasons.append(f"local-part has consecutive separators (e.g. '..' or '--') (+{weight})")

    # 2. Excessive separators overall
    sep_count = sum(lp.count(ch) for ch in ".-_+")
    if sep_count > max_separators:
        score += weight
        reasons.append(f"local-part has {sep_count} separators (> {max_separators}) (+{weight})")

    # 3. Unusual characters outside safe set
    if re.search(r"[^a-z0-9.\-_+]", lp):  # anything not in allowed set
        bad_chars = set(re.findall(r"[^a-z0-9.\-_+]", lp))
        score += weight
        reasons.append(f"local-part contains unusual chars {''.join(bad_chars)} (+{weight})")

    # cap total score for this rule
    if score > max_score:
        score = max_score

    return score, reasons

# 5TH Check For Local Part - Check Numeric Heavy Local 
def check_numeric_heavy_local(
    local: str,
    digit_seq_len: int = 6,
    digit_ratio_thresh: float = 0.5,
    long_seq_weight: int = 8,
    date_pattern_weight: int = 12,
    digit_ratio_weight: int = 10,
    epoch_weight: int = 12,
    max_score: int = 30
) -> Tuple[int, List[str]]:
    """
    Detect numeric-heavy or timestamp-like local-parts.
    Returns (score, reasons).

    - digit_seq_len: minimum digits in a contiguous digit sequence to consider "long" (default 6)
    - digit_ratio_thresh: fraction of characters that are digits to trigger digit-ratio signal
    - weights: score amounts for each heuristic
    - max_score: cap the contribution from this rule
    """
    if not local:
        return 0, []

    lp = local.strip()
    if not lp:
        return 0, []

    reasons: List[str] = []
    score = 0
    lower = lp.lower()

    # 1) contiguous digit sequences
    digit_seqs = re.findall(r"\d+", lower)
    for seq in digit_seqs:
        if len(seq) >= digit_seq_len:
            score += long_seq_weight
            reasons.append(f"local-part contains long digit sequence '{seq}' (len {len(seq)}) (+{long_seq_weight})")

    # 2) date-like patterns YYYYMMDD or YYYY-MM-DD / YYYY_MM_DD
    #    strict YYYYMMDD: (19|20)\d{2}[01]\d[0-3]\d  (simple validation)
    date_matches = re.findall(r"(?:19|20)\d{2}[01]\d[0-3]\d", lower)
    if date_matches:
        for dm in date_matches:
            score += date_pattern_weight
            reasons.append(f"local-part contains date-like token '{dm}' (+{date_pattern_weight})")

    # also catch dashed/underscored dates like 2025-09-24 or 2025_09_24
    dashed_dates = re.findall(r"(?:19|20)\d{2}[-_][01]\d[-_][0-3]\d", lower)
    for dd in dashed_dates:
        score += date_pattern_weight
        reasons.append(f"local-part contains date-like token '{dd}' (+{date_pattern_weight})")

    # 3) possible unix-epoch / very long numeric token (10+ digits)
    for seq in digit_seqs:
        if len(seq) >= 10:
            score += epoch_weight
            reasons.append(f"local-part contains very long numeric token (possible epoch) '{seq}' (+{epoch_weight})")

    # 4) digit ratio across the whole local-part
    total_chars = len(lower)
    if total_chars >= 6:  # avoid noisy short names
        digits = sum(c.isdigit() for c in lower)
        digit_ratio = digits / total_chars
        if digit_ratio >= digit_ratio_thresh:
            score += digit_ratio_weight
            reasons.append(f"digit ratio {digit_ratio:.2f} >= {digit_ratio_thresh} (+{digit_ratio_weight})")

    # cap the rule's contribution
    if score > max_score:
        score = max_score

    return score, reasons

# 6TH Check Detect Lookalike local-part for admin/service
def check_role_local(local: str,
                     roles: set = None,
                     weight: int = 5,
                     max_score: int = 30) -> Tuple[int, List[str]]:
    """
    Detect local-parts that look like role/service accounts (admin, support, etc.)
    Returns (score, reasons).
    """
    if not local:
        return 0, []

    roles = {r.lower() for r in (roles or ROLE_KEYWORDS)}
    lp = local.lower()

    reasons, score = [], 0

    # tokenized match on separators
    tokens = re.split(r"[._+\-]", lp)

    # 1) exact token match
    for tok in tokens:
        if tok in roles:
            score += weight
            reasons.append(f"local-part contains role token '{tok}' (+{weight})")

    # 2) full string match (like 'customerservice' without separators)
    for role in roles:
        if lp == role:
            score += weight
            reasons.append(f"local-part exactly equals role '{role}' (+{weight})")

    # cap score
    if score > max_score:
        score = max_score

    return score, reasons

#-----------------------------------------------------------------------------------LOCAL CHECK FNS END-------------------------------------------------------------------------------------
def calculate_score_domain(sender):
    WHITELIST = load_whitelist("whitelist.json")
    reasons = []
    global score
    score = 0
    local, domain = split_sender(sender)
    skip_more_domain = False
    # ---- EXACT MATCH CHECK (no subdomain allowed) ----
    # If domain exactly equals a whitelist entry -> immediate exit with points = 0, move on to username checks
    print("Checking exact whitelist match...")
    if domain in WHITELIST:
        #exit to local part checks
        reasons.append(f"Domain {domain} is an exact whitelist match, skipping further domain checks.")
        skip_more_domain = True

    if not skip_more_domain:
        # other domain heuristics only run when NOT whitelisted
        # If we get here, the domain is not an exact whitelist entry.
        reasons.append(f"Domain is NOT an exact whitelist match: {domain}, points added = 5.")
        add_points(5) # example penalty for non-whitelisted domain
        # continue program: add your scoring/heuristics here
        # e.g., compute score = analyze_sender_email(sender) ...

        print("Check for domain blacklist Match")
        badset = load_bad_domains("phishing-domains-ACTIVE.txt")
        if is_bad_domain(domain, badset):
            reasons.append(f"⚠️ Domain {domain} is in the blacklist!, points added = 50.")
            add_points(60)  # example penalty for bad domain

    # pattern recognition code

        # check for explicit tier 1 blacklist terms in domain
        print("Check for explicit tier 1 blacklist terms in domain...")
        pts, happy = check_tier1_blacklist_multi(local, 10,False)
        if pts > 0:
            reasons.append(f"Tier 1 Blacklisted Terms Detected: {happy}, points added = {pts}.")
            add_points(pts)

        # check long domain
        print("Check for long domain / many labels...")
        pts, happy = check_domain_length(domain)   
        if pts > 0:
            reasons.append(f"Long domain/Excessive Labels detected:, {happy}, points added = {pts}.")
            add_points(pts)
        
        # check improper brand token
        print("Check for improper brand token")
        pts, happy = check_brand_token(domain, WHITELIST)
        if pts > 0:
            reasons.append(f"Improper Brand Token Detected: {happy}, points added = {pts}.")
            add_points(pts)

        # Detect domains that append "action/update" tokens to brand names
        print("Detect domains that append \"action/update\" or other Scam tokens to brand names\n")
        pts, happy = check_brand_action_domain(domain, WHITELIST)
        if pts > 0:
            reasons.append(f"Scam Token appended to official brand domain detected: {happy}, points added = {pts}.")
            add_points(pts)

        # Typosquatting (single-character change / small edits)
        print("Check for typosquatting (single-character edits)")
        pts, happy = check_typosquat_domain(domain, WHITELIST)  
        if pts > 0:
            reasons.append(f"Typosquatting detected: {happy}, points added = {pts}.")
            add_points(pts)
        
        # Suspicious TLDs detection
        print("Check for suspicious Top Level Domains...")
        pts, happy  = check_suspicious_tld(domain)
        if pts > 0:
            reasons.append(f"Suspicious Top Level Domain detected: {happy}, points added = {pts}.")
            add_points(pts)

        #Many hyphens / long multi-part SLDs
        print("Check for many hyphens / long multi-part Small Level Domains")
        pts, happy = check_hyphenated_sld(domain)
        if pts > 0:
            reasons.append(f"Many hyphens / long multi-part Small Level Domains detected: {happy}, points added = {pts}.")
            add_points(pts)

        #Check if domain is an IP literal
        print("Check if domain is an IP literal")
        pts, happy = check_ip_as_domain(domain)
        if pts > 0:
            reasons.append(f"IP Literal Domain detected: {happy}, points added = {pts}.")
            add_points(pts)
        
    print("Starting Local Part Checks...\n")

    # ---- LOCAL PART CHECKS ----
    
    #Tier 1 Blacklisted Word Check
    print("Detecting Tier 1 Blacklisted Terms in local-part")
    pts, happy = check_tier1_blacklist_multi(local, 10,False)
    if pts > 0:
        reasons.append(f"Tier 1 Blacklisted Terms Detected: {happy}, points added = {pts}.")
        add_points(pts)

    #Local part check for Generic Action Words
    print("Detecting domains that append \"action/update\" or other Scam tokens to brand names")
    pts, happy = check_brand_action_domain(local, WHITELIST)
    if pts > 0:
        reasons.append(f"Scam Token appended to official brand local detected: {happy}, points added = {pts}.")
        add_points(pts)

    #Local-part equals brand while domain doesn’t match official brand domain
    print("Checking if local-part equals brand while domain doesn't match official brand domain")
    pts, happy = local_equals_brand_rule(local,domain,BRAND_KEYWORDS,WHITELIST,FREEMAIL_DEFAULT)
    if pts > 0:
        reasons.append(f"Local-part equals brand while domain doesn't match official brand domain: {happy}, points added = {pts}.")
        add_points(pts)

    #Long random / high-entropy local-parts
    print("Detecting long random / high-entropy local-parts")
    pts, happy = check_long_random_local(local)
    if pts > 0:
        reasons.append(f"Long random / high-entropy local-parts detected: {happy}, points added = {pts}.")
        add_points(pts)
    
    #Many dots / punctuation / unusual chars
    print("Detecting many dots / punctuation / unusual chars in local-part")
    pts, happy = check_unusual_local(local)
    if pts > 0:
        reasons.append(f"Many dots / punctuation / unusual chars in local-part detected: {happy}, points added = {pts}.")
        add_points(pts) 

    #Detect Numeric Heavy or timestamp like local parts
    print("Detecting Numeric Heavy or timestamp-like local part")
    pts, happy = check_numeric_heavy_local(local)
    if pts > 0:
        reasons.append(f"Numeric Heavy or timestamp-like local part detected: {happy}, points added = {pts}.")
        add_points(pts) 

    #Last check Detect Lookalike local-part for admin/service
    pts, happy = check_role_local(local)
    if pts > 0:
        reasons.append(f"Lookalike local-part for admin/service detected: {happy}, points added = {pts}.\n")
        add_points(pts) 

    pts = score
    if score>100:
        score =100
    return score, reasons