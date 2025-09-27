# check_whitelist_exact.py
# Step: load whitelist.json, read input, split, exact-match domain -> exit with points = 0

import json
import re
import ipaddress
import sys
from pathlib import Path
score = 0   # just like int score = 0;

PUBLIC_SUFFIXES_2LABEL = {
    # Singapore
    "com.sg", "net.sg", "org.sg", "edu.sg", "gov.sg",
    "co.uk", "com.au", "com.my", "com.hk", "co.jp", "com.br"
}

BRAND_KEYWORDS = ["amazon", "paypal", "azure", "gmail", "icloud", "outlook" "office", "office365", "microsoftonline", "ebay", "shopify","Eventbrite", "interactivebrokers",
    "yahoo", "google", "gmail", "apple", "microsoft", "dbs", "posb", "ocbc", "uobgroup", "Lazada", "shopee", "grab", "trustbank", "nlb", "gov", "singpass", "iras"
    "hdb", "mysingapore", "sit", "np", "nyp", "nus" "ntu", "smu", "sutd", "suss", "moe", "simba", "coursera", "edx", "facebook", "facebookmail", "meta", "twitter"
    "linkedin", "Instagram", "youtube", "Netflix", "yahoo" ]

actions = [
    "secure", "security", "login", "signin", "verify", "update", "confirm", "account",
    "billing", "invoice", "payment", "wallet", "transaction", "refund", "bank",
    "alert", "urgent", "notice", "warning", "suspend", "blocked", "deactivate",
    "activate", "reset", "unlock", "support", "helpdesk", "service", "required"
]

def add_points(points):
    global score        # tells Python you want to modify the global, not a local copy
    score = score + points

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

def read_sender():
    """Read a sender email from console and return lowercased trimmed string or None."""
    s = input("Enter sender email (or press Enter to cancel): ").strip()
    if s == "":
        print("No input provided.")
        return None
    return s.lower()

def split_sender(email: str):
    """
    Split email into (local_part, domain) using partition (splits at the first @).
    Returns (local, domain) or (None, None) on invalid address.
    """
    if email is None:
        return None, None
    # partition returns (before, sep, after)
    local, sep, domain = email.partition("@")
    if sep != "@" or local == "" or domain == "":
        return None, None
    return local, domain

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


def is_bad_domain(domain: str, bad_domains: set) -> bool:
    """
    Check if a domain is in the bad domain set (exact match).
    """
    return domain.lower().strip() in bad_domains

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
    MAX_POINTS = 8
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
        pts += 1
        reasons.append(f"{empty_labels} empty label(s) detected (consecutive/edge dots) (+1)")

    # length-based scoring
    if total_len >= TOTAL_LEN_HIGH:
        pts += 6
        reasons.append(f"very long domain ({total_len} chars) (+6)")
    elif total_len >= TOTAL_LEN_WARN:
        pts += 3
        reasons.append(f"long domain ({total_len} chars) (+3)")

    # label-count scoring
    if label_count >= LABELS_HIGH:
        pts += 4
        reasons.append(f"many labels ({label_count}) (+4)")
    elif label_count >= LABELS_WARN:
        pts += 2
        reasons.append(f"several labels ({label_count}) (+2)")

    # cap points from this heuristic
    if pts > MAX_POINTS:
        pts = MAX_POINTS

    return pts, reasons

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
                pts += 15
                reasons.append(f"brand token '{brand}' found in suspicious domain '{d}' (+15)")
            else:
                reasons.append(f"brand token '{brand}' found but matches official domain (safe)")

    return pts, reasons

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
    labels = d.split(".")

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

def check_suspicious_tld(domain: str) -> tuple[int, str]:
    """
    Heuristic #4 — Suspicious TLDs.
    Returns: (points, reason_string)

    - HIGH_RISK_TLDS get +6
    - MEDIUM_RISK_TLDS get +4
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
        return 6, f"suspicious TLD '.{tld}' (+6)"
    if tld in MEDIUM_RISK_TLDS:
        return 4, f"suspicious TLD '.{tld}' (+4)"

    return 0, "TLD not suspicious"

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
        pts = 15
        kind = "IPv6" if ":" in d else "IPv4"
        where = "bracketed" if bracketed else "bare"
        return pts, f"{kind} {where} address used as domain (+{pts})"
    except ValueError:
        return 0, "not an IP literal domain"
    

# Main function
def calculate_score_domain(sender):
    WHITELIST = load_whitelist("whitelist.json")
    reasons = []
    reasons.append("Starting Domain Checks...\n")
    local, domain = split_sender(sender)
    skip_more_domain = False
    # ---- EXACT MATCH CHECK (no subdomain allowed) ----
    # If domain exactly equals a whitelist entry -> immediate exit with points = 0, move on to username checks
    print("Checking exact whitelist match...")
    if domain in WHITELIST:
        # Print a clear message and exit with success code
        reasons.append(f"Exact whitelist domain match: {domain}, points added = 0.")
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
            add_points(50)  # example penalty for bad domain
    
        reasons.append(f"✅ Domain {domain} is NOT in the blacklist, points added = 0.")

    # pattern recognition code

        # check long domain
        print("Check for long domain / many labels...")
        pts, happy = check_domain_length(domain)   
        if pts > 0:
            reasons.append(f"Long domain/Excessive Labels detected:, {happy}, points added = {pts}.")
            add_points(pts)
        elif pts==0:
            reasons.append("No Long Domains or Excessive Labels detectecd, points added = 0.")
        
        # check improper brand token
        print("Check for improper brand token")
        pts, happy = check_brand_token(domain, WHITELIST)
        if pts > 0:
            reasons.append(f"Improper Brand Token Detected: {happy}, points added = {pts}.")
            add_points(pts)
        elif pts==0:
            reasons.append("No Improper Brand Token Detected, points added = 0.")

        # Detect domains that append "action/update" tokens to brand names
        print("Detect domains that append \"action/update\" or other Scam tokens to brand names\n")
        pts, happy = check_brand_action_domain(domain, WHITELIST)
        if pts > 0:
            reasons.append(f"Scam Token appended to official brand domain detected: {happy}, points added = {pts}.")
            add_points(pts)
        elif pts==0:
            reasons.append("No Scam Token appended to official brand domain detected, points added = 0.")

        # Typosquatting (single-character change / small edits)
        print("Check for typosquatting (single-character edits)")
        pts, happy = check_typosquat_domain(domain, WHITELIST)  
        if pts > 0:
            reasons.append(f"Typosquatting detected: {reasons}, points added = {pts}.")
            add_points(pts)
        elif pts==0:
            reasons.append("No typosquatting detected, points added = 0.")
        
        # Suspicious TLDs detection
        print("Check for suspicious Top Level Domains...")
        pts, happy  = check_suspicious_tld(domain)
        if pts > 0:
            reasons.append(f"Suspicious Top Level Domain detected: {happy}, points added = {pts}.")
            add_points(pts)
        elif pts==0:
            reasons.append("No suspicious Top Level Domain detected, points added = 0.")

        #Many hyphens / long multi-part SLDs
        print("Check for many hyphens / long multi-part Small Level Domains")
        pts, happy = check_hyphenated_sld(domain)
        if pts > 0:
            reasons.append(f"Many hyphens / long multi-part Small Level Domains detected: {happy}, points added = {pts}.")
            add_points(pts)
        elif pts==0:
            reasons.append("No hyphens or long multi-part Small Level Domains detected: points added = 0.")

        #Check if domain is an IP literal
        print("Check if domain is an IP literal")
        pts, happy = check_ip_as_domain(domain)
        if pts > 0:
            reasons.append(f"IP Literal Domain detected: {happy}, points added = {pts}.")
            add_points(pts)
        elif pts==0:
            print("No IP Literal Domain detected, points added = 0.")
        
    reasons.append("Starting Local Part Checks...\n")
        
    return score, reasons

#main function
# if __name__ == "__main__":
#     WHITELIST = load_whitelist("whitelist.json")

#     sender = read_sender()
#     if sender is None:
#         # user cancelled
#         sys.exit(0)

#     local, domain = split_sender(sender)
#     if local is None:
#         print("Invalid email format (missing or malformed '@').")
#         # continue program or exit as you need
#         sys.exit(1)

#     # ---- EXACT MATCH CHECK (no subdomain allowed) ----
#     # If domain exactly equals a whitelist entry -> immediate exit with points = 0
#     if domain in WHITELIST:
#         # Print a clear message and exit with success code
#         print("Exact whitelist domain match:", domain)
#         print("points = 0")
#         sys.exit(0)

#     # If we get here, the domain is not an exact whitelist entry.
#     print("Domain is NOT an exact whitelist match:", domain)
#     add_points(5) # example penalty for non-whitelisted domain
#     # continue program: add your scoring/heuristics here
#     # e.g., compute score = analyze_sender_email(sender) ...
#     print("Continuing with further checks...")
#     badset = load_bad_domains("phishing-domains-ACTIVE.txt")
#     if is_bad_domain(domain, badset):
#         print(f"⚠️ Domain {domain} is in the badlist!")
#         add_points(50)  # example penalty for bad domain
#         sys.exit(0)
 
#     print(f"✅ Domain {domain} is NOT in the badlist.")
#     print("Continuing with further checks...")

#     # pattern recognition

#     # check long domain
#     print("Check for long domain / many labels...")
#     pts, reasons = check_domain_length(domain)   
#     if pts > 0:
#         print("check completed, reasons:", reasons)
#         add_points(pts)
#     elif pts==0:
#         print("Nothing suspicious found in this checking sequence")
    
#     print("Continuing with further checks...")

#     # check improper brand token
#     print("Check for improper  brand token")
#     pts, reasons = check_brand_token(domain, WHITELIST)
#     if pts > 0:
#         print("check completed, reasons:", reasons)
#         add_points(pts)
#     elif pts==0:
#         print("Nothing suspicious found in this checking sequence")

#     # Detect domains that append "action/update" tokens to brand names
#     print("Detect domains that append \"action/update\" tokens to brand names\n")
#     pts, reasons = check_brand_action_domain(domain, WHITELIST)
#     if pts > 0:
#         print("check completed, reasons:", reasons)
#         add_points(pts)
#     elif pts==0:
#         print("Nothing suspicious found in this checking sequence")

#     # Typosquatting (single-character change / small edits)
#     print("Check for typosquatting (single-character edits)")
#     pts, reasons = check_typosquat_domain(domain, WHITELIST)  
#     if pts > 0:
#         print("check completed, reasons:", reasons)
#         add_points(pts)
#     elif pts==0:
#         print("Nothing suspicious found in this checking sequence")

#     print("Continuing with further checks...")
    
#     # Suspicious TLDs detection
#     print("Check for suspicious TLDs...")
#     pts, reasons  = check_suspicious_tld(domain)
#     if pts > 0:
#         print("check completed, reasons:", reasons)
#         add_points(pts)
#     elif pts==0:
#         print("Nothing suspicious found in this checking sequence")

#     #Many hyphens / long multi-part SLDs
#     print("Check for many hyphens / long multi-part SLDs...")
#     pts, reasons = check_hyphenated_sld(domain)
#     if pts > 0:
#         print("check completed, reasons:", reasons)
#         add_points(pts)
#     elif pts==0:
#         print("Nothing suspicious found in this checking sequence")

#     #Check if domain is an IP literal
#     print("Check if domain is an IP literal...")
#     pts, reasons = check_ip_as_domain(domain)
#     if pts > 0:
#         print("check completed, reasons:", reasons)
#         add_points(pts)
#     elif pts==0:
#         print("Nothing suspicious found in this checking sequence")
        

    
    



    


    
    
    



