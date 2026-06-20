import math
import numpy as np
from collections import Counter

# Keywords targeted for SQL Injection, XSS, Path Traversal, and Command Injection
INJECT_KW = ["select", "union", "drop", "insert", "script", "eval", "exec", "system", "../", "cmd=", "base64_decode"]

def entropy(s: str) -> float:
    """Calculates Shannon entropy of a string in O(N) time complexity using collections.Counter."""
    if not s:
        return 0.0
    counts = Counter(s)
    total = len(s)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())

def pct_upper(s: str) -> float:
    """Returns the percentage of uppercase characters in a string."""
    if not s:
        return 0.0
    return sum(1 for c in s if c.isupper()) / len(s)

def pct_digit(s: str) -> float:
    """Returns the percentage of digit characters in a string."""
    if not s:
        return 0.0
    return sum(1 for c in s if c.isdigit()) / len(s)

def pct_special(s: str) -> float:
    """Returns the percentage of non-alphanumeric characters in a string."""
    if not s:
        return 0.0
    return sum(1 for c in s if not c.isalnum()) / len(s)

def has_injection_kw(s: str) -> float:
    """Returns 1.0 if any signature keyword is found in the lowercased string, else 0.0."""
    if not s:
        return 0.0
    s_lower = s.lower()
    return float(any(k in s_lower for k in INJECT_KW))

def ua_is_scanner(ua: str) -> float:
    """Returns 1.0 if the User-Agent matches common scanning tool patterns, else 0.0."""
    if not ua:
        return 0.0
    ua_lower = ua.lower()
    return float(any(b in ua_lower for b in ["curl", "python", "nikto", "sqlmap", "nmap"]))

def build_features(data: dict) -> np.ndarray:
    """
    Transforms incoming request metadata into a numerical vector of shape (1, 30).
    Ensures safe type casting and defaults to prevent crashes on missing or corrupted inputs.
    """
    # Safe numerical conversions
    crs_score = float(data.get('crs_score') or 0.0)
    body_len = float(data.get('body_len') or 0.0)
    redis_rpm = float(data.get('redis_rpm') or 0.0)
    redis_rep = float(data.get('redis_rep') or 0.0)
    
    # Safe string conversions
    matched_vars = str(data.get('matched_vars') or '')
    uri = str(data.get('uri') or '')
    args = str(data.get('args') or '')
    method = str(data.get('method') or '').upper()
    ct = str(data.get('ct') or '')
    ua = str(data.get('ua') or '')

    # Compute matched variables count safely
    matched_vars_count = len([v for v in matched_vars.split(",") if v])

    # Construct the 30-feature vector
    features = [
        crs_score,                                              # 1
        crs_score / 10.0,                                       # 2
        float(matched_vars_count),                              # 3
        float(len(uri)),                                        # 4
        float(uri.count("/")),                                  # 5
        float(uri.count("?")),                                  # 6
        float(uri.count("=")),                                  # 7
        float(uri.count("%")),                                  # 8
        float(uri.count("..")),                                 # 9
        float(len(args)),                                       # 10
        entropy(args),                                          # 11
        pct_upper(args),                                        # 12
        pct_digit(args),                                        # 13
        pct_special(args),                                      # 14
        has_injection_kw(args),                                 # 15
        float(args.count("'") + args.count('"')),               # 16
        float(args.count("<") + args.count(">")),               # 17
        float(args.count("--")),                                # 18
        1.0 if method == "POST" else 0.0,                       # 19
        1.0 if method == "PUT" else 0.0,                        # 20
        1.0 if method == "DELETE" else 0.0,                     # 21
        body_len,                                               # 22
        1.0 if "json" in ct.lower() else 0.0,                   # 23
        1.0 if "multipart" in ct.lower() else 0.0,              # 24
        float(len(ua)),                                         # 25
        1.0 if ua == "" else 0.0,                               # 26
        ua_is_scanner(ua),                                      # 27
        redis_rpm,                                              # 28
        redis_rep,                                              # 29
        entropy(uri)                                            # 30
    ]
    
    # Assert vector shape matches exactly (1, 30) for input model shapes
    assert len(features) == 30, f"Vector length check failed. Expected 30 features, generated {len(features)}"
    return np.array([features])
