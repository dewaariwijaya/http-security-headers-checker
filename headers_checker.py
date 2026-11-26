#!/usr/bin/env python3
"""http-security-headers-checker

Fetch a website's HTTP response headers and grade its security headers:
HSTS, CSP, X-Content-Type-Options, frame protection, Referrer-Policy,
Permissions-Policy, COOP, plus Set-Cookie flags and Server disclosure.

Standard library only. One GET request, nothing else — a passive check,
exactly what your browser already receives on any visit.

Usage:
    python3 headers_checker.py https://example.com
    python3 headers_checker.py example.com --json
"""

import argparse
import json
import re
import ssl
import sys
import urllib.request
import urllib.error

USER_AGENT = "headers-checker/1.0 (+https://github.com/dewaariwijaya/http-security-headers-checker)"
TIMEOUT = 15

# Each check: (header-or-key, max points). Total = 100.
def check_hsts(headers):
    v = headers.get("Strict-Transport-Security")
    if not v:
        return 0, 15, "missing — browsers are not told to always use HTTPS"
    m = re.search(r"max-age\s*=\s*(\d+)", v, re.I)
    age = int(m.group(1)) if m else 0
    if age >= 31_536_000 and "includesubdomains" in v.lower():
        return 15, 15, f"strong (max-age={age}, includeSubDomains)"
    if age >= 31_536_000:
        return 12, 15, f"good max-age={age}; add includeSubDomains"
    if age > 0:
        return 6, 15, f"max-age too short ({age}s; aim for >= 31536000)"
    return 2, 15, "present but no valid max-age"


def check_csp(headers):
    v = headers.get("Content-Security-Policy")
    if not v:
        return 0, 20, "missing — no policy limiting where scripts/content may load from"
    notes = []
    score = 14
    if "unsafe-inline" in v:
        score -= 5
        notes.append("allows 'unsafe-inline'")
    if "unsafe-eval" in v:
        score -= 3
        notes.append("allows 'unsafe-eval'")
    if re.search(r"default-src[^;]*\*", v) or re.search(r"script-src[^;]*\*(\s|;|$)", v):
        score -= 5
        notes.append("wildcard source")
    if "object-src 'none'" in v or "object-src" in v:
        score += 3
    if "base-uri" in v:
        score += 3
    score = max(1, min(20, score))
    return score, 20, ("present; " + ", ".join(notes)) if notes else "present, no obvious weaknesses"


def check_xcto(headers):
    v = (headers.get("X-Content-Type-Options") or "").lower()
    if "nosniff" in v:
        return 10, 10, "nosniff set"
    return 0, 10, "missing — browsers may MIME-sniff responses into scripts"


def check_frame(headers):
    csp = headers.get("Content-Security-Policy") or ""
    if "frame-ancestors" in csp:
        return 15, 15, "CSP frame-ancestors present (modern clickjacking protection)"
    v = (headers.get("X-Frame-Options") or "").upper()
    if "DENY" in v or "SAMEORIGIN" in v:
        return 12, 15, f"X-Frame-Options: {v} (works; frame-ancestors is the modern form)"
    return 0, 15, "missing — page can be framed by other sites (clickjacking risk)"


def check_referrer(headers):
    v = (headers.get("Referrer-Policy") or "").lower()
    good = ("no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin")
    if any(g in v for g in good):
        return 10, 10, f"set ({v})"
    if v:
        return 5, 10, f"set but permissive ({v})"
    return 0, 10, "missing — full URLs may leak to third parties via Referer"


def check_permissions(headers):
    if headers.get("Permissions-Policy") or headers.get("Feature-Policy"):
        return 10, 10, "set — browser features (camera, mic, geolocation...) are restricted"
    return 0, 10, "missing — powerful browser features are not explicitly restricted"


def check_coop(headers):
    if headers.get("Cross-Origin-Opener-Policy"):
        return 10, 10, "set — cross-origin window references are isolated"
    return 0, 10, "missing — consider Cross-Origin-Opener-Policy: same-origin"


def check_cookies(headers):
    raw = headers.get_all("Set-Cookie") if hasattr(headers, "get_all") else None
    if not raw:
        single = headers.get("Set-Cookie")
        raw = [single] if single else []
    if not raw:
        return 10, 10, "no cookies set by this response — nothing to flag"
    worst = 10
    notes = []
    for c in raw:
        lc = c.lower()
        score = 10
        if "secure" not in lc:
            score -= 4
            notes.append("a cookie lacks Secure")
        if "httponly" not in lc:
            score -= 3
            notes.append("a cookie lacks HttpOnly")
        if "samesite" not in lc:
            score -= 3
            notes.append("a cookie lacks SameSite")
        worst = min(worst, score)
    return worst, 10, "; ".join(sorted(set(notes))) if notes else "all cookies carry Secure, HttpOnly and SameSite"


CHECKS = [
    ("Strict-Transport-Security", check_hsts),
    ("Content-Security-Policy", check_csp),
    ("X-Content-Type-Options", check_xcto),
    ("Frame protection", check_frame),
    ("Referrer-Policy", check_referrer),
    ("Permissions-Policy", check_permissions),
    ("Cross-Origin-Opener-Policy", check_coop),
    ("Set-Cookie flags", check_cookies),
]


def grade(score):
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def fetch(url):
    if "://" not in url:
        url = "https://" + url
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as resp:
        # Read a small slice only; we need headers, not the page.
        resp.read(1024)
        return resp.status, resp.geturl(), resp.headers


def main(argv=None):
    ap = argparse.ArgumentParser(description="Grade a website's HTTP security headers.")
    ap.add_argument("url", help="URL or domain, e.g. https://example.com")
    ap.add_argument("--json", action="store_true", help="print a JSON report instead of text")
    args = ap.parse_args(argv)

    try:
        status, final_url, headers = fetch(args.url)
    except urllib.error.HTTPError as e:
        status, final_url, headers = e.code, e.geturl(), e.headers
    except Exception as e:  # DNS, TLS, timeout, refused...
        print(f"Error: could not fetch {args.url}: {e}", file=sys.stderr)
        return 2

    results = []
    total = 0
    for name, fn in CHECKS:
        score, maxpts, note = fn(headers)
        total += score
        results.append({"check": name, "score": score, "max": maxpts,
                        "value": headers.get(name) if name in headers else None,
                        "note": note})
    g = grade(total)
    server = headers.get("Server")

    if args.json:
        print(json.dumps({"url": final_url, "status": status, "score": total,
                          "grade": g, "server_header": server,
                          "checks": results}, indent=2))
        return 0

    print(f"URL:    {final_url}")
    print(f"Status: {status}")
    print(f"Score:  {total}/100   Grade: {g}")
    if server:
        print(f"Note:   Server header discloses '{server}' (info leak, minor)")
    print("-" * 72)
    for r in results:
        mark = "PASS" if r["score"] == r["max"] else ("WEAK" if r["score"] > 0 else "MISS")
        print(f"[{mark:4}] {r['check']:32} {r['score']:>2}/{r['max']:<2}  {r['note']}")
    print("-" * 72)
    print("Grades: A >= 90, B >= 75, C >= 60, D >= 40, F < 40. "
          "A passive header check — it says nothing about the site's code, "
          "accounts or vulnerabilities.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
