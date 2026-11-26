# http-security-headers-checker

Grade any website's HTTP security headers in one command — and learn what
each header does while you are at it.

```bash
python3 headers_checker.py https://example.com
```

```
URL:    https://example.com
Status: 200
Score:  10/100   Grade: F
------------------------------------------------------------------------
[MISS] Strict-Transport-Security        0/15  missing — browsers are not told to always use HTTPS
...
```

No installs, no API keys, no dependencies: Python 3 standard library only.
The tool makes a single normal GET request — the same response headers your
browser receives on any visit — and scores what it finds.

## What it checks (100 points)

| Check | Points | Why it matters |
| --- | --- | --- |
| Strict-Transport-Security (HSTS) | 15 | Forces HTTPS so connections cannot be downgraded |
| Content-Security-Policy | 20 | Limits where scripts and content may load from; the main XSS seatbelt |
| X-Content-Type-Options | 10 | `nosniff` stops browsers guessing a file into a script |
| Frame protection | 15 | CSP `frame-ancestors` or X-Frame-Options — clickjacking defence |
| Referrer-Policy | 10 | Stops full URLs leaking to third parties |
| Permissions-Policy | 10 | Restricts camera, microphone, geolocation and other powerful features |
| Cross-Origin-Opener-Policy | 10 | Isolates your window from cross-origin popups |
| Set-Cookie flags | 10 | Secure, HttpOnly and SameSite on every cookie |

Grades: **A** ≥ 90, **B** ≥ 75, **C** ≥ 60, **D** ≥ 40, **F** < 40.
Partial credit is deliberate: a short HSTS max-age or a CSP that still
allows `'unsafe-inline'` scores less than a strict one, and the report
tells you why.

## Usage

```bash
# Domain or full URL (https:// is added if you leave it off)
python3 headers_checker.py github.com

# Machine-readable output for scripts
python3 headers_checker.py https://github.com --json
```

Exit code is `0` for any completed check (even an F — a bad grade is a
finding, not a crash) and `2` when the site could not be fetched at all.

A real run against github.com is saved in
[example-output.txt](examples/example-output.txt).

## Fixing your own site

Every `MISS` line names the header to add. Sensible starting values for
most sites:

```
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
Cross-Origin-Opener-Policy: same-origin
```

CSP and frame protection depend on how your site is built — start with
`Content-Security-Policy-Report-Only` and tighten from the reports.

## What this is not

A passive header check. It does **not** scan for vulnerabilities, test
logins, or probe the site in any way, and a good grade does not mean a
site is "secure" — it means one visible, worthwhile layer is in place.

## Authorised use only

Checking response headers is what every browser does on every visit, and
this tool only does that. Use it on sites you own, are authorised to
assess, or as a read-only learning exercise on public sites — one request,
no load testing, no evasion, no funny business.

## License

MIT — see [LICENSE](LICENSE).
