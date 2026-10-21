# Web Security Scanner

A command-line Python tool that audits web applications for **missing or misconfigured HTTP security headers** and **CORS (Cross-Origin Resource Sharing) vulnerabilities**.

---

## Features

| Category | Checks performed |
|---|---|
| **Security Headers** | Strict-Transport-Security, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, X-XSS-Protection, Cache-Control |
| **CORS Flaws** | Wildcard origin, arbitrary origin reflection, null-origin acceptance, credentials exposure, dangerous HTTP methods, sensitive header exposure |
| **Scoring** | Weighted risk score (0–100 %) factoring in severity (HIGH / MEDIUM / LOW) |
| **Output** | Colour-coded terminal report + optional JSON export |

---

## Requirements

- Python 3.10 or later
- `requests` ≥ 2.31.0
- `colorama` ≥ 0.4.6

---

## Installation

```bash
# 1. Clone / copy the project
cd web-security-scanner

# 2. (Recommended) create a virtual environment
python -m venv .venv
source .venv/bin/activate        # Linux / macOS
.venv\Scripts\activate           # Windows PowerShell

# 3. Install dependencies
pip install -r requirements.txt
```

---

## Usage

```
python scanner.py [OPTIONS] URL [URL ...]
```

### Positional arguments

| Argument | Description |
|---|---|
| `URL` | One or more target URLs to scan (e.g. `https://example.com`) |

### Optional arguments

| Flag | Default | Description |
|---|---|---|
| `--timeout SEC` | `10` | HTTP request timeout in seconds |
| `--json FILE` | — | Export results to a JSON file |
| `--user-agent UA` | built-in | Override the User-Agent header |

### Examples

```bash
# Scan a single site
python scanner.py https://example.com

# Scan multiple targets
python scanner.py https://example.com https://another.com

# Save results as JSON
python scanner.py https://example.com --json report.json

# Custom timeout
python scanner.py https://slow-site.com --timeout 20
```

---

## Sample Output

```
────────────────────────────────────────────────────────────────────────
  Web Security Scan Report
  Target  : https://example.com
  Final   : https://example.com/
  Status  : 200  |  HTTPS: YES
  Score   : 11/23  (47%)
────────────────────────────────────────────────────────────────────────

SECURITY HEADERS────────────────────────────────────────────────────────
  ✓  Strict-Transport-Security             [PRESENT] [HIGH]
  ✗  Content-Security-Policy              [MISSING] [HIGH]
     Detail : Restricts resource origins to prevent XSS and data injection.
     Fix    : Define a strict policy ...
  ...

CORS CHECKS─────────────────────────────────────────────────────────────
  ✓  Wildcard Origin                       [PASS] [INFO]
  ✗  Origin Reflection                     [FAIL] [HIGH]
     Detail : Server reflects arbitrary Origin header back in ACAO.
     Fix    : Validate the Origin against a whitelist ...
```

---

## JSON Report Structure

```json
{
  "url": "https://example.com",
  "final_url": "https://example.com/",
  "status_code": 200,
  "https_used": true,
  "score": 11,
  "max_score": 23,
  "score_pct": 47,
  "header_findings": [
    {
      "header": "Strict-Transport-Security",
      "status": "PRESENT",
      "severity": "HIGH",
      "value": "max-age=31536000",
      "detail": "...",
      "recommendation": ""
    }
  ],
  "cors_findings": [
    {
      "test": "Origin Reflection",
      "status": "FAIL",
      "severity": "HIGH",
      "detail": "...",
      "recommendation": "..."
    }
  ]
}
```

---

## Severity Levels

| Level | Meaning |
|---|---|
| **HIGH** | Directly exploitable; fix immediately |
| **MEDIUM** | Exploitable with additional preconditions |
| **LOW** | Best-practice gap; low direct impact |
| **INFO** | Informational result; no action required |

---

## Disclaimer

This tool is intended for **authorised security testing only**.  
Running it against systems you do not own or have explicit written permission to test may violate computer-fraud laws in your jurisdiction.  
The authors accept no liability for misuse.

---

## License

MIT
