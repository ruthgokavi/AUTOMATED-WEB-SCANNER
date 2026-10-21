#!/usr/bin/env python3
"""
Web Security Scanner
Audits websites for missing/misconfigured security headers and CORS flaws.
"""

import sys
import json
import argparse
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional

import requests
from requests.exceptions import RequestException
from colorama import Fore, Style, init as colorama_init

colorama_init(autoreset=True)

# ---------------------------------------------------------------------------
# Security header definitions
# ---------------------------------------------------------------------------

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "description": "Enforces HTTPS connections (HSTS).",
        "severity": "HIGH",
        "recommendation": (
            'Set to "max-age=31536000; includeSubDomains; preload". '
            "Minimum max-age should be 6 months (15768000)."
        ),
    },
    "Content-Security-Policy": {
        "description": "Restricts resource origins to prevent XSS and data injection.",
        "severity": "HIGH",
        "recommendation": (
            "Define a strict policy. At minimum avoid 'unsafe-inline' and 'unsafe-eval'. "
            "Example: \"default-src 'self'\"."
        ),
    },
    "X-Frame-Options": {
        "description": "Prevents clickjacking by controlling iframe embedding.",
        "severity": "MEDIUM",
        "recommendation": 'Set to "DENY" or "SAMEORIGIN".',
    },
    "X-Content-Type-Options": {
        "description": "Stops MIME-type sniffing.",
        "severity": "MEDIUM",
        "recommendation": 'Set to "nosniff".',
    },
    "Referrer-Policy": {
        "description": "Controls how much referrer information is sent.",
        "severity": "LOW",
        "recommendation": (
            'Set to "no-referrer", "strict-origin", or "strict-origin-when-cross-origin".'
        ),
    },
    "Permissions-Policy": {
        "description": "Controls access to browser features (camera, mic, etc.).",
        "severity": "LOW",
        "recommendation": 'Disable unused features, e.g. "camera=(), microphone=(), geolocation=()".',
    },
    "X-XSS-Protection": {
        "description": "Legacy XSS filter for older browsers.",
        "severity": "LOW",
        "recommendation": 'Set to "1; mode=block" (or omit entirely and rely on CSP).',
    },
    "Cache-Control": {
        "description": "Controls caching behaviour for sensitive responses.",
        "severity": "LOW",
        "recommendation": 'For authenticated/sensitive pages use "no-store, no-cache, must-revalidate".',
    },
}

# Dangerous CSP values
DANGEROUS_CSP_VALUES = ["'unsafe-inline'", "'unsafe-eval'", "data:", "*"]

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class HeaderFinding:
    header: str
    status: str          # MISSING | PRESENT | WEAK
    severity: str
    value: Optional[str] = None
    detail: str = ""
    recommendation: str = ""


@dataclass
class CORSFinding:
    test: str
    status: str          # PASS | FAIL | INFO
    severity: str
    detail: str = ""
    recommendation: str = ""


@dataclass
class ScanResult:
    url: str
    final_url: str
    status_code: int
    https_used: bool
    header_findings: list = field(default_factory=list)
    cors_findings: list = field(default_factory=list)
    score: int = 0
    max_score: int = 0

# ---------------------------------------------------------------------------
# Scanner logic
# ---------------------------------------------------------------------------

class WebSecurityScanner:
    def __init__(self, timeout: int = 10, user_agent: str = None):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers["User-Agent"] = (
            user_agent or "WebSecurityScanner/1.0 (security-audit)"
        )

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------

    def _get(self, url: str, **kwargs) -> requests.Response:
        return self.session.get(url, timeout=self.timeout, allow_redirects=True, **kwargs)

    def _options(self, url: str, headers: dict) -> Optional[requests.Response]:
        try:
            return self.session.options(
                url, headers=headers, timeout=self.timeout, allow_redirects=True
            )
        except RequestException:
            return None

    # ------------------------------------------------------------------
    # Security header checks
    # ------------------------------------------------------------------

    def _check_headers(self, response_headers: dict) -> list[HeaderFinding]:
        findings = []
        # Normalise header names for case-insensitive lookup
        lowered = {k.lower(): v for k, v in response_headers.items()}

        for header, meta in SECURITY_HEADERS.items():
            value = lowered.get(header.lower())

            if value is None:
                findings.append(HeaderFinding(
                    header=header,
                    status="MISSING",
                    severity=meta["severity"],
                    detail=meta["description"],
                    recommendation=meta["recommendation"],
                ))
                continue

            # Header is present — do additional value checks
            status = "PRESENT"
            detail = meta["description"]
            recommendation = ""

            if header == "Strict-Transport-Security":
                if "max-age" not in value.lower():
                    status = "WEAK"
                    detail = "HSTS header present but missing max-age directive."
                    recommendation = meta["recommendation"]
                else:
                    try:
                        age_part = [p for p in value.split(";") if "max-age" in p.lower()][0]
                        age = int(age_part.split("=")[1].strip())
                        if age < 15_768_000:
                            status = "WEAK"
                            detail = f"HSTS max-age ({age}s) is below recommended 6 months."
                            recommendation = meta["recommendation"]
                    except (IndexError, ValueError):
                        pass

            elif header == "Content-Security-Policy":
                dangerous = [d for d in DANGEROUS_CSP_VALUES if d in value]
                if dangerous:
                    status = "WEAK"
                    detail = f"CSP contains dangerous values: {', '.join(dangerous)}"
                    recommendation = meta["recommendation"]

            elif header == "X-Frame-Options":
                if value.strip().upper() not in ("DENY", "SAMEORIGIN"):
                    status = "WEAK"
                    detail = f"X-Frame-Options value '{value}' is not DENY or SAMEORIGIN."
                    recommendation = meta["recommendation"]

            elif header == "X-Content-Type-Options":
                if value.strip().lower() != "nosniff":
                    status = "WEAK"
                    detail = f"X-Content-Type-Options value '{value}' should be 'nosniff'."
                    recommendation = meta["recommendation"]

            findings.append(HeaderFinding(
                header=header,
                status=status,
                severity=meta["severity"],
                value=value,
                detail=detail,
                recommendation=recommendation,
            ))

        return findings

    # ------------------------------------------------------------------
    # CORS checks
    # ------------------------------------------------------------------

    def _check_cors(self, url: str, response_headers: dict) -> list[CORSFinding]:
        findings = []
        lowered = {k.lower(): v for k, v in response_headers.items()}
        acao = lowered.get("access-control-allow-origin", "")
        acac = lowered.get("access-control-allow-credentials", "").strip().lower()
        acam = lowered.get("access-control-allow-methods", "")
        acah = lowered.get("access-control-allow-headers", "")

        # --- Test 1: Wildcard origin ---
        if acao == "*":
            sev = "MEDIUM"
            detail = "Access-Control-Allow-Origin is set to wildcard '*'."
            rec = (
                "Restrict ACAO to specific trusted origins unless the resource "
                "is intentionally public."
            )
            if acac == "true":
                sev = "HIGH"
                detail += " Combined with Allow-Credentials: true — cookies/auth can be leaked."
                rec = "Never combine ACAO: * with Allow-Credentials: true. This is an invalid combination per the spec but some servers misconfigure it anyway."
            findings.append(CORSFinding("Wildcard Origin", "FAIL", sev, detail, rec))
        else:
            findings.append(CORSFinding(
                "Wildcard Origin", "PASS", "INFO",
                "ACAO is not set to wildcard." if acao else "ACAO header not present.",
            ))

        # --- Test 2: Origin reflection ---
        crafted_origin = "https://evil.attacker.com"
        resp = self._options(url, headers={"Origin": crafted_origin})
        if resp is not None:
            reflected = resp.headers.get("Access-Control-Allow-Origin", "")
            if reflected == crafted_origin:
                findings.append(CORSFinding(
                    "Origin Reflection", "FAIL", "HIGH",
                    "Server reflects arbitrary Origin header back in ACAO.",
                    "Validate the Origin against a whitelist; do not echo it back blindly.",
                ))
            else:
                findings.append(CORSFinding(
                    "Origin Reflection", "PASS", "INFO",
                    "Server does not reflect arbitrary origins.",
                ))
        else:
            findings.append(CORSFinding(
                "Origin Reflection", "INFO", "INFO",
                "OPTIONS request failed or was blocked; could not test origin reflection.",
            ))

        # --- Test 3: Null origin ---
        resp_null = self._options(url, headers={"Origin": "null"})
        if resp_null is not None:
            null_acao = resp_null.headers.get("Access-Control-Allow-Origin", "")
            if null_acao == "null":
                findings.append(CORSFinding(
                    "Null Origin", "FAIL", "HIGH",
                    "Server allows 'null' as an Origin — can be triggered from sandboxed iframes.",
                    "Reject 'null' origin; include only explicit trusted origins in the whitelist.",
                ))
            else:
                findings.append(CORSFinding(
                    "Null Origin", "PASS", "INFO",
                    "Server does not allow 'null' origin.",
                ))

        # --- Test 4: Credentials with specific origin ---
        if acac == "true" and acao not in ("", "*"):
            findings.append(CORSFinding(
                "Credentials Exposure", "FAIL", "HIGH",
                f"Allow-Credentials: true with ACAO set to '{acao}'. "
                "Authenticated cross-origin requests are allowed.",
                "Ensure the reflected origin is strictly validated against a whitelist.",
            ))
        else:
            findings.append(CORSFinding(
                "Credentials Exposure", "PASS", "INFO",
                "Allow-Credentials is not enabled or ACAO is not a specific origin.",
            ))

        # --- Test 5: Dangerous methods exposed ---
        if acam:
            dangerous_methods = [m.strip().upper() for m in acam.split(",")
                                 if m.strip().upper() in ("PUT", "DELETE", "PATCH", "TRACE", "CONNECT")]
            if dangerous_methods:
                findings.append(CORSFinding(
                    "Dangerous Methods", "FAIL", "MEDIUM",
                    f"Allow-Methods includes dangerous HTTP verbs: {', '.join(dangerous_methods)}.",
                    "Remove PUT/DELETE/PATCH/TRACE/CONNECT from CORS Allow-Methods unless required.",
                ))
            else:
                findings.append(CORSFinding(
                    "Dangerous Methods", "PASS", "INFO",
                    f"Allowed methods ({acam}) do not include dangerous verbs.",
                ))

        # --- Test 6: Sensitive headers exposed ---
        if acah:
            sensitive = [h.strip().lower() for h in acah.split(",")
                         if h.strip().lower() in ("authorization", "cookie", "x-api-key")]
            if sensitive:
                findings.append(CORSFinding(
                    "Sensitive Headers Exposed", "FAIL", "MEDIUM",
                    f"Access-Control-Allow-Headers exposes sensitive headers: {', '.join(sensitive)}.",
                    "Only expose headers that are strictly necessary for cross-origin requests.",
                ))

        return findings

    # ------------------------------------------------------------------
    # Main scan entry point
    # ------------------------------------------------------------------

    def scan(self, url: str) -> ScanResult:
        # Ensure scheme is present
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        try:
            response = self._get(url)
        except RequestException as exc:
            print(f"{Fore.RED}[ERROR] Could not reach {url}: {exc}{Style.RESET_ALL}")
            sys.exit(1)

        final_url = response.url
        https_used = final_url.startswith("https://")
        header_findings = self._check_headers(dict(response.headers))
        cors_findings = self._check_cors(final_url, dict(response.headers))

        result = ScanResult(
            url=url,
            final_url=final_url,
            status_code=response.status_code,
            https_used=https_used,
            header_findings=header_findings,
            cors_findings=cors_findings,
        )
        result.score, result.max_score = self._calculate_score(result)
        return result

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------

    def _calculate_score(self, result: ScanResult):
        weights = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
        total = 0
        earned = 0

        for f in result.header_findings:
            w = weights.get(f.severity, 1)
            total += w
            if f.status == "PRESENT":
                earned += w
            elif f.status == "WEAK":
                earned += w // 2

        # CORS bonus / penalty
        cors_fails = sum(1 for c in result.cors_findings if c.status == "FAIL")
        cors_high_fails = sum(1 for c in result.cors_findings
                              if c.status == "FAIL" and c.severity == "HIGH")
        total += 4
        cors_score = max(0, 4 - cors_fails - cors_high_fails)
        earned += cors_score

        # HTTPS bonus
        total += 3
        if result.https_used:
            earned += 3

        return earned, total

# ---------------------------------------------------------------------------
# Output / reporting
# ---------------------------------------------------------------------------

SEVERITY_COLOR = {
    "HIGH": Fore.RED,
    "MEDIUM": Fore.YELLOW,
    "LOW": Fore.CYAN,
    "INFO": Fore.WHITE,
}

STATUS_SYMBOL = {
    "MISSING": "✗",
    "WEAK":    "~",
    "PRESENT": "✓",
    "FAIL":    "✗",
    "PASS":    "✓",
    "INFO":    "i",
}


def _sev(severity: str) -> str:
    return f"{SEVERITY_COLOR.get(severity, '')}{severity}{Style.RESET_ALL}"


def print_result(result: ScanResult) -> None:
    sep = "─" * 72
    print(f"\n{Fore.CYAN}{sep}")
    print(f"  Web Security Scan Report")
    print(f"  Target  : {result.url}")
    print(f"  Final   : {result.final_url}")
    print(f"  Status  : {result.status_code}  |  HTTPS: {'YES' if result.https_used else 'NO'}")
    pct = int(result.score / result.max_score * 100) if result.max_score else 0
    grade_color = Fore.GREEN if pct >= 70 else (Fore.YELLOW if pct >= 40 else Fore.RED)
    print(f"  Score   : {grade_color}{result.score}/{result.max_score}  ({pct}%){Style.RESET_ALL}")
    print(f"{Fore.CYAN}{sep}{Style.RESET_ALL}\n")

    # -- Security Headers --
    print(f"{Fore.WHITE}{'SECURITY HEADERS':─<72}{Style.RESET_ALL}")
    for f in result.header_findings:
        sym = STATUS_SYMBOL.get(f.status, "?")
        color = Fore.GREEN if f.status == "PRESENT" else SEVERITY_COLOR.get(f.severity, "")
        print(f"  {color}{sym}  {f.header:<40}  [{f.status}] [{_sev(f.severity)}]{Style.RESET_ALL}")
        if f.status != "PRESENT":
            print(f"     {Fore.WHITE}Detail : {f.detail}{Style.RESET_ALL}")
            print(f"     {Fore.YELLOW}Fix    : {f.recommendation}{Style.RESET_ALL}")

    # -- CORS --
    print(f"\n{Fore.WHITE}{'CORS CHECKS':─<72}{Style.RESET_ALL}")
    for c in result.cors_findings:
        sym = STATUS_SYMBOL.get(c.status, "?")
        color = Fore.GREEN if c.status == "PASS" else (Fore.RED if c.status == "FAIL" else Fore.WHITE)
        print(f"  {color}{sym}  {c.test:<40}  [{c.status}] [{_sev(c.severity)}]{Style.RESET_ALL}")
        if c.status == "FAIL":
            print(f"     {Fore.WHITE}Detail : {c.detail}{Style.RESET_ALL}")
            print(f"     {Fore.YELLOW}Fix    : {c.recommendation}{Style.RESET_ALL}")

    print(f"\n{Fore.CYAN}{sep}{Style.RESET_ALL}\n")


def export_json(result: ScanResult, path: str) -> None:
    data = {
        "url": result.url,
        "final_url": result.final_url,
        "status_code": result.status_code,
        "https_used": result.https_used,
        "score": result.score,
        "max_score": result.max_score,
        "score_pct": int(result.score / result.max_score * 100) if result.max_score else 0,
        "header_findings": [f.__dict__ for f in result.header_findings],
        "cors_findings": [c.__dict__ for c in result.cors_findings],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    print(f"{Fore.GREEN}[+] JSON report saved to: {path}{Style.RESET_ALL}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scanner",
        description="Web Security Scanner — audits secure headers and CORS configuration.",
    )
    parser.add_argument("urls", nargs="+", metavar="URL", help="Target URL(s) to scan.")
    parser.add_argument(
        "--timeout", type=int, default=10, metavar="SEC",
        help="Request timeout in seconds (default: 10).",
    )
    parser.add_argument(
        "--json", dest="json_output", metavar="FILE",
        help="Export results to a JSON file.",
    )
    parser.add_argument(
        "--user-agent", metavar="UA",
        help="Custom User-Agent string.",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    scanner = WebSecurityScanner(timeout=args.timeout, user_agent=args.user_agent)
    all_results = []

    for url in args.urls:
        print(f"{Fore.CYAN}[*] Scanning: {url}{Style.RESET_ALL}")
        result = scanner.scan(url)
        print_result(result)
        all_results.append(result)

    if args.json_output:
        if len(all_results) == 1:
            export_json(all_results[0], args.json_output)
        else:
            base, ext = args.json_output.rsplit(".", 1) if "." in args.json_output else (args.json_output, "json")
            for i, r in enumerate(all_results):
                export_json(r, f"{base}_{i+1}.{ext}")


if __name__ == "__main__":
    main()
