#!/usr/bin/env python3
"""
FortiBleed Defensive Exposure Checker Division81 Grupo Oruss|Ethical Hackers

Purpose:
  Safe, non-exploitative checks for Fortinet/FortiGate/FortiProxy internet exposure,
  likely Fortinet fingerprints, exposed management interfaces, optional version risk
  assessment, and operational recommendations.

Important:
  "FortiBleed" is primarily a credential-exposure/compromise campaign, not a single
  vulnerability with a universal unauthenticated proof-of-concept. This tool does not
  test stolen credentials, bypass authentication, dump configs, or exploit devices.

Usage examples:
  python fortibleed_check.py -t https://vpn.example.com
  python fortibleed_check.py -f targets.txt --json results.json --csv results.csv
  python fortibleed_check.py -f targets.txt --ports 443,8443,10443 --timeout 8

Input target formats:
  vpn.example.com
  https://vpn.example.com
  203.0.113.10:10443

Exit codes:
  0 = completed
  1 = no targets / fatal argument error
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import socket
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Iterable, Optional
from urllib.parse import urlparse

import requests
from requests import Response
from requests.exceptions import RequestException

REQUEST_HEADERS = {
    "User-Agent": "FortiBleed-Defensive-Checker/1.0 (+authorized security assessment)",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Connection": "close",
}

FORTINET_FINGERPRINTS = [
    r"fortinet",
    r"fortigate",
    r"fortiproxy",
    r"fortiweb",
    r"fortios",
    r"/remote/login",
    r"/remote/hostcheck_validate",
    r"/sslvpn/",
    r"fgt_lang",
    r"svpn_lang",
    r"FortiToken",
    r"FGT",
]

MANAGEMENT_HINTS = [
    r"name=[\"']username[\"']",
    r"name=[\"']credential[\"']",
    r"/logincheck",
    r"/ng/system/login",
    r"Please Login",
    r"FortiGate login",
]

SSLVPN_HINTS = [
    r"/remote/login",
    r"sslvpn_login",
    r"Fortinet SSL-VPN",
    r"SVPNCOOKIE",
]

# Conservative version guidance. Keep this file updated from Fortinet PSIRT.
# The script only marks versions as potentially affected when a version is visible.
FORTINET_VERSION_RULES = [
    {
        "name": "CVE-2024-55591 FortiOS/FortiProxy auth bypass",
        "products": ["FortiOS", "FortiProxy"],
        "affected_regex": r"(?:FortiOS|FortiProxy)?\s*(7\.0\.(?:0|1|2|3|4|5|6|7|8|9|10|11|12|13|14|15|16)|7\.2\.(?:0|1|2|3|4|5|6|7|8|9|10))",
        "fixed_note": "Validate Fortinet PSIRT and upgrade to a fixed release; restrict management access immediately.",
    },
    {
        "name": "CVE-2023-27997 FortiOS/FortiProxy SSL-VPN RCE",
        "products": ["FortiOS", "FortiProxy"],
        "affected_regex": r"(?:FortiOS|FortiProxy)?\s*(7\.2\.[0-4]|7\.0\.(?:0|1|2|3|4|5|6|7|8|9|10|11|12)|6\.4\.(?:0|1|2|3|4|5|6|7|8|9|10|11|12)|6\.2\.(?:0|1|2|3|4|5|6|7|8|9|10|11|12|13))",
        "fixed_note": "Validate Fortinet PSIRT and upgrade to a fixed release; disable SSL-VPN if not required.",
    },
]


@dataclass
class Finding:
    target: str
    url: str
    reachable: bool = False
    status_code: Optional[int] = None
    title: Optional[str] = None
    server: Optional[str] = None
    tls_subject: Optional[str] = None
    tls_issuer: Optional[str] = None
    tls_not_after: Optional[str] = None
    is_fortinet: bool = False
    fortinet_evidence: list[str] = field(default_factory=list)
    exposed_management: bool = False
    sslvpn_exposed: bool = False
    version_candidates: list[str] = field(default_factory=list)
    risk: str = "unknown"
    risk_reasons: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    error: Optional[str] = None


def normalize_targets(raw: str, ports: list[int]) -> list[str]:
    raw = raw.strip()
    if not raw or raw.startswith("#"):
        return []
    parsed = urlparse(raw if "://" in raw else f"https://{raw}")
    host = parsed.hostname
    if not host:
        return []
    if parsed.port:
        return [f"{parsed.scheme}://{host}:{parsed.port}"]
    if "://" in raw:
        return [f"{parsed.scheme}://{host}"]
    return [f"https://{host}:{p}" if p != 443 else f"https://{host}" for p in ports]


def read_targets(args: argparse.Namespace) -> list[str]:
    items: list[str] = []
    if args.target:
        items.extend(args.target)
    if args.file:
        with open(args.file, "r", encoding="utf-8") as fh:
            items.extend(fh.readlines())
    ports = [int(p.strip()) for p in args.ports.split(",") if p.strip()]
    urls: list[str] = []
    for item in items:
        urls.extend(normalize_targets(item, ports))
    # Preserve order, remove duplicates
    return list(dict.fromkeys(urls))


def get_tls_info(host: str, port: int, timeout: int) -> tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
        subject = ", ".join("=".join(x) for rdn in cert.get("subject", []) for x in rdn)
        issuer = ", ".join("=".join(x) for rdn in cert.get("issuer", []) for x in rdn)
        not_after = cert.get("notAfter")
        return subject or None, issuer or None, not_after, None
    except Exception as exc:  # noqa: BLE001 - TLS failure should not stop HTTP probing
        return None, None, None, str(exc)


def safe_get(url: str, timeout: int, verify_tls: bool) -> Response:
    return requests.get(
        url,
        headers=REQUEST_HEADERS,
        timeout=timeout,
        allow_redirects=True,
        verify=verify_tls,
    )


def extract_title(html: str) -> Optional[str]:
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    if not m:
        return None
    return re.sub(r"\s+", " ", m.group(1)).strip()[:120]


def extract_versions(text: str) -> list[str]:
    patterns = [
        r"Forti(?:OS|Gate|Proxy|Web)?[^\n\r<>]{0,40}?\b(?:v)?\d+\.\d+\.\d+\b",
        r"\b(?:v)?\d+\.\d+\.\d+\b",
    ]
    found: list[str] = []
    for pat in patterns:
        for m in re.findall(pat, text, flags=re.I):
            value = re.sub(r"\s+", " ", m).strip()
            if value not in found:
                found.append(value[:80])
    return found[:10]


def evidence_matches(text: str, patterns: Iterable[str]) -> list[str]:
    hits: list[str] = []
    for pat in patterns:
        if re.search(pat, text, flags=re.I):
            hits.append(pat)
    return hits


def assess_version_risk(versions: list[str]) -> list[str]:
    reasons: list[str] = []
    haystack = " | ".join(versions)
    for rule in FORTINET_VERSION_RULES:
        if re.search(rule["affected_regex"], haystack, flags=re.I):
            reasons.append(f"Potentially affected by {rule['name']}. {rule['fixed_note']}")
    return reasons


def build_recommendations(f: Finding) -> list[str]:
    recs = []
    if f.is_fortinet:
        recs.append("Rotate all local, LDAP/RADIUS-backed, and VPN credentials associated with this device; invalidate active sessions where possible.")
        recs.append("Enforce MFA for VPN and administration; review impossible-travel, failed-login, and new-admin events.")
        recs.append("Upgrade FortiOS/FortiProxy/FortiWeb according to the latest Fortinet PSIRT advisory for the exact product/version.")
    if f.exposed_management:
        recs.append("Restrict administrative interfaces to VPN/jumpbox/allowlisted IPs only; do not expose management to the public internet.")
    if f.sslvpn_exposed:
        recs.append("Confirm SSL-VPN is required; otherwise disable it. If required, harden with MFA, geo/IP controls, lockout policy, and logging.")
    if not recs and f.reachable:
        recs.append("No Fortinet fingerprint found with passive checks; confirm with authenticated inventory/EDR/CMDB data.")
    return recs


def check_url(url: str, timeout: int, verify_tls: bool) -> Finding:
    parsed = urlparse(url)
    host = parsed.hostname or url
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    f = Finding(target=host, url=url)

    if parsed.scheme == "https":
        subj, issuer, not_after, tls_error = get_tls_info(host, port, timeout)
        f.tls_subject, f.tls_issuer, f.tls_not_after = subj, issuer, not_after
        if tls_error:
            f.risk_reasons.append(f"TLS inspection warning: {tls_error}")

    try:
        resp = safe_get(url, timeout=timeout, verify_tls=verify_tls)
        f.reachable = True
        f.status_code = resp.status_code
        f.server = resp.headers.get("Server")
        body = resp.text[:250_000]
        combined = "\n".join([str(resp.url), str(resp.headers), body])
        f.title = extract_title(body)
        f.fortinet_evidence = evidence_matches(combined, FORTINET_FINGERPRINTS)
        f.is_fortinet = bool(f.fortinet_evidence)
        f.exposed_management = bool(evidence_matches(combined, MANAGEMENT_HINTS))
        f.sslvpn_exposed = bool(evidence_matches(combined, SSLVPN_HINTS))
        f.version_candidates = extract_versions(combined)

        if f.is_fortinet:
            f.risk = "high" if (f.exposed_management or f.sslvpn_exposed) else "medium"
            f.risk_reasons.append("Fortinet/FortiGate/FortiProxy fingerprint detected on an internet-reachable service.")
        else:
            f.risk = "low"

        if f.exposed_management:
            f.risk_reasons.append("Possible exposed administrative login surface detected.")
        if f.sslvpn_exposed:
            f.risk_reasons.append("Possible exposed Fortinet SSL-VPN surface detected.")

        f.risk_reasons.extend(assess_version_risk(f.version_candidates))
        if any("Potentially affected" in r for r in f.risk_reasons):
            f.risk = "critical"

    except RequestException as exc:
        f.error = str(exc)
        f.risk = "unknown"
    except Exception as exc:  # noqa: BLE001
        f.error = f"Unexpected error: {exc}"
        f.risk = "unknown"

    f.recommendations = build_recommendations(f)
    return f


def write_json(path: str, results: list[Finding]) -> None:
    data = {
        "tool": "fortibleed-defensive-checker",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "results": [asdict(r) for r in results],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)


def write_csv(path: str, results: list[Finding]) -> None:
    fields = [
        "target", "url", "reachable", "status_code", "title", "server",
        "tls_subject", "tls_issuer", "tls_not_after", "is_fortinet",
        "exposed_management", "sslvpn_exposed", "version_candidates",
        "risk", "risk_reasons", "recommendations", "error",
    ]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        for r in results:
            row = asdict(r)
            row["version_candidates"] = " | ".join(r.version_candidates)
            row["risk_reasons"] = " | ".join(r.risk_reasons)
            row["recommendations"] = " | ".join(r.recommendations)
            writer.writerow(row)


def print_table(results: list[Finding]) -> None:
    print("\nFortiBleed Defensive Check Results")
    print("=" * 78)
    for r in results:
        print(f"[{r.risk.upper():8}] {r.url}")
        print(f"  Reachable: {r.reachable}  Status: {r.status_code}  Fortinet: {r.is_fortinet}")
        if r.title:
            print(f"  Title: {r.title}")
        if r.version_candidates:
            print(f"  Versions: {', '.join(r.version_candidates)}")
        if r.risk_reasons:
            print("  Reasons:")
            for reason in r.risk_reasons:
                print(f"    - {reason}")
        if r.error:
            print(f"  Error: {r.error}")
        print()


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Safe FortiBleed/Fortinet defensive exposure checker")
    p.add_argument("-t", "--target", action="append", help="Target host/URL. Can be repeated.")
    p.add_argument("-f", "--file", help="File with one target per line.")
    p.add_argument("--ports", default="443", help="Comma-separated HTTPS ports used when no port is provided. Default: 443")
    p.add_argument("--timeout", type=int, default=8, help="Network timeout in seconds. Default: 8")
    p.add_argument("--threads", type=int, default=20, help="Concurrent workers. Default: 20")
    p.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification for HTTPS requests.")
    p.add_argument("--json", dest="json_out", help="Write JSON report to path.")
    p.add_argument("--csv", dest="csv_out", help="Write CSV report to path.")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    targets = read_targets(args)
    if not targets:
        print("No targets provided. Use -t host or -f targets.txt", file=sys.stderr)
        return 1

    if args.insecure:
        requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]

    started = time.time()
    results: list[Finding] = []
    with ThreadPoolExecutor(max_workers=max(1, args.threads)) as pool:
        future_map = {pool.submit(check_url, url, args.timeout, not args.insecure): url for url in targets}
        for future in as_completed(future_map):
            results.append(future.result())

    results.sort(key=lambda x: (x.risk not in {"critical", "high"}, x.url))
    print_table(results)
    print(f"Completed {len(results)} checks in {time.time() - started:.1f}s")

    if args.json_out:
        write_json(args.json_out, results)
        print(f"JSON report written to {args.json_out}")
    if args.csv_out:
        write_csv(args.csv_out, results)
        print(f"CSV report written to {args.csv_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
