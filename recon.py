#!/usr/bin/env python3
"""
Fata Recon & AppSec Audit Suite (v2.0)
Author : Fata Fatikhul Karim (@UserFxxk | HackerOne: @zeonmaltius)
License: MIT
Purpose: Non-destructive Web Security Reconnaissance, Passive Subdomain
         Discovery (crt.sh), CORS/Cookie Misconfiguration Audit, and
         Security Header Analyzer for Bug Bounty & Pre-Release Audits.
"""

import argparse
import concurrent.futures
import json
import os
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime

# ANSI Colors (No external dependency required)
class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    PURPLE = "\033[95m"
    CYAN = "\033[96m"
    GRAY = "\033[90m"


BANNER = f"""{C.PURPLE}{C.BOLD}
  ╔══════════════════════════════════════════════════════════════╗
  ║   🛡️  FATA RECON & APPSEC AUDIT SUITE v2.0                   ║
  ║   Build it right, break it better • userfxxk.github.io       ║
  ╚══════════════════════════════════════════════════════════════╝{C.RESET}
"""

SECURITY_HEADERS = {
    "content-security-policy": ("HIGH", "Mitigates XSS and data injection attacks (CSP)"),
    "strict-transport-security": ("MEDIUM", "Enforces HTTPS connections (HSTS)"),
    "x-frame-options": ("MEDIUM", "Prevents Clickjacking attacks (XFO)"),
    "x-content-type-options": ("LOW", "Prevents MIME-sniffing (nosniff)"),
    "referrer-policy": ("LOW", "Controls referrer information leakage"),
    "permissions-policy": ("LOW", "Restricts browser features and APIs"),
}

FINGERPRINT_HEADERS = ["x-powered-by", "server", "x-aspnet-version", "x-generator"]

COMMON_PATHS = [
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/api",
    "/api/health",
    "/api/v1/health",
    "/api/history",
    "/api/docs",
    "/swagger.json",
    "/openapi.json",
    "/graphql",
]


def normalize_url(target: str) -> str:
    target = target.strip()
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    return target.rstrip("/")


def extract_domain(url: str) -> str:
    parsed = urllib.parse.urlparse(normalize_url(url))
    return parsed.hostname or url


def fetch_url(url: str, custom_headers: dict = None, timeout: int = 8):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    headers = {
        "User-Agent": "FataReconSuite/2.0 (Security-Audit; +https://userfxxk.github.io)"
    }
    if custom_headers:
        headers.update(custom_headers)

    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(65536)
            return {
                "ok": True,
                "status": resp.status,
                "headers": {k.lower(): v for k, v in resp.getheaders()},
                "raw_headers": resp.getheaders(),
                "length": len(body),
                "body_preview": body.decode("utf-8", errors="ignore")[:300],
            }
    except urllib.error.HTTPError as e:
        return {
            "ok": True,
            "status": e.code,
            "headers": {k.lower(): v for k, v in e.headers.items()},
            "raw_headers": list(e.headers.items()),
            "length": 0,
            "body_preview": "",
        }
    except Exception as e:
        return {"ok": False, "error": str(e)}


def audit_headers_and_fingerprint(target_url: str) -> list:
    url = normalize_url(target_url)
    print(f"\n{C.CYAN}{C.BOLD}[1/4] Auditing Security Headers & Tech Fingerprinting: {url}{C.RESET}")
    res = fetch_url(url)
    findings = []

    if not res.get("ok"):
        print(f"  {C.RED}[!] Connection failed: {res.get('error')}{C.RESET}")
        return findings

    headers = res["headers"]
    print(f"  {C.GRAY}HTTP Status: {res['status']}{C.RESET}")

    for hdr, (severity, desc) in SECURITY_HEADERS.items():
        if hdr in headers:
            print(f"  {C.GREEN}[PASS]{C.RESET} {hdr}: {headers[hdr][:60]}")
        else:
            color = C.RED if severity == "HIGH" else C.YELLOW
            print(f"  {color}[MISSING - {severity}]{C.RESET} {hdr} ({desc})")
            findings.append(f"[{severity}] Missing security header `{hdr}` — {desc}")

    for fp in FINGERPRINT_HEADERS:
        if fp in headers:
            val = headers[fp]
            print(f"  {C.YELLOW}[INFO-LEAK]{C.RESET} `{fp}: {val}` exposed (Stack Fingerprinting)")
            findings.append(f"[LOW] Information disclosure via header `{fp}: {val}`")

    return findings


def audit_cors_and_cookies(target_url: str) -> list:
    url = normalize_url(target_url)
    print(f"\n{C.CYAN}{C.BOLD}[2/4] Inspecting CORS Policy & Cookie Attributes: {url}{C.RESET}")
    test_origin = "https://evil-attacker.example.com"
    res = fetch_url(url, custom_headers={"Origin": test_origin})
    findings = []

    if not res.get("ok"):
        print(f"  {C.RED}[!] Connection failed: {res.get('error')}{C.RESET}")
        return findings

    headers = res["headers"]
    acao = headers.get("access-control-allow-origin")
    acac = headers.get("access-control-allow-credentials", "").lower()

    if acao == "*":
        print(f"  {C.YELLOW}[MEDIUM]{C.RESET} Permissive CORS Wildcard: Access-Control-Allow-Origin: *")
        findings.append("[MEDIUM] Permissive CORS Wildcard (`Access-Control-Allow-Origin: *`)")
    elif acao == test_origin:
        sev = "HIGH" if acac == "true" else "MEDIUM"
        print(f"  {C.RED}[{sev}]{C.RESET} Arbitrary Origin Reflected in CORS: {acao} (Credentials: {acac})")
        findings.append(f"[{sev}] Arbitrary Origin Reflection in CORS (`{acao}`, credentials={acac})")
    else:
        print(f"  {C.GREEN}[PASS]{C.RESET} No permissive CORS reflection detected.")

    # Inspect Set-Cookie headers
    cookies = [v for k, v in res.get("raw_headers", []) if k.lower() == "set-cookie"]
    if not cookies:
        print(f"  {C.GRAY}[INFO] No Set-Cookie headers returned on root request.{C.RESET}")
    for ck in cookies:
        ck_lower = ck.lower()
        name = ck.split("=", 1)[0].strip()
        issues = []
        if "httponly" not in ck_lower:
            issues.append("missing HttpOnly")
        if "secure" not in ck_lower:
            issues.append("missing Secure")
        if "samesite=none" in ck_lower:
            issues.append("SameSite=None (cross-site cookie risk)")
        if issues:
            issue_str = ", ".join(issues)
            print(f"  {C.YELLOW}[MEDIUM]{C.RESET} Cookie `{name}` flags: {issue_str}")
            findings.append(f"[MEDIUM] Cookie `{name}` has weak flags: {issue_str}")
        else:
            print(f"  {C.GREEN}[PASS]{C.RESET} Cookie `{name}` has strong security attributes.")

    return findings


def passive_subdomain_recon(domain_or_url: str, limit: int = 25) -> list:
    domain = extract_domain(domain_or_url)
    print(f"\n{C.CYAN}{C.BOLD}[3/4] Passive Subdomain Enumeration (OTX + HackerTarget + crt.sh): {domain}{C.RESET}")
    subdomains = set()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    # Source 1: AlienVault OTX Passive DNS (Fast & Reliable JSON API)
    try:
        otx_url = f"https://otx.alienvault.com/api/v1/indicators/domain/{urllib.parse.quote(domain)}/passive_dns"
        req = urllib.request.Request(otx_url, headers={"User-Agent": "FataReconSuite/2.0"})
        with urllib.request.urlopen(req, timeout=8, context=ctx) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="ignore"))
            for item in data.get("passive_dns", []):
                host = item.get("hostname", "").strip().lower().lstrip("*.")
                if host.endswith(domain):
                    subdomains.add(host)
    except Exception:
        pass

    # Source 2: HackerTarget HostSearch API
    try:
        ht_url = f"https://api.hackertarget.com/hostsearch/?q={urllib.parse.quote(domain)}"
        req = urllib.request.Request(ht_url, headers={"User-Agent": "FataReconSuite/2.0"})
        with urllib.request.urlopen(req, timeout=8, context=ctx) as resp:
            lines = resp.read().decode("utf-8", errors="ignore").splitlines()
            for line in lines:
                if "," in line and "API count exceeded" not in line:
                    host = line.split(",", 1)[0].strip().lower()
                    if host.endswith(domain):
                        subdomains.add(host)
    except Exception:
        pass

    # Source 3: crt.sh Certificate Transparency (Fallback if needed)
    if len(subdomains) < 5:
        try:
            crt_url = f"https://crt.sh/?q=%.{urllib.parse.quote(domain)}&output=json"
            req = urllib.request.Request(crt_url, headers={"User-Agent": "FataReconSuite/2.0"})
            with urllib.request.urlopen(req, timeout=8, context=ctx) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="ignore"))
                for entry in data:
                    for sub in entry.get("name_value", "").splitlines():
                        sub = sub.strip().lower().lstrip("*.")
                        if sub.endswith(domain):
                            subdomains.add(sub)
        except Exception:
            pass

    sorted_subs = sorted(subdomains)
    if not sorted_subs:
        print(f"  {C.YELLOW}[!] No passive subdomains returned from OSINT sources.{C.RESET}")
        return []

    print(f"  {C.GREEN}[+] Discovered {len(sorted_subs)} unique subdomains passively:{C.RESET}")
    for sub in sorted_subs[:limit]:
        try:
            ip = socket.gethostbyname(sub)
            print(f"    • {sub:<38} -> {C.GREEN}{ip}{C.RESET}")
        except Exception:
            print(f"    • {sub:<38} -> {C.GRAY}(unresolved){C.RESET}")

    if len(sorted_subs) > limit:
        print(f"    {C.GRAY}... and {len(sorted_subs) - limit} more subdomains.{C.RESET}")

    return sorted_subs


def probe_common_endpoints(target_url: str) -> list:
    base = normalize_url(target_url)
    print(f"\n{C.CYAN}{C.BOLD}[4/4] Probing Common API & Discovery Endpoints ({len(COMMON_PATHS)} paths):{C.RESET}")
    exposed = []

    def check_path(path):
        full_url = base + path
        r = fetch_url(full_url, timeout=6)
        return path, r

    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
        futures = [executor.submit(check_path, p) for p in COMMON_PATHS]
        for fut in concurrent.futures.as_completed(futures):
            path, r = fut.result()
            if r.get("ok") and r.get("status") in (200, 201, 401, 403):
                st = r["status"]
                color = C.GREEN if st == 200 else C.YELLOW
                print(f"  {color}[HTTP {st}]{C.RESET} {path:<28} (Size: {r.get('length', 0)} bytes)")
                if st == 200:
                    exposed.append(f"[INFO] Publicly accessible endpoint `{path}` (HTTP 200)")

    if not exposed:
        print(f"  {C.GRAY}No open HTTP 200 discovery endpoints found.{C.RESET}")
    return exposed


def generate_markdown_report(target: str, findings: list, subdomains: list, filename: str):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        f"# 🛡️ Security Reconnaissance & Audit Report: `{target}`",
        f"- **Generated by:** Fata Recon & AppSec Audit Suite v2.0",
        f"- **Timestamp:** {now}",
        "",
        "## 1. Security Findings Summary",
    ]
    if findings:
        for idx, f in enumerate(findings, 1):
            lines.append(f"{idx}. {f}")
    else:
        lines.append("- No missing headers or CORS misconfigurations detected.")

    lines.append("")
    lines.append(f"## 2. Discovered Subdomains ({len(subdomains)})")
    for s in subdomains[:50]:
        lines.append(f"- `{s}`")

    with open(filename, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    print(f"\n{C.GREEN}{C.BOLD}[✓] Saved Markdown Audit Report to: {filename}{C.RESET}")


def interactive_menu():
    while True:
        print(BANNER)
        print(f"  {C.BOLD}Select Reconnaissance Module:{C.RESET}")
        print(f"  {C.PURPLE}[1]{C.RESET} Security Header & Stack Fingerprinting Audit")
        print(f"  {C.PURPLE}[2]{C.RESET} CORS Wildcard & Cookie Security Inspector")
        print(f"  {C.PURPLE}[3]{C.RESET} Passive Subdomain Enumerator (crt.sh CT Logs)")
        print(f"  {C.PURPLE}[4]{C.RESET} Common API & Endpoint Exposure Prober")
        print(f"  {C.GREEN}[5]{C.RESET} Run Full Audit Pipeline + Export Markdown Report")
        print(f"  {C.RED}[0]{C.RESET} Exit\n")

        choice = input(f"{C.CYAN}fata@recon:~$ {C.RESET}").strip()
        if choice == "0":
            print(f"\n{C.GREEN}Happy Bug Hunting! — Fata Fatikhul Karim (@zeonmaltius){C.RESET}")
            break
        elif choice in ("1", "2", "3", "4", "5"):
            target = input(f"{C.YELLOW}Enter target domain or URL (e.g. example.com): {C.RESET}").strip()
            if not target:
                continue
            if choice == "1":
                audit_headers_and_fingerprint(target)
            elif choice == "2":
                audit_cors_and_cookies(target)
            elif choice == "3":
                passive_subdomain_recon(target)
            elif choice == "4":
                probe_common_endpoints(target)
            elif choice == "5":
                f1 = audit_headers_and_fingerprint(target)
                f2 = audit_cors_and_cookies(target)
                subs = passive_subdomain_recon(target)
                f3 = probe_common_endpoints(target)
                clean_name = extract_domain(target).replace(".", "_")
                report_file = f"audit_report_{clean_name}.md"
                generate_markdown_report(target, f1 + f2 + f3, subs, report_file)
            input(f"\n{C.GRAY}[Press Enter to return to main menu]{C.RESET}")
        else:
            print(f"{C.RED}[!] Invalid option.{C.RESET}")
            time.sleep(1)


def main():
    parser = argparse.ArgumentParser(
        description="Fata Recon & AppSec Audit Suite v2.0 — Web Security & Bug Bounty Recon CLI"
    )
    parser.add_argument("-u", "--url", help="Target URL or domain to audit")
    parser.add_argument("--headers", action="store_true", help="Run Security Header & Fingerprint Audit")
    parser.add_argument("--cors", action="store_true", help="Run CORS & Cookie Security Audit")
    parser.add_argument("--subs", action="store_true", help="Run Passive Subdomain Recon (crt.sh)")
    parser.add_argument("--probe", action="store_true", help="Probe common API & discovery endpoints")
    parser.add_argument("--full", action="store_true", help="Run full audit and save Markdown report")
    parser.add_argument("-o", "--output", help="Output Markdown report filename")

    args = parser.parse_args()
    if not args.url:
        interactive_menu()
        return

    print(BANNER)
    findings = []
    subs = []
    if args.headers or args.full:
        findings.extend(audit_headers_and_fingerprint(args.url))
    if args.cors or args.full:
        findings.extend(audit_cors_and_cookies(args.url))
    if args.subs or args.full:
        subs = passive_subdomain_recon(args.url)
    if args.probe or args.full:
        findings.extend(probe_common_endpoints(args.url))

    if args.full or args.output:
        out_name = args.output or f"audit_{extract_domain(args.url).replace('.', '_')}.md"
        generate_markdown_report(args.url, findings, subs, out_name)


if __name__ == "__main__":
    main()
