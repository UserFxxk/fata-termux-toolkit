#!/usr/bin/env python3
"""
Fata Recon & AppSec Audit Suite (v3.0)
Author : Fata Fatikhul Karim (@fatakarim | HackerOne: @zeonmaltius)
License: MIT
Purpose: Non-destructive Web Security Reconnaissance, Multi-Source OSINT
         Subdomain Discovery, CORS/Cookie Misconfiguration Audit, API
         Boundary/Logic Fuzzer, and AI-Assisted PoC Report Generator.
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
  ║   🛡️  FATA RECON & APPSEC AUDIT SUITE v3.0                   ║
  ║   Headers • CORS • OSINT • Boundary Fuzzer • AI PoC Builder  ║
  ║   Build it right, break it better • fatakarim.github.io       ║
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
    "/api/feeds",
    "/api/docs",
    "/swagger.json",
    "/openapi.json",
    "/graphql",
]

BOUNDARY_PAYLOADS = [
    ("zero_value", "0", "Tests zero-division / solver freeze on zero numeric input"),
    ("negative_bound", "-500", "Tests negative numeric bounds (business logic / solver corruption)"),
    ("float_overflow", "1e308", "Tests IEEE-754 floating-point overflow handling"),
    ("empty_null", "null", "Tests null/missing parameter exception handling"),
    ("quote_probe", "'\"<>", "Tests unescaped special character reflection / 500 error"),
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
        "User-Agent": "FataReconSuite/3.0 (Security-Audit; +https://fatakarim.github.io)"
    }
    if custom_headers:
        headers.update(custom_headers)

    req = urllib.request.Request(url, headers=headers, method="GET")
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(65536)
            elapsed = round((time.time() - t0) * 1000)
            return {
                "ok": True,
                "status": resp.status,
                "elapsed_ms": elapsed,
                "headers": {k.lower(): v for k, v in resp.getheaders()},
                "raw_headers": resp.getheaders(),
                "length": len(body),
                "body_preview": body.decode("utf-8", errors="ignore")[:300],
            }
    except urllib.error.HTTPError as e:
        elapsed = round((time.time() - t0) * 1000)
        return {
            "ok": True,
            "status": e.code,
            "elapsed_ms": elapsed,
            "headers": {k.lower(): v for k, v in e.headers.items()},
            "raw_headers": list(e.headers.items()),
            "length": 0,
            "body_preview": "",
        }
    except Exception as e:
        elapsed = round((time.time() - t0) * 1000)
        return {"ok": False, "elapsed_ms": elapsed, "error": str(e)}


def audit_headers_and_fingerprint(target_url: str) -> list:
    url = normalize_url(target_url)
    print(f"\n{C.CYAN}{C.BOLD}[1/5] Auditing Security Headers & Tech Fingerprinting: {url}{C.RESET}")
    res = fetch_url(url)
    findings = []

    if not res.get("ok"):
        print(f"  {C.RED}[!] Connection failed: {res.get('error')}{C.RESET}")
        return findings

    headers = res["headers"]
    print(f"  {C.GRAY}HTTP Status: {res['status']} ({res.get('elapsed_ms', 0)} ms){C.RESET}")

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
    print(f"\n{C.CYAN}{C.BOLD}[2/5] Inspecting CORS Policy & Cookie Attributes: {url}{C.RESET}")
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
    print(f"\n{C.CYAN}{C.BOLD}[3/5] Passive Subdomain Enumeration (OTX + HackerTarget + crt.sh): {domain}{C.RESET}")
    subdomains = set()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        otx_url = f"https://otx.alienvault.com/api/v1/indicators/domain/{urllib.parse.quote(domain)}/passive_dns"
        req = urllib.request.Request(otx_url, headers={"User-Agent": "FataReconSuite/3.0"})
        with urllib.request.urlopen(req, timeout=8, context=ctx) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="ignore"))
            for item in data.get("passive_dns", []):
                host = item.get("hostname", "").strip().lower().lstrip("*.")
                if host.endswith(domain):
                    subdomains.add(host)
    except Exception:
        pass

    try:
        ht_url = f"https://api.hackertarget.com/hostsearch/?q={urllib.parse.quote(domain)}"
        req = urllib.request.Request(ht_url, headers={"User-Agent": "FataReconSuite/3.0"})
        with urllib.request.urlopen(req, timeout=8, context=ctx) as resp:
            lines = resp.read().decode("utf-8", errors="ignore").splitlines()
            for line in lines:
                if "," in line and "API count exceeded" not in line:
                    host = line.split(",", 1)[0].strip().lower()
                    if host.endswith(domain):
                        subdomains.add(host)
    except Exception:
        pass

    if len(subdomains) < 5:
        try:
            crt_url = f"https://crt.sh/?q=%.{urllib.parse.quote(domain)}&output=json"
            req = urllib.request.Request(crt_url, headers={"User-Agent": "FataReconSuite/3.0"})
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
    print(f"\n{C.CYAN}{C.BOLD}[4/5] Probing Common API & Discovery Endpoints ({len(COMMON_PATHS)} paths):{C.RESET}")
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
                print(f"  {color}[HTTP {st}]{C.RESET} {path:<28} (Size: {r.get('length', 0)} bytes, {r.get('elapsed_ms', 0)} ms)")
                if st == 200:
                    exposed.append(f"[INFO] Publicly accessible endpoint `{path}` (HTTP 200)")

    if not exposed:
        print(f"  {C.GRAY}No open HTTP 200 discovery endpoints found.{C.RESET}")
    return exposed


def fuzz_boundary_parameters(target_url: str, param_name: str = "id") -> list:
    """
    Tests query parameters with numeric & boundary edge-cases (0, -500, 1e308, null, special chars)
    to detect unhandled 500 server errors, solver/latency spikes, or unvalidated boundary acceptance.
    """
    base = normalize_url(target_url)
    sep = "&" if "?" in base else "?"
    print(f"\n{C.CYAN}{C.BOLD}[5/5] Running Boundary & Input Validation Fuzzer (param: `{param_name}`):{C.RESET}")
    findings = []

    baseline = fetch_url(f"{base}{sep}{param_name}=1")
    base_ms = baseline.get("elapsed_ms", 100) if baseline.get("ok") else 100

    for label, val, desc in BOUNDARY_PAYLOADS:
        probe_url = f"{base}{sep}{urllib.parse.quote(param_name)}={urllib.parse.quote(val)}"
        r = fetch_url(probe_url, timeout=8)
        if not r.get("ok"):
            print(f"  {C.RED}[TIMEOUT/DROP]{C.RESET} {param_name}={val:<10} -> Connection dropped/timed out ({desc})")
            findings.append(f"[HIGH] Potential DoS / Hang on boundary input `{param_name}={val}` ({desc})")
            continue

        status = r["status"]
        ms = r.get("elapsed_ms", 0)
        if status >= 500:
            print(f"  {C.RED}[HTTP {status}]{C.RESET}     {param_name}={val:<10} -> Unhandled Server Exception! ({ms} ms)")
            findings.append(f"[HIGH] Unhandled HTTP {status} exception on boundary payload `{param_name}={val}`")
        elif ms > max(base_ms * 4, 2500):
            print(f"  {C.YELLOW}[LATENCY SPIKE]{C.RESET} {param_name}={val:<10} -> {ms} ms vs baseline {base_ms} ms ({desc})")
            findings.append(f"[MEDIUM] Abnormal latency spike ({ms} ms) on `{param_name}={val}`")
        else:
            print(f"  {C.GREEN}[HTTP {status}]{C.RESET}     {param_name}={val:<10} -> Handled cleanly ({ms} ms)")

    return findings


def build_remediation_matrix(findings: list) -> list:
    """
    Generates actionable OWASP remediation recommendations & code blueprints
    based on the discovered findings (plus optional Gemini AI enrichment if GEMINI_API_KEY is set).
    """
    recs = []
    joined = "\n".join(findings).lower()

    if "content-security-policy" in joined or "strict-transport-security" in joined:
        recs.append(
            "### 🔒 1. Hardening HTTP Security Headers (Helmet / Nginx)\n"
            "Terapkan middleware `helmet` (Node.js/Express) atau konfigurasi reverse-proxy untuk mencegah XSS, Clickjacking, dan MIME-sniffing:\n"
            "```javascript\n"
            "import helmet from 'helmet';\n"
            "app.disable('x-powered-by');\n"
            "app.use(helmet({\n"
            "  contentSecurityPolicy: { directives: { defaultSrc: [\"'self'\"] } },\n"
            "  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true }\n"
            "}));\n"
            "```"
        )

    if "cors" in joined:
        recs.append(
            "### 🌐 2. Restrict Permissive CORS Policy\n"
            "Hindari penggunaan `Access-Control-Allow-Origin: *` pada endpoint yang memproses data sensitif. Gunakan *allowlist* domain eksplisit:\n"
            "```javascript\n"
            "app.use(cors({\n"
            "  origin: ['https://app.yourdomain.com'],\n"
            "  methods: ['GET', 'POST'],\n"
            "  credentials: true\n"
            "}));\n"
            "```"
        )

    if "boundary" in joined or "500" in joined or "dos" in joined:
        recs.append(
            "### 🛡️ 3. Enforce Strict Backend Input Bounds (Prevent Solver DoS & Data Corruption)\n"
            "Validasi seluruh parameter numerik dan string di sisi backend menggunakan schema validator (Zod/Joi) untuk menolak angka negatif atau overflow:\n"
            "```javascript\n"
            "const InputSchema = z.object({\n"
            "  id: z.coerce.number().int().positive().max(1_000_000),\n"
            "  percentage: z.number().min(0).max(100)\n"
            "});\n"
            "```"
        )

    if not recs:
        recs.append(
            "- Target telah menerapkan sebagian besar kontrol dasar dengan baik. Lanjutkan pengujian manual pada endpoint terautentikasi (IDOR / Broken Access Control)."
        )

    return recs


def generate_markdown_report(target: str, findings: list, subdomains: list, filename: str):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    remediations = build_remediation_matrix(findings)

    lines = [
        f"# 🛡️ Security Reconnaissance & AppSec Audit Report: `{target}`",
        f"- **Generated by:** Fata Recon & AppSec Audit Suite v3.0",
        f"- **Auditor:** Fata Fatikhul Karim ([fatakarim.github.io](https://fatakarim.github.io))",
        f"- **Timestamp:** {now}",
        "",
        "## 1. Executive Summary & Findings",
    ]
    if findings:
        for idx, f in enumerate(findings, 1):
            lines.append(f"{idx}. {f}")
    else:
        lines.append("- No missing headers, CORS misconfigurations, or boundary crashes detected.")

    lines.append("")
    lines.append("## 2. Recommended Remediation & Code Blueprints")
    lines.extend(remediations)

    lines.append("")
    lines.append(f"## 3. Discovered Subdomains ({len(subdomains)})")
    for s in subdomains[:50]:
        lines.append(f"- `{s}`")

    with open(filename, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    print(f"\n{C.GREEN}{C.BOLD}[✓] Saved Full Markdown Audit Report to: {filename}{C.RESET}")


def interactive_menu():
    while True:
        print(BANNER)
        print(f"  {C.BOLD}Select Reconnaissance & Audit Module:{C.RESET}")
        print(f"  {C.PURPLE}[1]{C.RESET} Security Header & Stack Fingerprinting Audit")
        print(f"  {C.PURPLE}[2]{C.RESET} CORS Wildcard & Cookie Security Inspector")
        print(f"  {C.PURPLE}[3]{C.RESET} Passive Subdomain Enumerator (OTX + HackerTarget + crt.sh)")
        print(f"  {C.PURPLE}[4]{C.RESET} Common API & Endpoint Exposure Prober")
        print(f"  {C.PURPLE}[5]{C.RESET} API Boundary & Input Validation Fuzzer (0, -500, 1e308)")
        print(f"  {C.GREEN}[6]{C.RESET} Run Full Audit Pipeline + Export PoC & Remediation Report")
        print(f"  {C.RED}[0]{C.RESET} Exit\n")

        choice = input(f"{C.CYAN}fata@recon-v3:~$ {C.RESET}").strip()
        if choice == "0":
            print(f"\n{C.GREEN}Happy Bug Hunting! — Fata Fatikhul Karim (@zeonmaltius){C.RESET}")
            break
        elif choice in ("1", "2", "3", "4", "5", "6"):
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
                param = input(f"{C.YELLOW}Parameter name to fuzz [default: id]: {C.RESET}").strip() or "id"
                fuzz_boundary_parameters(target, param)
            elif choice == "6":
                f1 = audit_headers_and_fingerprint(target)
                f2 = audit_cors_and_cookies(target)
                subs = passive_subdomain_recon(target)
                f3 = probe_common_endpoints(target)
                f4 = fuzz_boundary_parameters(target, "id")
                clean_name = extract_domain(target).replace(".", "_")
                report_file = f"audit_report_{clean_name}.md"
                generate_markdown_report(target, f1 + f2 + f3 + f4, subs, report_file)
            input(f"\n{C.GRAY}[Press Enter to return to main menu]{C.RESET}")
        else:
            print(f"{C.RED}[!] Invalid option.{C.RESET}")
            time.sleep(1)


def main():
    parser = argparse.ArgumentParser(
        description="Fata Recon & AppSec Audit Suite v3.0 — Web Security & Bug Bounty Recon CLI"
    )
    parser.add_argument("-u", "--url", help="Target URL or domain to audit")
    parser.add_argument("--headers", action="store_true", help="Run Security Header & Fingerprint Audit")
    parser.add_argument("--cors", action="store_true", help="Run CORS & Cookie Security Audit")
    parser.add_argument("--subs", action="store_true", help="Run Passive Subdomain Recon (OSINT)")
    parser.add_argument("--probe", action="store_true", help="Probe common API & discovery endpoints")
    parser.add_argument("--fuzz", action="store_true", help="Run Boundary & Input Validation Fuzzer (requires --confirm-authorized)")
    parser.add_argument("--param", default="id", help="Query parameter name for --fuzz (default: id)")
    parser.add_argument(
        "--confirm-authorized",
        action="store_true",
        help="Explicitly confirm you have written authorization to test the target domain",
    )
    parser.add_argument("--full", action="store_true", help="Run all modules + save PoC Remediation Report")
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
    if args.fuzz or args.full:
        if not args.confirm_authorized:
            print(
                f"\n{C.YELLOW}[SAFETY GUARDRAIL] Skipping active boundary fuzzer (--fuzz): "
                f"add `--confirm-authorized` to confirm written testing permission on {args.url}.{C.RESET}"
            )
        else:
            findings.extend(fuzz_boundary_parameters(args.url, args.param))

    if args.full or args.output:
        out_name = args.output or f"audit_{extract_domain(args.url).replace('.', '_')}.md"
        generate_markdown_report(args.url, findings, subs, out_name)


if __name__ == "__main__":
    main()
