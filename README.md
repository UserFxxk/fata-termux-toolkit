# 🛡️ Fata Recon & AppSec Audit Suite (v3.0)

[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![CI](https://github.com/fatakarim/fata-termux-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/fatakarim/fata-termux-toolkit/actions)
[![Unit Tests](https://img.shields.io/badge/Tests-9%2F9_Passing_(Python_%2B_Node)-10B981?style=for-the-badge&logo=pytest&logoColor=white)](tests/test_recon.py)
[![OWASP](https://img.shields.io/badge/Focus-OWASP_Top_10-000000?style=for-the-badge&logo=owasp&logoColor=white)](https://owasp.org)
[![License](https://img.shields.io/badge/License-MIT-10B981?style=for-the-badge)](LICENSE)

**Fata Recon & AppSec Audit Suite v3.0** is a zero-dependency **Python 3 Command-Line Interface (CLI)** engineered for **Pre-Release Web Application Security Hygiene Checks**, **HTTP Security Header & CORS/Cookie Auditing**, **Multi-Source Passive Subdomain Enumeration (`AlienVault OTX + HackerTarget + crt.sh`)**, **Non-Destructive API Numeric Boundary Probing (`0, -500, 1e308`)**, and **Automated Markdown Remediation Report Generation**.

It also includes a runnable **Defensive Backend Remediation Blueprint (`examples/express-solver-remediation/`)** with automated regression tests demonstrating how to patch `CWE-306` (Missing Authentication), `CWE-20` (Numeric Domain Bounds), `CWE-400` (Solver DoS), and `CWE-942` (Wildcard CORS).

---

## ✨ Core Modules & Architecture

1. **🔍 Security Header & Stack Fingerprinting Auditor (`--headers`)**
   - Audits essential OWASP HTTP security headers: `Content-Security-Policy (CSP)`, `Strict-Transport-Security (HSTS)`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, and `Permissions-Policy`.
   - Detects backend stack fingerprinting leaks across `X-Powered-By`, `Server`, `X-AspNet-Version`, and `X-Generator`.

2. **🍪 CORS Wildcard & Cookie Attribute Inspector (`--cors`)**
   - Evaluates whether the target endpoint exposes a permissive `Access-Control-Allow-Origin: *` wildcard or reflects arbitrary `Origin` headers alongside `Access-Control-Allow-Credentials: true`.
   - Audits `Set-Cookie` headers for missing `HttpOnly`, `Secure`, or permissive `SameSite=None` attributes.

3. **🌐 Multi-Source Passive Subdomain Enumerator (`--subs`)**
   - Aggregates passive DNS telemetry across three independent OSINT providers (**AlienVault OTX**, **HackerTarget**, and **Certificate Transparency `crt.sh`**) with automatic failover and concurrent IP resolution—sending zero active packets to the target host during discovery.

4. **⚡ Concurrent API & Discovery Endpoint Prober (`--probe`)**
   - Multi-threaded (`concurrent.futures.ThreadPoolExecutor`) probing for common API documentation and telemetry paths (`/api/history`, `/api/health`, `/swagger.json`, `/openapi.json`, `/graphql`, `/.well-known/security.txt`).

5. **🧪 Non-Destructive API Boundary & Input Validation Prober (`--fuzz --param <name> --confirm-authorized`)**
   - Tests query/API parameters against 5 non-destructive boundary payloads (`0`, `-500`, `1e308`, `null`, and `'"<>`) to identify unhandled server exceptions (`HTTP 500`), solver thread hangs / latency spikes (`CWE-400`), or missing server-side numeric domain validation (`CWE-20`).
   - **Explicit Authorization Guardrail:** Active boundary probing is disabled by default unless the operator passes `--confirm-authorized` to confirm written testing permission.

6. **📄 Automated PoC & Remediation Blueprint Generator (`--full`)**
   - Generates a structured Markdown security assessment report containing drop-in defensive code blueprints (`Helmet` security headers, strict `CORS` origin allowlists, and `Zod` numeric boundary validation schemas).

---

## 🚀 Quick Start & CLI Usage

### 1. Run Automated Verification Suites (Python `unittest` + Node.js Remediation Regression Tests)
```bash
git clone https://github.com/fatakarim/fata-termux-toolkit.git
cd fata-termux-toolkit

# Run Python 3 CLI & OSINT unit tests (5/5 tests)
python3 -m unittest discover -s tests -v

# Run Defensive API Remediation Blueprint regression tests (SOLVER-01..08)
node --test examples/express-solver-remediation/solver-security.test.js
```

### 2. Direct CLI Execution
```bash
# Passive Security Header & CORS/Cookie Audit
python3 recon.py -u https://example.com --headers --cors

# Multi-Source Passive Subdomain Enumeration (OTX + HackerTarget + crt.sh)
python3 recon.py -u example.com --subs

# Full Authorized Audit (including non-destructive boundary probing) + Markdown Report export
python3 recon.py -u https://example.com --full --confirm-authorized -o audit_report.md
```

---

## 📸 Terminal Output Sample

```text
  ╔══════════════════════════════════════════════════════════════╗
  ║   🛡️  FATA RECON & APPSEC AUDIT SUITE v3.0                   ║
  ║   Headers • CORS • OSINT • Boundary Fuzzer • AI PoC Builder  ║
  ║   Build it right, break it better • fatakarim.github.io       ║
  ╚══════════════════════════════════════════════════════════════╝

[1/5] Auditing Security Headers & Tech Fingerprinting: https://example.com
  [MISSING - HIGH] content-security-policy (Mitigates XSS and data injection attacks (CSP))
  [MISSING - MEDIUM] strict-transport-security (Enforces HTTPS connections (HSTS))
  [INFO-LEAK] `x-powered-by: Express` exposed (Stack Fingerprinting)

[2/5] Inspecting CORS Policy & Cookie Attributes: https://example.com
  [MEDIUM] Permissive CORS Wildcard: Access-Control-Allow-Origin: *
```

---

## ⚠️ Ethical Use & Authorization Disclaimer
This toolkit is engineered strictly for educational use, pre-release DevSecOps hygiene checks on your own applications, and authorized penetration testing / official Bug Bounty programs. Always obtain explicit written permission before testing any system.

## 👨‍💻 Author
**Fata Fatikhul Karim**
- 🌐 Portfolio & Case Studies: [https://fatakarim.github.io](https://fatakarim.github.io)
- 💼 LinkedIn: [linkedin.com/in/fata-fatikhul-karim](https://www.linkedin.com/in/fata-fatikhul-karim)
- 🛡️ HackerOne: [@zeonmaltius](https://hackerone.com/zeonmaltius)
