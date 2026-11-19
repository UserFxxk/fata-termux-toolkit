# 🛡️ Fata Recon & AppSec Audit Suite (v3.0)

[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![OWASP](https://img.shields.io/badge/Focus-OWASP_Top_10-000000?style=for-the-badge&logo=owasp&logoColor=white)](https://owasp.org)
[![License](https://img.shields.io/badge/License-MIT-10B981?style=for-the-badge)](LICENSE)

**Fata Recon & AppSec Audit Suite v3.0** adalah perangkat *Command-Line Interface (CLI)* berbasis Python tanpa dependensi eksternal (*zero external dependencies*) untuk melakukan **Web Security Reconnaissance**, **Audit Konfigurasi Header & CORS/Cookie**, **Enumerasi Subdomain Pasif Multi-Sumber (`OTX + HackerTarget + crt.sh`)**, **API Boundary & Input Validation Fuzzing (`0, -500, 1e308`)**, serta **Generator Laporan PoC & Kode Remediasi Otomatis**.

Dirancang untuk mempercepat tahap *Reconnaissance* pada pengujian **Bug Bounty** maupun audit keamanan aplikasi sebelum rilis produksi (*Pre-Release Security Assessment*).

---

## ✨ Modul & Kapabilitas Utama

1. **🔍 Security Header & Stack Fingerprinting Auditor (`--headers`)**
   - Memeriksa keberadaan dan konfigurasi header keamanan krusial: `Content-Security-Policy (CSP)`, `Strict-Transport-Security (HSTS)`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, dan `Permissions-Policy`.
   - Mendeteksi kebocoran informasi teknologi backend (*stack fingerprinting*) melalui header `X-Powered-By`, `Server`, dan `X-Generator`.

2. **🍪 CORS Wildcard & Cookie Security Inspector (`--cors`)**
   - Menguji apakah server memiliki konfigurasi `Access-Control-Allow-Origin: *` (Wildcard) atau memantulkan (*reflect*) header `Origin` arbitrer beserta `Access-Control-Allow-Credentials: true`.
   - Memeriksa atribut keamanan pada setiap `Set-Cookie` (`HttpOnly`, `Secure`, dan risiko `SameSite=None`).

3. **🌐 Passive Subdomain Enumerator via CT Logs (`--subs`)**
   - Mengambil daftar subdomain secara pasif melalui log *Certificate Transparency* publik (`crt.sh`) tanpa mengirimkan trafik langsung ke server target, lalu melakukan resolusi IP DNS secara otomatis.

4. **⚡ Concurrent API & Discovery Endpoint Prober (`--probe`)**
   - Memeriksa ketersediaan endpoint dokumentasi dan API umum (`/api/history`, `/api/health`, `/swagger.json`, `/openapi.json`, `/graphql`, `/.well-known/security.txt`) secara konkurensi (*multi-threaded*).

5. **🧪 API Boundary & Input Validation Fuzzer (`--fuzz --param <name> --confirm-authorized`)**
   - Menguji parameter URL/API dengan *edge-case payloads* (`0`, `-500`, `1e308`, `null`, dan karakter spesial `'\"<>`) untuk mendeteksi *Unhandled Server Exception (HTTP 500)*, *Solver Hang / Latency Spike (DoS)*, atau ketiadaan validasi batas numerik di backend.
   - **Safety Guardrail:** Modul `--fuzz` secara default dinonaktifkan kecuali pengguna menyertakan flag eksplisit `--confirm-authorized` sebagai konfirmasi bahwa pengujian dilakukan pada target yang memiliki izin tertulis (*Authorized Target / Bug Bounty Scope*).

6. **📄 Automated PoC & Remediation Blueprint Generator (`--full`)**
   - Menjalankan seluruh modul sekaligus dan otomatis menyusun laporan Markdown lengkap dengan *Code Blueprint* mitigasi (`Helmet` untuk Header, `CORS Allowlist`, dan `Zod Schema Validation`).

---

## 🚀 Cara Penggunaan

### Mode Interaktif (Menu TUI)
```bash
git clone https://github.com/fatakarim/fata-termux-toolkit.git
cd fata-termux-toolkit
python3 recon.py
```

### Mode CLI (Baris Perintah Langsung)
```bash
# Jalankan Full Audit (termasuk boundary fuzzer pada target berizin) & simpan laporan ke Markdown
python3 recon.py -u example.com --full --confirm-authorized

# Hanya cek pasif/header (Security Headers & CORS/Cookie)
python3 recon.py -u https://example.com --headers --cors

# Enumerasi Subdomain Pasif (OTX + HackerTarget + crt.sh)
python3 recon.py -u example.com --subs
```

---

## 📸 Contoh Output Terminal

```text
  ╔══════════════════════════════════════════════════════════════╗
  ║   🛡️  FATA RECON & APPSEC AUDIT SUITE v2.0                   ║
  ║   Build it right, break it better • fatakarim.github.io       ║
  ╚══════════════════════════════════════════════════════════════╝

[1/4] Auditing Security Headers & Tech Fingerprinting: https://example.com
  [MISSING - HIGH] content-security-policy (Mitigates XSS and data injection attacks)
  [MISSING - MEDIUM] strict-transport-security (Enforces HTTPS connections)
  [INFO-LEAK] `x-powered-by: Express` exposed (Stack Fingerprinting)

[2/4] Inspecting CORS Policy & Cookie Attributes: https://example.com
  [MEDIUM] Permissive CORS Wildcard: Access-Control-Allow-Origin: *
  [MEDIUM] Cookie `__cf_bm` flags: SameSite=None (cross-site cookie risk)
```

---

## ⚠️ Disclaimer
Perkakas ini dibuat murni untuk tujuan edukasi, riset keamanan yang sah (*Authorized Penetration Testing*), dan program *Bug Bounty* resmi. Pengguna bertanggung jawab penuh untuk mematuhi hukum dan ruang lingkup (*scope*) pengujian yang berlaku.

## 👨‍💻 Author
**Fata Fatikhul Karim**
- 🌐 Portfolio: [https://fatakarim.github.io](https://fatakarim.github.io)
- 💼 LinkedIn: [linkedin.com/in/fata-fatikhul-karim](https://www.linkedin.com/in/fata-fatikhul-karim)
- 🛡️ HackerOne: [@zeonmaltius](https://hackerone.com/zeonmaltius)
