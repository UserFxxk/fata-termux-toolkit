# 🦅 HackerOne (@zeonmaltius) & VDP Coordinated Disclosure Playbook

This operational runbook standardizes how **Fata Fatikhul Karim (`@zeonmaltius`)** conducts high-signal, non-destructive application security assessments across official **HackerOne Vulnerability Disclosure Programs (VDPs)** and authorized web applications.

---

## 🎯 1. Target Selection Strategy (High-Signal, Low-Bot Competition)

Automated nuclei farms flood public Bug Bounty wildcards (`*.target.com`). To maximize valid **Triaged / Resolved** findings and build verified reputation on `hackerone.com/zeonmaltius`, prioritize:

1. **Authenticated Business-Logic & Domain Math Flows (`CWE-20` / `CWE-840`):**
   - Multi-step calculation forms, financial/quantity estimators, quota allocators, and scientific/agricultural solvers where negative (`-500`), zero (`0`), or float boundary (`1e308`) inputs bypass frontend HTML validation.
2. **Horizontal & Vertical Broken Access Control (`IDOR / BOLA` — `OWASP API1:2023`):**
   - Create two separate test accounts (`Account A` and `Account B`).
   - Capture state-reading (`GET /api/history`, `GET /api/v1/exports/{id}`) and state-mutating (`PUT`, `PATCH`, `DELETE`) requests in Burp Suite and replay `Account A`'s object UUIDs using `Account B`'s session token (and unauthenticated).
3. **Secondary API & Staging Subdomains via Passive OSINT:**
   - Use `recon.py --subs` to enumerate subdomains across AlienVault OTX, HackerTarget, and `crt.sh` without triggering WAF rate limits.

---

## 🛠️ 2. Standardized 3-Phase Recon & Triage Workflow

### Phase A: Zero-Packet Passive OSINT & Hygiene Audit
```bash
# 1. Enumerate subdomains passively (OTX + HackerTarget + crt.sh)
python3 recon.py -u <in-scope-domain.com> --subs

# 2. Audit HTTP Security Headers, Stack Fingerprinting & CORS Reflection
python3 recon.py -u https://<in-scope-target.com> --headers --cors --json-out target_hygiene.json
```

### Phase B: Authorized Non-Destructive API Boundary Probing
*(Only on targets explicitly permitting active testing in scope)*
```bash
python3 recon.py -u "https://<in-scope-target.com>/api/v1/calculate?weight=100" \
  --fuzz --param weight --confirm-authorized -o boundary_report.md
```

### Phase C: Pre-Submission False-Positive Checklist
Before submitting any report to HackerOne or a CSIRT, verify:
- [ ] **Not a CDN/Bot Cookie Informational:** Cookies like Cloudflare `__cf_bm` or `_cfuvid` with `SameSite=None` are expected CDN behavior—never report them as session flaws.
- [ ] **CORS Impact Proof:** Never report `Access-Control-Allow-Origin: *` on public unauthenticated endpoints unless sensitive user-specific data is returned or `Access-Control-Allow-Credentials: true` reflects an arbitrary origin.
- [ ] **Clean Up Test Artifacts:** Log every test record UUID created during verification (`4e856b17...`) and include the list in the report so maintainers can purge test data cleanly.

---

## 📝 3. Maintainer-Ready HackerOne Report Template (RCA + Patch + Regression Test)

```markdown
## Summary
An [Unauthenticated Access Control / Improper Input Boundary Validation] vulnerability on `[ENDPOINT]` allows an attacker to [CONCRETE IMPACT, e.g., read calculation history across tenants / trigger float divergence via negative parameter values].

- **CWE:** CWE-306 / CWE-20
- **CVSS v3.1 Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` (7.5 High)
- **Affected Endpoint:** `[METHOD] https://<target>/api/...`

## Steps to Reproduce (Non-Destructive PoC)
1. Send the following `curl` request without a session token (or with negative boundary payload):
   ```bash
   curl -i -X GET "https://<target>/api/..."
   ```
2. Observe the `HTTP 200 OK` response returning sensitive records / unhandled exception.
3. **Test Artifact Cleanup Note:** Verification created test record UUID(s) `[UUID-1]`, which can be safely deleted.

## Root-Cause Analysis & Recommended Patch (Express.js / Zod Blueprint)
The route handler processes `req.body` without enforcing authentication middleware or domain-grounded numeric bounds:

```javascript
import { z } from 'zod';

const PayloadSchema = z.object({
  parameterName: z.number().min(0.5).max(100)
});
```

## Impact
[1-2 sentences quantifying confidentiality, integrity, or availability impact on production users.]
```
