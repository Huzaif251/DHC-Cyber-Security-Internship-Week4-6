# 🛡️ DHC Cybersecurity Internship — Weeks 4, 5 & 6
## Advanced Security, Ethical Hacking & Security Audits

<div align="center">

![Node.js](https://img.shields.io/badge/Node.js-18.x-339933?style=for-the-badge&logo=nodedotjs&logoColor=white)
![Express](https://img.shields.io/badge/Express-4.18-000000?style=for-the-badge&logo=express&logoColor=white)
![Kali Linux](https://img.shields.io/badge/Kali_Linux-557C94?style=for-the-badge&logo=kalilinux&logoColor=white)
![OWASP](https://img.shields.io/badge/OWASP_Top_10-Compliant-brightgreen?style=for-the-badge)
![License](https://img.shields.io/badge/License-ISC-blue?style=for-the-badge)

**Author:** Huzaifa Ahmed &nbsp;|&nbsp; **DHC ID:** 154 &nbsp;|&nbsp; **Organization:** DHC &nbsp;|&nbsp; **Completed:** 24th May, 2026

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Week 4 — API Security](#-week-4--advanced-threat-detection--api-security)
- [Week 5 — Ethical Hacking](#-week-5--ethical-hacking--vulnerability-fixes)
- [Week 6 — Security Audits](#-week-6--security-audits--compliance)
- [OWASP Top 10 Compliance](#-owasp-top-10-compliance)
- [Getting Started](#-getting-started)
- [API Reference](#-api-reference)
- [Screenshots Evidence](#-screenshots-evidence)

---

## 🎯 Overview

This repository covers Weeks 4–6 of the DHC Cybersecurity Internship, building progressively on the Week 1–3 foundation:

| Week | Focus | Risk Level Before | Risk Level After |
|------|-------|-----------------|-----------------|
| 1 | Vulnerable app (SQLi, plain-text passwords) | CRITICAL | — |
| 2 | Security fixes (bcrypt, JWT, Helmet) | HIGH | MEDIUM |
| 3 | Penetration testing, HTTPS, logging | MEDIUM | LOW |
| **4** | **Rate limiting, CORS, API Keys, CSP, HSTS** | LOW | **VERY LOW** |
| **5** | **Ethical hacking, SQLi fix, CSRF protection** | LOW | **MINIMAL** |
| **6** | **OWASP ZAP, Nikto, Lynis audits** | MINIMAL | **SECURED** |

---

## 🔒 Week 4 — Advanced Threat Detection & API Security

### Features Implemented

| Feature | Tool | Details |
|---------|------|---------|
| **Rate Limiting** | express-rate-limit | Global: 100/15min, Login: 5/15min |
| **CORS Policy** | cors | Whitelist approved origins only |
| **API Key Auth** | Custom middleware | X-API-Key header validation |
| **JWT Auth** | jsonwebtoken | Bearer token, 1h expiry, HS256 |
| **CSP Headers** | helmet | default-src 'self'; blocks XSS |
| **HSTS** | helmet | max-age=31536000; preload |
| **Security Logging** | winston | security.log + combined.log |
| **Intrusion Detection** | Fail2Ban config | Auto-ban on repeated failures |

### Security Headers Verified
```
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'...
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
```

---

## ⚔️ Week 5 — Ethical Hacking & Vulnerability Fixes

### Tools Used (Kali Linux)

| Tool | Version | Purpose |
|------|---------|---------|
| WhatWeb | Built-in | Technology fingerprinting & header analysis |
| SQLMap | 1.10.2#stable | SQL injection detection & exploitation |
| Burp Suite | Community | Manual HTTP interception & CSRF testing |
| Ping/Nmap | Built-in | Network reconnaissance |

### SQL Injection — Found & Fixed

**Vulnerable Code (Week 1):**
```javascript
// ❌ String concatenation — INJECTABLE
const query = `SELECT * FROM users WHERE email='${email}'`;
// SQLMap payload: ' OR '1'='1' --
// Result: All users returned — authentication bypassed
```

**Secure Code (Week 5):**
```javascript
// ✅ Prepared statement — SAFE
db.get('SELECT * FROM users WHERE email = ?', [email]);
// SQLMap result: 0 injectable parameters found
```

### CSRF — Found & Fixed

**Attack scenario:** Forged POST request without CSRF token.

**Fix:** `csurf` middleware — every state-changing request requires a valid token:
```javascript
const csrfProtection = csurf({
  cookie: { httpOnly: true, sameSite: 'strict' }
});
// Missing token → HTTP 403 CSRF Token Invalid
```

**Burp Suite test result:** HTTP 403 when X-CSRF-Token header is removed ✅

---

## 🔍 Week 6 — Security Audits & Compliance

### OWASP ZAP 2.17.0 Results

| Risk Level | Count | Details |
|-----------|-------|---------|
| 🔴 High | 0 | No high-risk vulnerabilities |
| 🟡 Medium | 3 | CSP `unsafe-inline` (dashboard requirement) |
| 🔵 Info | 1 | User Agent Fuzzer (rate limiting blocked it) |

**Rate limiting confirmed working:** ZAP fuzzer received HTTP 429 Too Many Requests ✅

### Nikto v2.6.0 Results

```
+ Server: No banner retrieved                     ← X-Powered-By hidden ✅
+ RateLimit-Limit: 100                            ← Rate limiting active ✅
+ 7978 requests: 0 errors and 7 items reported
+ End Time: 2026-03-27 22:45:58 (174 seconds)
+ 1 host(s) tested
```

### Lynis 3.1.6 System Audit

- **Version:** Lynis 3.1.6 on Kali Linux Rolling
- **Kernel:** 6.18.12+kali, x86_64
- **Categories audited:** Boot, Services, Kernel, Memory, Users, Authentication, File Systems, USB, NFS, Ports
- **Log file:** `/var/log/lynis.log` — all 27 plugin categories completed

---

## ✅ OWASP Top 10 Compliance

| # | Risk | Status | Implementation |
|---|------|--------|---------------|
| A01 | Broken Access Control | ✅ | JWT + API Key + Role-based auth |
| A02 | Cryptographic Failures | ✅ | bcrypt(12); HSTS forces HTTPS |
| A03 | Injection | ✅ | Prepared statements; CSP |
| A04 | Insecure Design | ✅ | Secure-by-default architecture |
| A05 | Security Misconfiguration | ✅ | Helmet; no defaults exposed |
| A06 | Vulnerable Components | ✅ | npm audit: 0 vulnerabilities |
| A07 | Auth Failures | ✅ | Rate limit; JWT; bcrypt; CSRF |
| A08 | Data Integrity Failures | ✅ | CSRF tokens; signed cookies |
| A09 | Logging & Monitoring | ✅ | Winston: security.log |
| A10 | SSRF | ✅ | Strict CORS; no outbound requests |

**Result: 10/10 OWASP Top 10 Compliant ✅**

---

## 🚀 Getting Started

```bash
# Clone the repository
git clone (https://github.com/Huzaif251/DHC-Cyber-Security-Internship-Week4-6.git)
cd DHC-Cyber-Security-Internship-Week4-6

# Install dependencies
npm install

# Start the secured server (port 3000)
node server.js

# Optional: Start vulnerable demo server for SQLMap (port 3001)
node vulnerable-server.js
```

Open `http://localhost:3000` to access the security dashboard.

**Default credentials:**
- Email: `admin@dhc.com`
- Password: `Admin@2026`
- API Key: `dhc-apikey-admin-001`

---

## 📡 API Reference

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/api/health` | None | Server status |
| POST | `/auth/signup` | None | Register user |
| POST | `/auth/login` | None (5/15min limit) | Get JWT token |
| GET | `/auth/csrf-token` | None | Fetch CSRF token |
| GET | `/api/headers-check` | None | View security headers |
| GET | `/api/profile` | JWT | User profile |
| GET | `/api/data` | API Key | Protected data |
| GET | `/api/admin` | API Key + JWT | Admin panel |
| POST | `/api/update-profile` | JWT + CSRF | CSRF demo |
| GET | `/api/sqli-demo` | None | SQLi comparison |

---

## 📸 Screenshots Evidence

### Week 5 (Kali Linux)
| # | Screenshot | Tool | Description |
|---|-----------|------|-------------|
| 1 | 21:27 | Ping | Successful connectivity to 192.168.16.104 |
| 2 | 21:40 | WhatWeb | Security headers & technology fingerprint |
| 3 | 21:59 | SQLMap | Version 1.10.2#stable confirmed |
| 4 | 22:00 | SQLMap | Injection found in email parameter |

### Week 6 (Kali Linux)
| # | Screenshot | Tool | Description |
|---|-----------|------|-------------|
| 5 | 22:22 | Tools | Lynis/Docker versions confirmed |
| 6 | 22:23 | OWASP ZAP | ZAP 2.17.0 launched |
| 7 | 22:28 | OWASP ZAP | Automated scan at 37% progress |
| 8 | 22:34 | OWASP ZAP | 4 alerts, response headers shown |
| 9 | 22:35 | OWASP ZAP | HTTP 429 confirming rate limiting |
| 10 | 22:44 | Nikto | Scan in progress |
| 11 | 22:46 | Nikto | Scan complete — 7 items, 0 errors |
| 12-16 | 22:49-50 | Lynis | System audit sections |
| 17 | 22:51 | Lynis | Log file review |

---

## 📂 Project Structure

```
dhc-cybersecurity-week4-6/
├── server.js                    # Main server (Week 5: + CSRF)
├── vulnerable-server.js         # Week 5: SQLMap demo (port 3001)
├── package.json
├── .env
├── config/
│   ├── logger.js                # Winston logging
│   ├── database.js              # SQLite + prepared statements
│   └── fail2ban-jail.conf       # Fail2Ban config
├── middleware/
│   ├── rateLimiter.js           # Week 4: Rate limiting
│   ├── securityHeaders.js       # Week 4: Helmet CSP + HSTS
│   ├── corsConfig.js            # Week 4: CORS whitelist
│   ├── auth.js                  # Week 4: API Key + JWT
│   └── csrfProtection.js        # Week 5: CSRF tokens
├── routes/
│   ├── authRoutes.js            # /auth/* endpoints
│   └── apiRoutes.js             # /api/* endpoints
└── public/
    └── index.html               # Live security dashboard
```

---

