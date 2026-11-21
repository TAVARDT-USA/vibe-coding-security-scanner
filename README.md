# Vibe Coding Security Scanner & AI-Generated App Auditor | TAVARDT USA

[![Licence MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Vibe Coding Security](https://img.shields.io/badge/Vibe%20Coding-Security%20Hardened-00d26a.svg)](README.md)
[![Language](https://img.shields.io/badge/Language-English%20(US)-green.svg)](README.md)
[![Engineering](https://img.shields.io/badge/TAVARDT-Cybersecurity-5b3cf5.svg)](https://ag.tavardt.com/cybersecurity/)

Open-source security scanner auditing live applications built with vibe coding tools (Cursor, Lovable, Bolt, v0). Detects leaked frontend API keys, Supabase RLS gaps, exposed sourcemaps, and sensitive files.

Engineered and maintained by the cybersecurity engineering practice at **[TAVARDT USA](https://ag.tavardt.com/cybersecurity/)**.

---

## 1. Vibe Coding Security Scanner Overview

The rise of AI-assisted engineering and *vibe coding* allows founders to ship working web apps in hours using **Cursor, Lovable.dev, Bolt.new, v0, and Replit**.

However, rapid deployment without perimeter security checks frequently leaks production secrets, unshielded databases, and private intellectual property directly into browser bundles.

This repository provides a fast, dependency-light Python scanner that audits **the live public surface of any deployed web application**, pinpointing critical exposures before malicious actors exploit them.

---

## 2. Audited Vulnerabilities & Attack Vectors

| Risk Vector | How It Happens in Vibe Coding | Technical Impact |
| :--- | :--- | :--- |
| **Frontend API Key Leaks** | Creators place private OpenAI (`sk-...`), Stripe, or AWS keys in client `.env` files or React components. | Any visitor inspects DevTools and drains your paid account balance. |
| **Unprotected Supabase RLS** | Tables are created in Supabase without enabling Row Level Security (RLS). | Since the `anon_key` is public, anyone can dump or wipe tables via REST. |
| **Exposed Production Sourcemaps** | Bundlers (Vite/Next.js) deploy `.js.map` files to public hosting. | Full proprietary source code and backend logic are exposed to reverse engineering. |
| **Leaked Infrastructure Files** | Misconfigured web servers leave `/.env` or `/.git/HEAD` publicly accessible. | Complete compromise of database credentials and private service tokens. |
| **Missing Security Headers** | Absence of CSP, HSTS, and X-Frame-Options policies. | Susceptibility to Clickjacking, cross-site scripting (XSS), and MITM attacks. |

---

## 3. Installation & Execution Guide

### Quick Installation

```bash
git clone https://github.com/TAVARDT-USA/vibe-coding-security-scanner.git
cd vibe-coding-security-scanner
```

### Scan a Live Application URL

```bash
python scanner.py https://your-app.vercel.app
```

### CLI Options

```bash
# Output full structured JSON report
python scanner.py https://your-app.vercel.app --json

# Skip sourcemap extraction
python scanner.py https://your-app.vercel.app --no-sourcemaps
```

---

## 4. Enterprise Hardening & Engineering Support

If your diagnostic revealed leaked credentials, unprotected Supabase/Firebase tables, or requires dedicated perimeter hardening:

* **Corporate Portal:** [TAVARDT USA](https://ag.tavardt.com/cybersecurity/)
* **Direct Technical Contact:** [Contact Engineering Team](https://ag.tavardt.com/contact/)

---

## License

Distributed under the open-source MIT License. Review the [`LICENSE`](LICENSE) file for full terms.  
Copyright (c) 2026 TAVARDT USA.
