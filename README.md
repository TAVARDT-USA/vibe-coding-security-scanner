# TAVARDT Vibe Coding Security & AI Architecture Auditor (USA)

Corporate defensive architecture guide, credential leakage mitigation, and deterministic CLI auditing utility for applications built with AI development tools (Vibe Coding).

## Threat Surface in AI-Generated Applications

Accelerated AI-assisted development (Cursor, Lovable, v0, Bolt) introduces three prevalent architectural vulnerabilities:

1. **Sourcemap Leaks (.js.map):** Production builds that retain sourcemap files enable complete deobfuscation and reverse-engineering of original TypeScript business logic and backend models.
2. **Exposing AI Model Secrets in Client Bundles:** OpenAI, Anthropic, or Supabase `service_role` tokens prefixed with `NEXT_PUBLIC_` or `VITE_` are burned directly into static client assets downloaded by any browser.
3. **Absence of Row Level Security (RLS):** Relational databases queried directly via REST/GraphQL endpoints without active RLS policies allow unauthenticated or unauthorized third parties to dump entire tables.

***

## Official CLI Audit Tool

To bypass browser sandbox constraints and CORS enforcement, TAVARDT provides an enterprise Python audit utility for direct socket inspection via terminal or CI/CD pipelines:

```bash
# 1. Download official audit utility from repository
curl -sO https://raw.githubusercontent.com/TAVARDT-USA/vibe-coding-security-scanner/main/audit_vibe_security.py

# 2. Run direct audit against your target application
python audit_vibe_security.py https://your-application.com
```

### Key Inspection Capabilities

* **Sourcemap Audit:** Automated scanning across standardized build directories to detect exposed `.js.map` files.
* **HTTP Header Inspection:** Rigorous validation of `Content-Security-Policy`, `Strict-Transport-Security`, `X-Content-Type-Options`, and `X-Frame-Options` headers.
* **Compiled Secret Detection:** High-fidelity regex scanning to identify AI provider keys and administrative credentials embedded within production JavaScript bundles.

***

## Defensive Mitigation Blueprints

This repository includes certified production blueprints to harden your application stack:

* **Vite (`vite.config.ts`):** Complete deactivation of production sourcemaps and bundle chunk sanitization.
* **Next.js (`next.config.js`):** `productionBrowserSourceMaps` deactivation and enterprise defensive header enforcement.
* **Supabase SQL (`supabase-rls.sql`):** Mandatory `ROW LEVEL SECURITY` activation across public schemas and complete revocation of unauthenticated `anon` table permissions.
* **Cloudflare WAF:** Perimeter rules to instantly block incoming probes targeting `.js.map`, `.env`, and `.git` files.

***

## Compliance Frameworks & Enterprise Standards

Defensive architecture and cybersecurity controls aligned with NIST SP 800-53, CMMC 2.0, SOC 2 Type II, and Federal Cybersecurity Standards.

***

## Official Links & Resources

* **Live Hub:** [https://tavardt-usa.github.io/vibe-coding-security-scanner/](https://tavardt-usa.github.io/vibe-coding-security-scanner/)
* **TAVARDT Portal:** [https://ag.tavardt.com/us/](https://ag.tavardt.com/us/)
* **Cybersecurity Tools:** [https://tools.tavardt.com/us/](https://tools.tavardt.com/us/)

&copy; 2026 TAVARDT. All rights reserved.
