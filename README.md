<p align="center">
  <a href="https://ag.tavardt.com/">
    <img src="https://ag.tavardt.com/img/tavardt-banner.png" alt="TAVARDT" width="1024" />
  </a>
</p>

# Vibe Coding Security & AI Architecture Auditor

[![Live Demo](https://img.shields.io/badge/Live%20Demo-GitHub%20Pages-5b3cf5.svg)](https://tavardt-usa.github.io/vibe-coding-security-scanner/)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![Security](https://img.shields.io/badge/Security-AI%20Architecture-blue.svg)](https://tavardt-usa.github.io/vibe-coding-security-scanner/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Corporate defensive engineering specification, vulnerability mitigation framework, and deterministic CLI auditing utility for software applications generated with artificial intelligence development assistants (Vibe Coding).

***

## Executive Overview: The Security Reality of Vibe Coding

The paradigm shift toward accelerated AI-assisted programming (utilizing tools such as Cursor, Lovable, v0, Bolt, Windsurf, Replit, Claude Code, and GitHub Copilot) allows engineering teams and solo founders to generate full-stack web applications at unprecedented velocity. However, autonomous code generators optimize primarily for immediate functional completion rather than defensive boundary isolation, least-privilege architecture, or production asset sanitization.

When developers instruct AI models to ship features quickly, the resulting software artifacts consistently inherit systemic architectural vulnerabilities:
* Development configurations leak into production builds without compilation guards.
* Administrative database service keys are mistakenly exposed in public client bundles.
* Relational database tables lack declarative authorization rules (Row Level Security).
* Crucial perimeter defensive headers are omitted from static and dynamic web responses.

This repository provides an enterprise-grade defensive architecture standard, certified configuration blueprints for modern frameworks, and a deterministic local Python CLI auditor (`audit_vibe_security.py`) to systematically identify and neutralize these vulnerabilities before deployment.

***

## Detailed Attack Surface in AI-Generated Applications

### 1. Production Sourcemap Exposure (.js.map)
AI generation tools commonly configure frontend bundling systems (Vite, Webpack, Turbopack, Rollup) with default settings that output full sourcemaps alongside minified JavaScript bundles. When deployed to public content delivery networks (CDNs), these `.js.map` files allow external threat actors to perform full algorithmic deobfuscation:
* Exact restoration of original TypeScript and JavaScript source code.
* Complete visibility into proprietary backend data models, ORM schemas, and interface contracts.
* Exposure of internal administrative API endpoints, hidden routes, and developer comments containing security context.

### 2. Hardcoded AI Provider Secrets and BaaS Service Roles
Because AI coding engines frequently lack context regarding the physical separation between server execution environments and client browsers, secret keys are routinely embedded into frontend files. When environment variables prefixed with `NEXT_PUBLIC_` or `VITE_` are invoked, their literal values are baked directly into static client assets downloaded by any browser:
* OpenAI, Anthropic, and Google Gemini API keys with unrestricted consumption quotas.
* Supabase `service_role` and administrative JWT tokens that completely bypass row-level authorization.
* AWS access keys, Google Cloud API keys, and third-party payment or messaging webhooks.

### 3. Absence of Relational Database Row Level Security (RLS)
Modern AI tools heavily promote Direct-to-Database client architectures using client-side SDKs. While highly productive, AI engines frequently create PostgreSQL tables without issuing `ALTER TABLE ... ENABLE ROW LEVEL SECURITY;`. Without mandatory RLS policies:
* Unauthenticated browser visitors possessing public project URLs can execute direct REST and GraphQL queries.
* Entire user databases, tenant records, personal identifiable information, and payment histories can be dumped through unauthenticated HTTP requests.

### 4. Omission of Core Defensive HTTP Headers
AI-generated server configurations rarely implement mandatory web security headers by default, leaving applications exposed to client-side injection and cross-site framing:
* `Content-Security-Policy` (CSP): Essential to prevent unauthorized remote script execution, malicious telemetry injection, and data exfiltration.
* `Strict-Transport-Security` (HSTS): Enforces encrypted transport and eliminates protocol downgrade attacks.
* `X-Frame-Options` and `X-Content-Type-Options`: Blocks clickjacking overlays and MIME-type sniffing exploits.

### 5. Sensitive Environment Variable Routes
Improperly configured web server root directories frequently leave `.env`, `.env.local`, and `.env.production` files accessible directly over public HTTP endpoints, allowing automated scanners to harvest credentials with single requests.

***

## Deterministic CLI Audit Utility

Browser-based web applications operate under strict sandbox constraints and cross-origin resource sharing (CORS) boundaries, preventing client-side scripts from reading arbitrary headers or scanning third-party endpoints. To deliver verifiable, zero-telemetry technical audits, TAVARDT provides an enterprise Python audit utility designed for terminal execution and automated CI/CD security quality gates.

### Deterministic Audit Workflow

The audit utility (`audit_vibe_security.py`) executes a five-stage defensive inspection:
1. **Root Perimeter Audit:** Establishes TLS socket connection, validates web server response codes, and verifies defensive HTTP security headers.
2. **DOM Script Discovery:** Parses HTML markup to dynamically discover all frontend script bundles imported into the document object model.
3. **Sourcemap Verification:** Probes for exposed `.js.map` files matching each discovered script bundle across public directories.
4. **Compiled Bundle Secret Inspection:** Executes high-precision regular expression scanning against bundle payloads to detect active API keys, Supabase service roles, and cloud tokens.
5. **Environment Route Scanning:** Validates whether critical root environment files (`/.env`, `/.env.local`, `/.env.production`) are blocked or publicly reachable.

### Terminal Usage

Download and execute the audit utility directly against target web endpoints:

```bash
# 1. Download official audit utility from repository
curl -sO https://raw.githubusercontent.com/TAVARDT-USA/vibe-coding-security-scanner/main/audit_vibe_security.py

# 2. Run direct deterministic audit against target application
python audit_vibe_security.py https://your-application.com
```

***

## Certified Production Mitigation Blueprints

This repository includes battle-tested, copy-ready hardening blueprints designed to secure modern AI application stacks:

### Vite Configuration (`vite.config.ts`)
Disables production sourcemaps completely and removes development artifact markers:

```typescript
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  build: {
    sourcemap: false,
    chunkSizeWarningLimit: 1000,
    rollupOptions: {
      output: {
        manualChunks: undefined
      }
    }
  }
});
```

### Next.js Configuration (`next.config.js`)
Suppresses client sourcemap generation and enforces enterprise HTTP headers:

```javascript
/** @type {import('next').NextConfig} */
const nextConfig = {
  productionBrowserSourceMaps: false,
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          { key: 'X-Frame-Options', value: 'DENY' },
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
          { key: 'Strict-Transport-Security', value: 'max-age=63072000; includeSubDomains; preload' }
        ]
      }
    ];
  }
};

module.exports = nextConfig;
```

### Supabase Row Level Security Hardening (`supabase-rls.sql`)
Enforces strict table isolation and revokes unauthenticated data exfiltration paths:

```sql
/* 1. Force Row Level Security across all public schema tables */
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.transactions ENABLE ROW LEVEL SECURITY;

/* 2. Revoke default public execution privileges */
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM anon;

/* 3. Grant strict authenticated read-only access scoped by user identity */
CREATE POLICY "Users can only view own profile" 
ON public.profiles FOR SELECT 
TO authenticated 
USING (auth.uid() = id);
```

### Cloudflare WAF Edge Filtering Rule
Immediate edge rule blocking malicious recon probes targeting sensitive extensions:

```text
(http.request.uri.path contains ".js.map") or 
(http.request.uri.path contains ".env") or 
(http.request.uri.path contains ".git")
Action: Block (Drop incoming connection immediately)
```

***

## Frequently Asked Questions (Technical & Architecture FAQ)

### What specific security risks arise from Vibe Coding and AI software generators?
AI models generate code based on statistical pattern matching rather than architectural risk modeling. They routinely place secret API keys in client components, neglect to enable database row level security, and leave frontend bundler debugging flags enabled, exposing business logic and credentials to public extraction.

### Why is publishing sourcemaps to production environments dangerous?
Sourcemap files contain the exact inverse mapping of minified bundles back to original source code. Publishing `.js.map` files enables attackers to reconstruct full application source code, review database schemas, locate unauthenticated endpoints, and identify logic vulnerabilities with zero effort.

### How should frontend applications consume AI APIs securely?
Frontend applications must never communicate directly with AI provider APIs using administrative tokens. All AI interactions must be proxied through secure backend API routes or serverless edge functions that validate authenticated user sessions, enforce rate limits, and inject secrets securely on the server side.

### Does the deterministic Python auditor disrupt live production services?
No. The CLI utility operates strictly as a read-only passive diagnostic inspector. It transmits standard HTTP GET and HEAD requests to discover public scripts, headers, and exposed files, evaluating security posture without altering host states or degrading performance.

***

## Compliance Frameworks & Enterprise Standards

Defensive architecture and cybersecurity controls aligned with NIST SP 800-53, CMMC 2.0, SOC 2 Type II, and Federal Cybersecurity Standards.

***

## Useful Links

* **Corporate Portal:** https://ag.tavardt.com/
* **Diagnostic Suite:** https://tools.tavardt.com/
* **Technical Contact:** https://ag.tavardt.com/contact/

***

## Governance and Sovereignty

* **Sovereign Unit**: **TAVARDT United States** (`TAVARDT-USA`)
* **Diagnostic Portal**: **TAVARDT US Diagnostic Suite**
* **Enterprise Security**: [TAVARDT US Cybersecurity](https://ag.tavardt.com/cybersecurity/)

***

### License
Released under the MIT License. See [LICENSE](LICENSE) for full details.

***

© 2026 TAVARDT. All rights reserved.
