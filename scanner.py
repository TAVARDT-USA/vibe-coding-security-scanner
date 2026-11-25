#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TAVARDT Vibe Coding Security Scanner
Perimeter security auditor for live web applications built with AI coding assistants.
Detects leaked multi-AI API keys (OpenAI, Anthropic Claude, Google Gemini, xAI Grok,
Groq, HuggingFace, Perplexity), GitHub/Copilot tokens, unshielded Supabase RLS endpoints,
exposed sourcemaps, and sensitive environment files without SPA false positives.
"""

import os
import sys
import re
import json
import base64
import argparse
import urllib.request
import urllib.error
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

BANNER = """
===================================================================
     TAVARDT Vibe Coding Security Scanner - Live Web Auditor
  AI Secrets (Claude/Gemini/OpenAI/Grok), RLS & Sourcemap Scanner
===================================================================
"""

SECRET_PATTERNS = [
    ("Anthropic Claude API Key", r"sk-ant-(?:api\d{2}-)?[a-zA-Z0-9_-]{20,}"),
    ("OpenAI Project API Key", r"sk-proj-[a-zA-Z0-9_-]{20,}"),
    ("OpenAI Service Account Key", r"sk-svcacct-[a-zA-Z0-9_-]{20,}"),
    ("OpenAI API Key", r"sk-(?!ant-|proj-|svcacct-|live_|test_)[a-zA-Z0-9_-]{20,}"),
    ("Google Gemini / Cloud API Key", r"AIza[0-9A-Za-z_-]{35}"),
    ("xAI Grok API Key", r"xai-[a-zA-Z0-9_-]{20,}"),
    ("Groq API Key", r"gsk_[a-zA-Z0-9]{20,}"),
    ("HuggingFace Access Token", r"hf_[a-zA-Z0-9]{30,}"),
    ("Perplexity API Key", r"pplx-[a-zA-Z0-9]{20,}"),
    ("Replicate API Token", r"r8_[a-zA-Z0-9]{20,}"),
    ("GitHub Fine-Grained / Copilot PAT", r"github_pat_[a-zA-Z0-9_]{22,}"),
    ("GitHub OAuth / App Token", r"gh[ousr]_[a-zA-Z0-9]{36}"),
    ("GitHub Classic Personal Token", r"ghp_[a-zA-Z0-9]{36}"),
    ("Stripe Live Secret Key", r"(?:sk|rk)_live_[0-9a-zA-Z]{24,}"),
    ("AWS Access Key ID", r"(?:AKIA|ASIA)[0-9A-Z]{16}"),
    ("Resend API Key", r"re_[a-zA-Z0-9]{24,}"),
    ("Slack Webhook URL", r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+"),
    ("Supabase Management Token", r"sbp_[a-zA-Z0-9]{30,}")
]

JWT_PATTERN = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")

SENSITIVE_PATHS = [
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.git/HEAD",
    "/.git/config",
    "/swagger.json",
    "/api/swagger.json",
    "/docker-compose.yml"
]


def fetch_url(url, timeout=7):
    headers = {"User-Agent": "Mozilla/5.0 (compatible; TAVARDT-Vibe-Scanner/1.1)"}
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as res:
            return res.getcode(), res.read().decode("utf-8", errors="ignore"), dict(res.info())
    except urllib.error.HTTPError as e:
        return e.code, "", {}
    except Exception:
        return None, "", {}


def is_supabase_service_role_jwt(token):
    """Safely inspect JWT payload to distinguish public anon keys from leaked service_role keys."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return False
        payload_b64 = parts[1]
        padding = "=" * (-len(payload_b64) % 4)
        decoded = base64.urlsafe_b64decode(payload_b64 + padding).decode("utf-8", errors="ignore")
        claims = json.loads(decoded)
        return claims.get("role") == "service_role"
    except Exception:
        return False


def is_html_fallback(body):
    stripped = body.lstrip()[:200].lower()
    return stripped.startswith("<!doctype html") or stripped.startswith("<html") or "<head>" in stripped


def validate_sensitive_body(path, body):
    if not body or len(body.strip()) < 5 or is_html_fallback(body):
        return False
    if path.startswith("/.env"):
        return bool(re.search(r"^[A-Z][A-Z0-9_]{1,}=.+", body, re.MULTILINE))
    if path == "/.git/HEAD":
        return "ref: " in body
    if path == "/.git/config":
        return "[core]" in body or "[remote" in body
    if "swagger.json" in path:
        return '"openapi"' in body or '"swagger"' in body
    if path == "/docker-compose.yml":
        return "services:" in body
    return False


def scan_payload_for_secrets(content, source_label):
    findings = []
    for name, pattern in SECRET_PATTERNS:
        matches = re.findall(pattern, content)
        if matches:
            masked = [m[:8] + "..." + m[-4:] if len(m) > 12 else "***" for m in matches[:2]]
            findings.append({
                "severity": "CRITICAL",
                "category": "Credential Leak",
                "issue": f"{name} detected in {source_label}",
                "evidence": masked
            })

    jwt_matches = JWT_PATTERN.findall(content)
    service_roles = [t for t in jwt_matches if is_supabase_service_role_jwt(t)]
    if service_roles:
        masked = [t[:10] + "..." + t[-6:] for t in service_roles[:2]]
        findings.append({
            "severity": "CRITICAL",
            "category": "Credential Leak",
            "issue": f"Supabase Service Role Key (privileged JWT) detected in {source_label}",
            "evidence": masked
        })
    return findings


def scan_target(target_url, check_sourcemaps=True, timeout=7, quiet=False):
    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        target_url = "https://" + target_url

    findings = []
    risk_score = 0
    parsed_root = urllib.parse.urlparse(target_url)
    base_origin = f"{parsed_root.scheme}://{parsed_root.netloc}"

    if not quiet:
        print(f"[*] Auditing target: {target_url}...")
    status, html_content, headers = fetch_url(target_url, timeout=timeout)
    if not status or status >= 400:
        return {"error": f"Unable to reach target URL: {target_url} (HTTP {status})"}

    # 1. Audit Security Headers
    h_lower = {k.lower(): v for k, v in headers.items()}
    if "strict-transport-security" not in h_lower:
        findings.append({"severity": "LOW", "category": "Headers", "issue": "Missing HSTS policy (Strict-Transport-Security)"})
        risk_score += 5
    if "content-security-policy" not in h_lower:
        findings.append({"severity": "MEDIUM", "category": "Headers", "issue": "Missing Content-Security-Policy (CSP)"})
        risk_score += 15
    if "x-frame-options" not in h_lower and "content-security-policy" not in h_lower:
        findings.append({"severity": "LOW", "category": "Headers", "issue": "Missing Clickjacking protection (X-Frame-Options)"})
        risk_score += 10
    if "x-content-type-options" not in h_lower:
        findings.append({"severity": "LOW", "category": "Headers", "issue": "Missing X-Content-Type-Options (nosniff)"})
        risk_score += 5

    # 2. Scan inline scripts and SSR payloads directly in HTML
    inline_findings = scan_payload_for_secrets(html_content, "inline HTML/SSR payload")
    for f in inline_findings:
        findings.append(f)
        risk_score += 35

    # 3. Extract External Script URLs
    script_matches = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html_content, re.IGNORECASE)
    script_urls = []
    for s in script_matches:
        if s.startswith("//"):
            script_urls.append(f"{parsed_root.scheme}:{s}")
        elif s.startswith("http"):
            script_urls.append(s)
        else:
            script_urls.append(urllib.parse.urljoin(base_origin, s))
    script_urls = list(dict.fromkeys(script_urls))

    if not quiet:
        print(f"[*] Found {len(script_urls)} frontend script bundles. Analyzing bundle contents...")

    # 4. Analyze Scripts Concurrently
    tested_supabase = set()

    def check_script(s_url):
        _, content, _ = fetch_url(s_url, timeout=timeout)
        if not content:
            return []
        label = f"frontend script: {s_url.split('/')[-1].split('?')[0]}"
        f_list = scan_payload_for_secrets(content, label)

        supabase_matches = re.findall(r"https://[a-z0-9]{20}\.supabase\.co", content)
        for sb_url in supabase_matches:
            if sb_url not in tested_supabase:
                tested_supabase.add(sb_url)
                test_endpoint = f"{sb_url}/rest/v1/users"
                sb_code, sb_body, _ = fetch_url(test_endpoint, timeout=4)
                if sb_code == 200 and sb_body.strip().startswith("["):
                    f_list.append({
                        "severity": "CRITICAL",
                        "category": "Database Security",
                        "issue": "Supabase Row Level Security (RLS) is misconfigured! Table /rest/v1/users is publicly readable.",
                        "evidence": [sb_url]
                    })
        return f_list

    with ThreadPoolExecutor(max_workers=8) as executor:
        for script_findings in executor.map(check_script, script_urls[:20]):
            for f in script_findings:
                findings.append(f)
                risk_score += 35

    # 5. Check Exposed Sourcemaps
    if check_sourcemaps and script_urls:
        for s_url in script_urls[:8]:
            clean_s = s_url.split("?")[0]
            if not clean_s.endswith(".js"):
                continue
            map_url = f"{clean_s}.map"
            m_code, m_content, _ = fetch_url(map_url, timeout=4)
            if m_code == 200 and '"sources":' in m_content and '"version":' in m_content:
                findings.append({
                    "severity": "HIGH",
                    "category": "Source Disclosure",
                    "issue": f"Production sourcemap exposed: {map_url.split('/')[-1]} reveals original source code."
                })
                risk_score += 25
                break

    # 6. Check Sensitive Infrastructure Files
    def check_path(path):
        target = urllib.parse.urljoin(base_origin, path)
        c, body, _ = fetch_url(target, timeout=4)
        if c == 200 and validate_sensitive_body(path, body):
            return {
                "severity": "CRITICAL",
                "category": "Exposed Files",
                "issue": f"Sensitive file publicly accessible at {path}"
            }
        return None

    with ThreadPoolExecutor(max_workers=4) as executor:
        for res in executor.map(check_path, SENSITIVE_PATHS):
            if res:
                findings.append(res)
                risk_score += 40

    risk_score = min(100, risk_score)
    return {
        "target": target_url,
        "risk_score": risk_score,
        "risk_level": "CRITICAL" if risk_score >= 60 else "HIGH" if risk_score >= 35 else "MEDIUM" if risk_score > 0 else "LOW",
        "scripts_audited": len(script_urls),
        "findings_count": len(findings),
        "findings": findings
    }


def write_github_summary(results):
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return
    try:
        lines = [
            "## TAVARDT Vibe Coding Security Scanner Report",
            f"**Target:** `{results['target']}`",
            f"**Risk Score:** `{results['risk_score']}/100` (`{results['risk_level']}`)",
            f"**Scripts Audited:** {results['scripts_audited']} | **Total Findings:** {results['findings_count']}",
            ""
        ]
        if not results["findings"]:
            lines.append("No critical perimeter vulnerabilities identified on public surface.")
        else:
            lines.append("### Detected Security Findings")
            for f in results["findings"]:
                lines.append(f"* **[{f['severity']}] {f['category']}**: {f['issue']}")
        with open(summary_path, "a", encoding="utf-8") as sf:
            sf.write("\n".join(lines) + "\n")
    except Exception:
        pass


def main():
    parser = argparse.ArgumentParser(description="TAVARDT Vibe Coding Security Scanner")
    parser.add_argument("url", help="Target application URL to audit (e.g. https://your-application.com)")
    parser.add_argument("-j", "-json", "--json", dest="json", action="store_true", help="Output audit report as JSON")
    parser.add_argument("-s", "-strict", "--strict", dest="strict", action="store_true", help="Exit with code 1 if any finding is detected")
    parser.add_argument("-t", "--timeout", type=int, default=7, help="HTTP request timeout in seconds (default: 7)")
    parser.add_argument("--no-sourcemaps", action="store_true", help="Skip sourcemap inspection")
    args = parser.parse_args()

    if not args.json:
        print(BANNER)

    results = scan_target(args.url, check_sourcemaps=not args.no_sourcemaps, timeout=args.timeout, quiet=args.json)

    if "error" in results:
        if args.json:
            print(json.dumps(results, indent=2))
        else:
            print(f"[!] Error: {results['error']}")
        sys.exit(1)

    write_github_summary(results)

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print("\n" + "=" * 67)
        print(f"AUDIT SUMMARY FOR: {results['target']}")
        print(f"OVERALL RISK SCORE: {results['risk_score']}/100 [{results['risk_level']}]")
        print(f"SCRIPTS AUDITED: {results['scripts_audited']} | TOTAL FINDINGS: {results['findings_count']}")
        print("=" * 67)

        if not results["findings"]:
            print("[+] No critical perimeter vulnerabilities identified on public surface.")
        else:
            for idx, f in enumerate(results["findings"], 1):
                print(f"\n[{idx}] [{f['severity']}] [{f['category']}] {f['issue']}")
                if "evidence" in f:
                    print(f"    Evidence: {f['evidence']}")

        print("\n" + "=" * 67)
        print("TAVARDT Cybersecurity Engineering: https://ag.tavardt.com/")
        print("=" * 67 + "\n")

    critical_count = sum(1 for f in results["findings"] if f["severity"] == "CRITICAL")
    if critical_count > 0:
        sys.exit(1)
    if args.strict and results["findings_count"] > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
