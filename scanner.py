"""
TAVARDT Vibe Coding Security Scanner
Perimeter security auditor for live web applications built with AI coding assistants.
Detects leaked frontend keys, unshielded Supabase/Firebase RLS endpoints, exposed sourcemaps, and sensitive files.
"""

import sys
import re
import json
import argparse
import urllib.request
import urllib.error
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

BANNER = """
===================================================================
     TAVARDT Vibe Coding Security Scanner - Live Web Auditor       
  Detects Frontend Secrets, Supabase RLS Gaps, & Exposed Sourcemaps
===================================================================
"""

SECRET_PATTERNS = [
    ("OpenAI API Key", r"sk-[a-zA-Z0-9_-]{20,}"),
    ("OpenAI Project Key", r"sk-proj-[a-zA-Z0-9_-]{20,}"),
    ("Stripe Secret Key", r"sk_live_[0-9a-zA-Z]{24,}"),
    ("AWS Access Key ID", r"AKIA[0-9A-Z]{16}"),
    ("GitHub Personal Token", r"ghp_[a-zA-Z0-9]{36}"),
    ("Resend API Key", r"re_[a-zA-Z0-9]{24,}"),
    ("Slack Webhook URL", r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+"),
    ("Supabase Service Role Key", r"ey[A-Za-z0-9-_=]+\.ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]+")
]

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
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) TAVARDT-Security-Scanner/1.0"}
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as res:
            return res.getcode(), res.read().decode("utf-8", errors="ignore"), dict(res.info())
    except urllib.error.HTTPError as e:
        return e.code, "", {}
    except Exception:
        return None, "", {}

def scan_target(target_url, check_sourcemaps=True):
    findings = []
    risk_score = 0
    parsed_root = urllib.parse.urlparse(target_url)
    base_origin = f"{parsed_root.scheme}://{parsed_root.netloc}"

    print(f"[*] Auditing target: {target_url}...")
    status, html_content, headers = fetch_url(target_url)
    if not status or status >= 400:
        return {"error": f"Unable to reach target URL: {target_url} (HTTP {status})"}

    # 1. Audit Security Headers
    h_lower = {k.lower(): v for k, v in headers.items()}
    if "strict-transport-security" not in h_lower:
        findings.append({"severity": "LOW", "category": "Headers", "issue": "Missing HSTS policy"})
        risk_score += 5
    if "content-security-policy" not in h_lower:
        findings.append({"severity": "MEDIUM", "category": "Headers", "issue": "Missing Content-Security-Policy (CSP)"})
        risk_score += 15
    if "x-frame-options" not in h_lower and "content-security-policy" not in h_lower:
        findings.append({"severity": "LOW", "category": "Headers", "issue": "Missing Clickjacking protection (X-Frame-Options)"})
        risk_score += 10

    # 2. Extract Script URLs
    script_matches = re.findall(r'<script[^>]+src=["']([^"']+)["']', html_content, re.IGNORECASE)
    script_urls = []
    for s in script_matches:
        if s.startswith("//"):
            script_urls.append(f"{parsed_root.scheme}:{s}")
        elif s.startswith("http"):
            script_urls.append(s)
        else:
            script_urls.append(urllib.parse.urljoin(base_origin, s))

    print(f"[*] Found {len(script_urls)} frontend script bundles. Analyzing bundle contents...")

    # 3. Analyze Scripts Concurrently
    def check_script(s_url):
        code, content, _ = fetch_url(s_url)
        if not content:
            return []
        f_list = []
        for name, pattern in SECRET_PATTERNS:
            matches = re.findall(pattern, content)
            if matches:
                # Mask secret
                masked = [m[:8] + "..." + m[-4:] if len(m) > 12 else "***" for m in matches[:2]]
                f_list.append({
                    "severity": "CRITICAL" if "Key" in name or "Token" in name else "HIGH",
                    "category": "Credential Leak",
                    "issue": f"{name} detected in frontend script: {s_url.split('/')[-1]}",
                    "evidence": masked
                })
        # Check for Supabase URL and open RLS
        supabase_matches = re.findall(r"https://[a-z0-9]{20}\.supabase\.co", content)
        if supabase_matches:
            sb_url = supabase_matches[0]
            # Probe unauthenticated REST endpoint
            test_endpoint = f"{sb_url}/rest/v1/users"
            sb_code, sb_body, _ = fetch_url(test_endpoint, timeout=4)
            if sb_code == 200 and "[" in sb_body:
                f_list.append({
                    "severity": "CRITICAL",
                    "category": "Database Security",
                    "issue": "Supabase Row Level Security (RLS) is disabled! Table /rest/v1/users is publicly readable.",
                    "evidence": [sb_url]
                })
        return f_list

    with ThreadPoolExecutor(max_workers=8) as executor:
        for script_findings in executor.map(check_script, script_urls):
            for f in script_findings:
                findings.append(f)
                risk_score += 35 if f["severity"] == "CRITICAL" else 20

    # 4. Check Exposed Sourcemaps
    if check_sourcemaps and script_urls:
        for s_url in script_urls[:5]:
            map_url = f"{s_url}.map"
            m_code, m_content, _ = fetch_url(map_url, timeout=3)
            if m_code == 200 and '"sources":' in m_content:
                findings.append({
                    "severity": "HIGH",
                    "category": "Source Disclosure",
                    "issue": f"Production sourcemap exposed: {map_url.split('/')[-1]} reveals original source files."
                })
                risk_score += 25
                break

    # 5. Check Sensitive Infrastructure Files
    def check_path(path):
        target = urllib.parse.urljoin(base_origin, path)
        c, body, _ = fetch_url(target, timeout=3)
        if c == 200 and ("=" in body or "ref:" in body or "swagger" in body.lower()):
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
        "findings_count": len(findings),
        "findings": findings
    }

def main():
    parser = argparse.ArgumentParser(description="TAVARDT Vibe Coding Security Scanner")
    parser.add_argument("url", help="Target application URL to audit (e.g. https://my-app.vercel.app)")
    parser.add_argument("--json", action="store_true", help="Output audit report as JSON")
    parser.add_argument("--no-sourcemaps", action="store_true", help="Skip sourcemap inspection")
    args = parser.parse_args()

    if not args.json:
        print(BANNER)

    results = scan_target(args.url, check_sourcemaps=not args.no_sourcemaps)

    if args.json:
        print(json.dumps(results, indent=2))
        return

    if "error" in results:
        print(f"[!] Error: {results['error']}")
        sys.exit(1)

    print("
" + "="*67)
    print(f"AUDIT SUMMARY FOR: {results['target']}")
    print(f"OVERALL RISK SCORE: {results['risk_score']}/100 [{results['risk_level']}]")
    print(f"TOTAL FINDINGS: {results['findings_count']}")
    print("="*67)

    if not results["findings"]:
        print("[+] No critical perimeter vulnerabilities identified on public surface.")
    else:
        for idx, f in enumerate(results["findings"], 1):
            print(f"
[{idx}] [{f['severity']}] [{f['category']}] {f['issue']}")
            if "evidence" in f:
                print(f"    Evidence: {f['evidence']}")

    print("
" + "="*67)
    print("Need professional perimeter hardening, RLS lock-down, or backend secret isolation?")
    print("Contact TAVARDT Engineering: https://ag.tavardt.com/cybersecurity/")
    print("="*67 + "
")

if __name__ == "__main__":
    main()
