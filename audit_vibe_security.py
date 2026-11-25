#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TAVARDT Vibe Coding Security & AI Architecture Auditor (CLI)
Deterministic auditor for frontend bundles, inline SSR scripts, exposed sourcemaps,
HTTP security headers, multi-AI provider secrets, and sensitive environment routes.
Usage: python audit_vibe_security.py https://your-application.com
"""

import sys
import os
import re
import ssl
import time
import json
import base64
from urllib.parse import urlparse, urljoin
import urllib.request
import urllib.error

SECRET_PATTERNS = [
    (re.compile(r'sk-ant-(?:api\d{2}-)?[a-zA-Z0-9_-]{20,}'), 'Anthropic Claude API Key'),
    (re.compile(r'sk-proj-[a-zA-Z0-9_-]{20,}'), 'OpenAI Project API Key'),
    (re.compile(r'sk-svcacct-[a-zA-Z0-9_-]{20,}'), 'OpenAI Service Account Key'),
    (re.compile(r'sk-(?!ant-|proj-|svcacct-|live_|test_)[a-zA-Z0-9_-]{20,}'), 'OpenAI API Key'),
    (re.compile(r'AIza[0-9A-Za-z_-]{35}'), 'Google Gemini / Cloud API Key'),
    (re.compile(r'xai-[a-zA-Z0-9_-]{20,}'), 'xAI Grok API Key'),
    (re.compile(r'gsk_[a-zA-Z0-9]{20,}'), 'Groq API Key'),
    (re.compile(r'hf_[a-zA-Z0-9]{30,}'), 'HuggingFace Access Token'),
    (re.compile(r'pplx-[a-zA-Z0-9]{20,}'), 'Perplexity API Key'),
    (re.compile(r'r8_[a-zA-Z0-9]{20,}'), 'Replicate API Token'),
    (re.compile(r'github_pat_[a-zA-Z0-9_]{22,}'), 'GitHub Fine-Grained / Copilot PAT'),
    (re.compile(r'gh[ousr]_[a-zA-Z0-9]{36}'), 'GitHub OAuth / App Token'),
    (re.compile(r'ghp_[a-zA-Z0-9]{36}'), 'GitHub Classic Personal Token'),
    (re.compile(r'(?:sk|rk)_live_[0-9a-zA-Z]{24,}'), 'Stripe Live Secret Key'),
    (re.compile(r'(?:AKIA|ASIA)[0-9A-Z]{16}'), 'AWS Access Key ID'),
    (re.compile(r're_[a-zA-Z0-9]{24,}'), 'Resend API Key'),
    (re.compile(r'sbp_[a-zA-Z0-9]{30,}'), 'Supabase Management Token')
]

JWT_PATTERN = re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}')


def create_ssl_context():
    ctx = ssl.create_default_context()
    return ctx


def fetch_url(url, timeout=7, user_agent='Mozilla/5.0 (compatible; TAVARDT-Vibe-Auditor/1.1)'):
    ctx = create_ssl_context()
    headers = {
        'User-Agent': user_agent,
        'Accept': '*/*'
    }
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            content = resp.read()
            return {
                'status': resp.status,
                'headers': dict(resp.headers),
                'content': content,
                'error': None
            }
    except urllib.error.HTTPError as e:
        return {
            'status': e.code,
            'headers': dict(e.headers),
            'content': b'',
            'error': str(e)
        }
    except Exception as ex:
        return {
            'status': 0,
            'headers': {},
            'content': b'',
            'error': str(ex)
        }


def is_supabase_service_role_jwt(token):
    """Inspect JWT payload to distinguish public anon keys from privileged service_role keys."""
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return False
        payload_b64 = parts[1]
        padding = '=' * (-len(payload_b64) % 4)
        decoded = base64.urlsafe_b64decode(payload_b64 + padding).decode('utf-8', errors='ignore')
        claims = json.loads(decoded)
        return claims.get('role') == 'service_role'
    except Exception:
        return False


def is_html_fallback(text):
    stripped = text.lstrip()[:200].lower()
    return stripped.startswith('<!doctype html') or stripped.startswith('<html') or '<head>' in stripped


def find_script_urls(html_text, base_url):
    script_pattern = re.compile(r'<script\b[^>]*src=[\'"]([^\'"]+)[\'"]', re.IGNORECASE)
    matches = script_pattern.findall(html_text)
    urls = []
    for m in matches:
        full_url = urljoin(base_url, m)
        urls.append(full_url)
    return list(dict.fromkeys(urls))


def scan_text_for_secrets(text, location, report, quiet=False):
    for pat, sec_name in SECRET_PATTERNS:
        if pat.search(text):
            if not quiet:
                print(f'[CRITICAL] {sec_name} exposed in {location}')
            report['secrets_detected'].append({
                'secret_type': sec_name,
                'location': location
            })
            report['findings'].append({
                'severity': 'CRITICAL',
                'title': f'{sec_name} Exposed in Production Artifact',
                'detail': f'Detected credential pattern ({sec_name}) inside {location}'
            })

    for jwt_token in JWT_PATTERN.findall(text):
        if is_supabase_service_role_jwt(jwt_token):
            if not quiet:
                print(f'[CRITICAL] Supabase Service Role JWT exposed in {location}')
            report['secrets_detected'].append({
                'secret_type': 'Supabase Service Role Key',
                'location': location
            })
            report['findings'].append({
                'severity': 'CRITICAL',
                'title': 'Supabase Service Role JWT Exposed',
                'detail': f'Detected privileged service_role JWT inside {location}'
            })


def audit_vibe_application(target_url, timeout=7, quiet=False):
    report = {
        'target': target_url,
        'timestamp': int(time.time()),
        'findings': [],
        'headers_audit': {},
        'sourcemaps_exposed': [],
        'scripts_audited': 0,
        'secrets_detected': []
    }

    if not quiet:
        print('[*] Starting deterministic perimeter audit on:', target_url)

    # 1. Fetch main page
    root_res = fetch_url(target_url, timeout=timeout)
    if root_res['status'] != 200:
        if not quiet:
            print('[ALERT] Failed to reach root URL HTTP status:', root_res['status'])
        report['findings'].append({
            'severity': 'HIGH',
            'title': 'Root Web Endpoint Unreachable or Blocked',
            'detail': f'Returned HTTP status code: {root_res["status"]}'
        })
        return report

    # 2. Audit Security Headers
    headers = {k.lower(): v for k, v in root_res['headers'].items()}
    report['headers_audit'] = {
        'content_security_policy': 'content-security-policy' in headers,
        'strict_transport_security': 'strict-transport-security' in headers,
        'x_frame_options': 'x-frame-options' in headers,
        'x_content_type_options': 'x-content-type-options' in headers
    }

    if not report['headers_audit']['content_security_policy']:
        report['findings'].append({
            'severity': 'MEDIUM',
            'title': 'Missing Content-Security-Policy Header',
            'detail': 'Absence of CSP directives allows unrestricted third-party script execution.'
        })

    if not report['headers_audit']['x_frame_options'] and not report['headers_audit']['content_security_policy']:
        report['findings'].append({
            'severity': 'LOW',
            'title': 'Missing X-Frame-Options Header',
            'detail': 'Permits rendering of the application inside unauthorized cross-origin iframes.'
        })

    if not report['headers_audit']['strict_transport_security']:
        report['findings'].append({
            'severity': 'LOW',
            'title': 'Missing Strict-Transport-Security (HSTS) Header',
            'detail': 'Allows potential TLS downgrade attacks on initial client connections.'
        })

    # 3. Discover frontend scripts & inspect inline SSR payloads
    try:
        html_text = root_res['content'].decode('utf-8', errors='ignore')
    except Exception:
        html_text = ''

    scan_text_for_secrets(html_text, 'inline HTML/SSR payload', report, quiet=quiet)

    scripts = find_script_urls(html_text, target_url)
    report['scripts_audited'] = len(scripts)
    if not quiet:
        print(f'[*] Frontend script bundles discovered in DOM: {len(scripts)}')

    # 4. Check for sourcemap exposure & secrets in bundles
    for script_url in scripts[:15]:
        clean_script = script_url.split('?')[0]
        if clean_script.endswith('.js'):
            map_url = clean_script + '.map'
            map_res = fetch_url(map_url, timeout=timeout)
            if map_res['status'] == 200 and len(map_res['content']) > 200:
                map_text = map_res['content'].decode('utf-8', errors='ignore')
                if '"sources":' in map_text and '"version":' in map_text:
                    if not quiet:
                        print(f'[CRITICAL] Production sourcemap exposed: {map_url}')
                    report['sourcemaps_exposed'].append(map_url)
                    report['findings'].append({
                        'severity': 'HIGH',
                        'title': 'Publicly Exposed Production Sourcemap (.js.map)',
                        'detail': f'File {map_url} exposes original source code for reverse engineering.'
                    })

        js_res = fetch_url(script_url, timeout=timeout)
        if js_res['status'] == 200:
            js_text = js_res['content'].decode('utf-8', errors='ignore')
            scan_text_for_secrets(js_text, script_url, report, quiet=quiet)

    # 5. Check public env exposure routes (SPA-fallback safe)
    env_probes = ['/.env', '/.env.local', '/.env.production', '/.git/HEAD']
    for p in env_probes:
        p_url = urljoin(target_url, p)
        p_res = fetch_url(p_url, timeout=timeout)
        if p_res['status'] == 200 and len(p_res['content']) > 5:
            body_text = p_res['content'].decode('utf-8', errors='ignore')
            if is_html_fallback(body_text):
                continue
            is_real_leak = False
            if p.startswith('/.env') and re.search(r'^[A-Z][A-Z0-9_]{1,}=.+', body_text, re.MULTILINE):
                is_real_leak = True
            elif p == '/.git/HEAD' and 'ref: ' in body_text:
                is_real_leak = True

            if is_real_leak:
                if not quiet:
                    print(f'[CRITICAL] Exposed sensitive file route: {p_url}')
                report['findings'].append({
                    'severity': 'CRITICAL',
                    'title': f'Sensitive Configuration File Accessible ({p})',
                    'detail': f'Public route {p_url} returned HTTP 200 with environment or repository content.'
                })

    return report


def write_github_summary(rep):
    summary_path = os.environ.get('GITHUB_STEP_SUMMARY')
    if not summary_path:
        return
    try:
        lines = [
            '## TAVARDT Vibe Coding Security Auditor Report',
            f'**Target:** `{rep["target"]}`',
            f'**Scripts Audited:** {rep["scripts_audited"]} | **Sourcemaps Exposed:** {len(rep["sourcemaps_exposed"])} | **Secrets Detected:** {len(rep["secrets_detected"])}',
            ''
        ]
        if not rep['findings']:
            lines.append('No perimeter vulnerabilities or leaked credentials detected.')
        else:
            lines.append('### Security Findings')
            for f in rep['findings']:
                lines.append(f'* **[{f["severity"]}] {f["title"]}**: {f["detail"]}')
        with open(summary_path, 'a', encoding='utf-8') as sf:
            sf.write('\n'.join(lines) + '\n')
    except Exception:
        pass


def print_text_report(rep):
    print('\n' + '=' * 65)
    print('TAVARDT VIBE CODING & AI ARCHITECTURE AUDIT REPORT')
    print('=' * 65)
    print(f'Target Inspected:   {rep["target"]}')
    print(f'Scripts Audited:    {rep["scripts_audited"]}')
    print(f'Sourcemaps Exposed: {len(rep["sourcemaps_exposed"])}')
    print(f'Secrets Detected:   {len(rep["secrets_detected"])}')
    print(f'Total Findings:     {len(rep["findings"])}')
    print('-' * 65)

    if not rep['findings']:
        print('[STATUS] COMPLIANT: No perimeter vulnerabilities detected.')
    else:
        for f in rep['findings']:
            print(f'[{f["severity"]}] {f["title"]}')
            print(f'   Detail: {f["detail"]}')
    print('=' * 65)


def main():
    target = None
    json_mode = False
    strict_mode = False
    timeout = 7

    args = sys.argv[1:]
    i = 0
    while i < len(args):
        a = args[i]
        if a == '-u' and i + 1 < len(args):
            target = args[i + 1]
            i += 2
        elif a == '-t' and i + 1 < len(args):
            try:
                timeout = int(args[i + 1])
            except ValueError:
                timeout = 7
            i += 2
        elif a in ('-j', '-json', '--json'):
            json_mode = True
            i += 1
        elif a in ('-s', '-strict', '--strict'):
            strict_mode = True
            i += 1
        elif not a.startswith('-') and target is None:
            target = a
            i += 1
        else:
            i += 1

    if not target:
        print('Usage: python audit_vibe_security.py https://your-application.com')
        print('Options:')
        print('  -u <url>      Target application URL')
        print('  -t <seconds>  Request timeout in seconds (default: 7)')
        print('  -s            Strict mode (exit code 1 on any finding)')
        print('  -j            Output structured JSON report')
        sys.exit(1)

    if not target.startswith('http://') and not target.startswith('https://'):
        target = 'https://' + target

    rep = audit_vibe_application(target, timeout=timeout, quiet=json_mode)
    write_github_summary(rep)

    if json_mode:
        print(json.dumps(rep, indent=2))
    else:
        print_text_report(rep)

    critical_count = sum(1 for f in rep['findings'] if f['severity'] == 'CRITICAL')
    if critical_count > 0:
        sys.exit(1)
    if strict_mode and rep['findings']:
        sys.exit(1)
    sys.exit(0)


if __name__ == '__main__':
    main()
