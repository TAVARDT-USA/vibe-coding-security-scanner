#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TAVARDT Vibe Coding Security & AI Architecture Auditor (CLI)
Auditoria deterministica de bundles, sourcemaps e cabecalhos de seguranca.
Uso: python audit_vibe_security.py https://sua-aplicacao.com
"""

import sys
import os
import re
import ssl
import time
import json
import urllib.request
import urllib.error
from urllib.parse import urlparse, urljoin

def create_ssl_context():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

def fetch_url(url, timeout=7, user_agent='TAVARDT-Vibe-Auditor/1.0'):
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
                'url': resp.geturl()
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

def find_script_urls(html_text, base_url):
    script_pattern = re.compile(r'<script\b[^>]*src=[\'"]([^\'"]+)[\'"]', re.IGNORECASE)
    matches = script_pattern.findall(html_text)
    urls = []
    for m in matches:
        full_url = urljoin(base_url, m)
        urls.append(full_url)
    return list(dict.fromkeys(urls))

def audit_vibe_application(target_url, timeout=7):
    report = {
        'target': target_url,
        'timestamp': int(time.time()),
        'findings': [],
        'headers_audit': {},
        'sourcemaps_exposed': [],
        'scripts_audited': 0,
        'secrets_detected': []
    }

    print('[*] Iniciando auditoria deterministica em:', target_url)
    
    # 1. Fetch main page
    root_res = fetch_url(target_url, timeout=timeout)
    if root_res['status'] != 200:
        print('[ALERTA] Falha ao acessar raiz HTTP status:', root_res['status'])
        report['findings'].append({
            'severity': 'ALTA',
            'title': 'Raiz Web Inacessivel ou Bloqueada',
            'detail': f'Codigo HTTP retornado: {root_res["status"]}'
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
            'severity': 'MEDIA',
            'title': 'Cabecalho Content-Security-Policy Ausente',
            'detail': 'Ausencia de diretivas CSP permite execucao irrestrita de scripts de terceiros.'
        })

    if not report['headers_audit']['x_frame_options']:
        report['findings'].append({
            'severity': 'BAIXA',
            'title': 'Cabecalho X-Frame-Options Ausente',
            'detail': 'Permite renderizacao da aplicacao em iframes alheios sem bloqueio SAMEORIGIN.'
        })

    # 3. Discover frontend scripts
    try:
        html_text = root_res['content'].decode('utf-8', errors='ignore')
    except Exception:
        html_text = ''

    scripts = find_script_urls(html_text, target_url)
    report['scripts_audited'] = len(scripts)
    print(f'[*] Scripts frontend localizados no DOM: {len(scripts)}')

    # 4. Check for sourcemap exposure on bundles
    secret_patterns = [
        (re.compile(r'sk-[a-zA-Z0-9_-]{20,}'), 'Chave OpenAI API exposta'),
        (re.compile(r'sbp_[a-zA-Z0-9]{30,}'), 'Chave Supabase Service Role exposta'),
        (re.compile(r'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'), 'Token JWT com potencial service_role'),
        (re.compile(r'AKIA[0-9A-Z]{16}'), 'Chave de Acesso AWS exposta'),
        (re.compile(r'AIza[0-9A-Za-z\\-_]{35}'), 'Chave Google API exposta')
    ]

    for script_url in scripts[:12]:
        # Sourcemap check
        map_url = script_url + '.map'
        map_res = fetch_url(map_url, timeout=timeout)
        if map_res['status'] == 200 and len(map_res['content']) > 200:
            print(f'[CRITICO] Sourcemap de producao exposto: {map_url}')
            report['sourcemaps_exposed'].append(map_url)
            report['findings'].append({
                'severity': 'CRITICA',
                'title': 'Sourcemap de Producao Exposto Publicamente (.js.map)',
                'detail': f'O arquivo {map_url} expoe o codigo fonte original completo para engenharia reversa.'
            })

        # Bundle secret scanning
        js_res = fetch_url(script_url, timeout=timeout)
        if js_res['status'] == 200:
            js_text = js_res['content'].decode('utf-8', errors='ignore')
            for pat, sec_name in secret_patterns:
                if pat.search(js_text):
                    print(f'[ALERTA MAXIMO] {sec_name} no bundle: {script_url}')
                    report['secrets_detected'].append({
                        'secret_type': sec_name,
                        'bundle_url': script_url
                    })
                    report['findings'].append({
                        'severity': 'CRITICA',
                        'title': f'{sec_name} no Bundle de Producao',
                        'detail': f'Detectada presenca de padrao credencial no arquivo {script_url}'
                    })

    # 5. Check public env exposure routes
    env_probes = ['/.env', '/.env.local', '/.env.production']
    for p in env_probes:
        p_url = urljoin(target_url, p)
        p_res = fetch_url(p_url, timeout=timeout)
        if p_res['status'] == 200 and len(p_res['content']) > 10:
            print(f'[CRITICO] Rota de arquivo de ambiente exposta: {p_url}')
            report['findings'].append({
                'severity': 'CRITICA',
                'title': 'Arquivo de Variaveis de Ambiente Acessivel (.env)',
                'detail': f'Rota publica {p_url} retornou HTTP 200 com conteudo.'
            })

    return report

def print_text_report(rep):
    print('\n' + '=' * 65)
    print('TAVARDT VIBE CODING & AI ARCHITECTURE AUDIT REPORT')
    print('=' * 65)
    print(f'Alvo Inspecionado: {rep["target"]}')
    print(f'Scripts Analisados: {rep["scripts_audited"]}')
    print(f'Sourcemaps Expostos: {len(rep["sourcemaps_exposed"])}')
    print(f'Segredos Detectados: {len(rep["secrets_detected"])}')
    print(f'Total de Achados: {len(rep["findings"])}')
    print('-' * 65)
    
    if not rep['findings']:
        print('[STATUS] CONFORME: Nenhuma fragilidade perimetral detectada.')
    else:
        for f in rep['findings']:
            print(f'[{f["severity"]}] {f["title"]}')
            print(f'   Detalhe: {f["detail"]}')
    print('=' * 65)

def main():
    target = None
    json_mode = False
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
        elif a == '-j':
            json_mode = True
            i += 1
        elif not a.startswith('-') and target is None:
            target = a
            i += 1
        else:
            i += 1

    if not target:
        print('Uso: python audit_vibe_security.py https://sua-aplicacao.com')
        print('Parametros:')
        print('  -u <url>      URL da aplicacao alvo')
        print('  -t <segundos> Timeout de requisicao (padrao: 7)')
        print('  -j            Saida estruturada em formato JSON')
        sys.exit(1)

    if not target.startswith('http://') and not target.startswith('https://'):
        target = 'https://' + target

    rep = audit_vibe_application(target, timeout=timeout)

    if json_mode:
        print(json.dumps(rep, indent=2))
    else:
        print_text_report(rep)

if __name__ == '__main__':
    main()
