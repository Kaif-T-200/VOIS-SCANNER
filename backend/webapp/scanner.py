import asyncio
import re
import aiohttp
from typing import Optional

TECH_SIGNATURES = {
    'WordPress': {'body': [r'wp-content', r'wp-includes'], 'cookies': ['wp-settings']},
    'Joomla': {'body': [r'joomla', r'/media/jui/'], 'cookies': []},
    'Drupal': {'headers': {'X-Generator': 'Drupal'}, 'body': [r'drupal']},
    'Magento': {'body': [r'magento', r'/static/frontend/']},
    'Shopify': {'headers': {'X-Powered-By': 'Shopify'}, 'body': [r'cdn\.shopify\.com']},
    'React': {'body': [r'react', r'__REACT_DEVTOOLS_GLOBAL_HOOK__']},
    'Angular': {'body': [r'ng-app', r'angular', r'ng-version']},
    'Vue.js': {'body': [r'vue', r'__VUE_DEVTOOLS_GLOBAL_HOOK__', r'data-v-']},
    'jQuery': {'body': [r'jquery', r'jQuery']},
    'Bootstrap': {'body': [r'bootstrap']},
    'Laravel': {'body': [r'laravel'], 'cookies': ['laravel_session']},
    'Django': {'body': [r'django'], 'cookies': ['csrftoken']},
    'Flask': {'cookies': ['session']},
    'Express': {'headers': {'X-Powered-By': 'Express'}},
    'Ruby on Rails': {'headers': {'X-Runtime': True}, 'cookies': ['_session_id']},
    'Spring Boot': {'body': [r'whitelabel error page']},
    'ASP.NET': {'headers': {'X-AspNet-Version': True}, 'body': [r'__VIEWSTATE']},
    'PHP': {'headers': {'X-Powered-By': 'PHP'}, 'cookies': ['PHPSESSID']},
    'Nginx': {'headers': {'Server': 'nginx'}},
    'Apache': {'headers': {'Server': 'Apache'}},
    'IIS': {'headers': {'Server': 'Microsoft-IIS'}},
    'Cloudflare': {'headers': {'Server': 'cloudflare', 'CF-RAY': True}},
    'AWS CloudFront': {'headers': {'Server': 'CloudFront'}},
    'Vercel': {'headers': {'Server': 'Vercel'}},
    'Netlify': {'headers': {'Server': 'Netlify'}},
    'Google Analytics': {'body': [r'google-analytics\.com', r'googletagmanager\.com']},
    'reCAPTCHA': {'body': [r'recaptcha', r'g-recaptcha']},
    'Stripe': {'body': [r'stripe\.com']},
    'Sentry': {'body': [r'sentry\.io', r'Sentry\.init']},
    'Jenkins': {'body': [r'jenkins', r'Jenkins']},
    'GitLab': {'body': [r'gitlab', r'GitLab']},
    'Grafana': {'body': [r'grafana', r'Grafana']},
    'Kibana': {'body': [r'kibana', r'Kibana']},
    'Elasticsearch': {'body': [r'You Know, for Search']},
    'Next.js': {'headers': {'x-powered-by': 'Next.js'}, 'body': [r'__NEXT_DATA__']},
    'Nuxt.js': {'body': [r'__NUXT__']},
    'Gatsby': {'body': [r'gatsby', r'Gatsby']},
    'Ghost': {'body': [r'ghost\.org', r'Ghost']},
    'Hugo': {'body': [r'gohugo\.io', r'Powered by Hugo']},
    'Jekyll': {'body': [r'jekyll', r'Jekyll']},
    'Docusaurus': {'body': [r'docusaurus', r'Docusaurus']},
    'Moodle': {'body': [r'moodle', r'Moodle']},
    'Jira': {'body': [r'jira', r'Jira']},
    'Confluence': {'body': [r'confluence', r'Confluence']},
    'Notion': {'body': [r'notion\.so']},
    'HubSpot': {'body': [r'hubspot', r'HubSpot']},
    'Salesforce': {'body': [r'salesforce', r'Salesforce']},
    'Mailchimp': {'body': [r'mailchimp']},
    'Klaviyo': {'body': [r'klaviyo']},
}

SENSITIVE_PATHS = [
    '/admin', '/administrator', '/login', '/wp-admin', '/wp-login.php',
    '/phpmyadmin', '/pma', '/cpanel', '/webmail',
    '/api', '/api/v1', '/api/v2', '/graphql',
    '/.env', '/.git', '/.git/config', '/.svn',
    '/backup', '/backup.sql', '/dump.sql', '/db.sql',
    '/config', '/config.php', '/config.yml', '/config.json',
    '/robots.txt', '/sitemap.xml',
    '/server-status', '/server-info', '/status',
    '/info.php', '/phpinfo.php', '/test.php',
    '/console', '/debug', '/actuator', '/actuator/health',
    '/swagger', '/swagger-ui.html', '/api-docs', '/openapi.json',
    '/jenkins', '/solr', '/kibana', '/grafana',
    '/nagios', '/zabbix', '/prometheus',
    '/manager', '/manager/html', '/host-manager',
    '/xmlrpc.php', '/wp-json/wp/v2/users',
    '/.htaccess', '/.htpasswd',
    '/wp-config.php.bak', '/wp-config.php.old',
    '/.bash_history', '/.ssh/authorized_keys',
    '/Thumbs.db', '/Desktop.ini',
    '/elmah.axd', '/trace.axd',
    '/.well-known/security.txt',
    '/.well-known/assetlinks.json',
    '/crossdomain.xml', '/clientaccesspolicy.xml',
]

XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    "'\"><script>alert(1)</script>",
    "javascript:alert(1)",
]

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR 1=1 --",
    "admin' --",
    "' UNION SELECT NULL --",
    "1' AND SLEEP(5)--",
]


class WebAppScanner:
    def __init__(self, target: str, timeout: float = 5.0):
        self.target = target
        self.timeout = timeout
        self.base_url = target if target.startswith('http') else f'http://{target}'

    async def detect_tech(self) -> list:
        detected = []
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(self.base_url, timeout=aiohttp.ClientTimeout(total=self.timeout), ssl=False) as resp:
                    headers = dict(resp.headers)
                    body = await resp.text(errors='replace')
                    cookies = set(headers.get('Set-Cookie', '').lower().split(';'))
                    for tech, sigs in TECH_SIGNATURES.items():
                        score = 0
                        for hdr, val in sigs.get('headers', {}).items():
                            hdr_val = headers.get(hdr, '')
                            if val is True and hdr_val or (isinstance(val, str) and val.lower() in hdr_val.lower()):
                                score += 3
                        for pattern in sigs.get('body', []):
                            if re.search(pattern, body, re.IGNORECASE):
                                score += 2
                        for cookie in sigs.get('cookies', []):
                            if any(cookie.lower() in c for c in cookies):
                                score += 2
                        if score > 0:
                            detected.append({'tech': tech, 'confidence': min(score * 10, 100)})
        except Exception:
            pass
        return sorted(detected, key=lambda x: x['confidence'], reverse=True)

    async def brute_dirs(self, paths: list = None) -> list:
        paths = paths or SENSITIVE_PATHS
        found = []
        async with aiohttp.ClientSession() as session:
            async def check(path):
                try:
                    url = f"{self.base_url.rstrip('/')}{path}"
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=3), allow_redirects=False, ssl=False) as resp:
                        if resp.status in (200, 301, 302, 403):
                            return {'path': path, 'status': resp.status, 'url': url}
                except:
                    pass
                return None
            tasks = [asyncio.create_task(check(p)) for p in paths]
            for coro in asyncio.as_completed(tasks):
                result = await coro
                if result:
                    found.append(result)
        return found

    async def check_xss(self, params: list = None) -> list:
        params = params or ['q', 'search', 'query', 's', 'keyword', 'id']
        findings = []
        async with aiohttp.ClientSession() as session:
            for param in params:
                for payload in XSS_PAYLOADS:
                    try:
                        url = f"{self.base_url}?{param}={payload}"
                        async with session.get(url, timeout=aiohttp.ClientTimeout(total=5), ssl=False) as resp:
                            body = await resp.text(errors='replace')
                            if payload in body:
                                findings.append({'type': 'xss', 'param': param, 'payload': payload, 'url': url, 'severity': 'high'})
                    except:
                        pass
        return findings

    async def check_sqli(self, params: list = None) -> list:
        params = params or ['id', 'user', 'username', 'login', 'email']
        findings = []
        async with aiohttp.ClientSession() as session:
            for param in params:
                for payload in SQLI_PAYLOADS:
                    try:
                        url = f"{self.base_url}?{param}={payload}"
                        async with session.get(url, timeout=aiohttp.ClientTimeout(total=5), ssl=False) as resp:
                            body = await resp.text(errors='replace')
                            if any(err in body.lower() for err in ['sql syntax', 'mysql', 'postgresql', 'oracle', 'sqlite', 'mssql', 'odbc', 'db2', 'syntax error', 'unclosed quotation']):
                                findings.append({'type': 'sqli', 'param': param, 'payload': payload, 'url': url, 'severity': 'critical'})
                    except:
                        pass
        return findings

    async def check_headers(self) -> list:
        findings = []
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(self.base_url, timeout=aiohttp.ClientTimeout(total=5), ssl=False) as resp:
                    headers = dict(resp.headers)
                    missing = ['X-Content-Type-Options', 'X-Frame-Options', 'Content-Security-Policy', 'Strict-Transport-Security', 'X-XSS-Protection', 'Referrer-Policy', 'Permissions-Policy']
                    for h in missing:
                        if h not in headers:
                            findings.append({'type': 'missing_header', 'header': h, 'severity': 'medium'})
                    if headers.get('Server', '').lower() in ('nginx', 'apache', 'microsoft-iis'):
                        findings.append({'type': 'server_disclosure', 'header': 'Server', 'value': headers['Server'], 'severity': 'low'})
                    if headers.get('X-Powered-By'):
                        findings.append({'type': 'tech_disclosure', 'header': 'X-Powered-By', 'value': headers['X-Powered-By'], 'severity': 'low'})
        except:
            pass
        return findings

    async def scan(self) -> dict:
        tech, dirs, xss, sqli, headers = await asyncio.gather(
            self.detect_tech(),
            self.brute_dirs(),
            self.check_xss(),
            self.check_sqli(),
            self.check_headers()
        )
        vulns = xss + sqli + headers
        return {
            'target': self.target,
            'technologies': tech,
            'directories': dirs,
            'vulnerabilities': vulns,
            'summary': {
                'tech_count': len(tech),
                'dirs_found': len(dirs),
                'vulns_found': len(vulns),
                'critical': len([v for v in vulns if v.get('severity') == 'critical']),
                'high': len([v for v in vulns if v.get('severity') == 'high']),
                'medium': len([v for v in vulns if v.get('severity') == 'medium']),
                'low': len([v for v in vulns if v.get('severity') == 'low']),
            }
        }
