import asyncio
import aiohttp
import json
from typing import Optional

SHODAN_API = "https://api.shodan.io/shodan/host/{}"
VIRUSTOTAL_API = "https://www.virustotal.com/api/v3"
HIBP_API = "https://haveibeenpwned.com/api/v3"
CENSYS_API = "https://search.censys.io/api/v2/hosts/{}"


class ShodanIntegration:
    def __init__(self, api_key: str = None):
        self.api_key = api_key

    async def lookup(self, ip: str) -> dict:
        if not self.api_key:
            return {'error': 'No Shodan API key configured'}
        try:
            url = SHODAN_API.format(ip)
            async with aiohttp.ClientSession() as session:
                async with session.get(url, params={'key': self.api_key}, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return {
                            'ip': data.get('ip_str'),
                            'ports': data.get('ports', []),
                            'os': data.get('os'),
                            'hostnames': data.get('hostnames', []),
                            'country': data.get('country_name'),
                            'city': data.get('city'),
                            'org': data.get('org'),
                            'isp': data.get('isp'),
                            'vulns': data.get('vulns', []),
                            'last_update': data.get('last_update'),
                            'tags': data.get('tags', []),
                        }
                    return {'error': f'Shodan API error: {resp.status}'}
        except Exception as e:
            return {'error': str(e)}


class VirusTotalIntegration:
    def __init__(self, api_key: str = None):
        self.api_key = api_key

    async def lookup_ip(self, ip: str) -> dict:
        if not self.api_key:
            return {'error': 'No VirusTotal API key configured'}
        try:
            url = f"{VIRUSTOTAL_API}/ip_addresses/{ip}"
            headers = {'x-apikey': self.api_key}
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        attrs = data.get('data', {}).get('attributes', {})
                        return {
                            'reputation': attrs.get('reputation'),
                            'last_analysis_stats': attrs.get('last_analysis_stats', {}),
                            'country': attrs.get('country'),
                            'as_owner': attrs.get('as_owner'),
                            'network': attrs.get('network'),
                            'whois': attrs.get('whois'),
                            'whois_date': attrs.get('whois_date'),
                        }
                    return {'error': f'VT API error: {resp.status}'}
        except Exception as e:
            return {'error': str(e)}

    async def lookup_domain(self, domain: str) -> dict:
        if not self.api_key:
            return {'error': 'No VirusTotal API key configured'}
        try:
            url = f"{VIRUSTOTAL_API}/domains/{domain}"
            headers = {'x-apikey': self.api_key}
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        attrs = data.get('data', {}).get('attributes', {})
                        return {
                            'reputation': attrs.get('reputation'),
                            'categories': attrs.get('categories', {}),
                            'registrar': attrs.get('registrar'),
                            'whois': attrs.get('whois'),
                            'last_analysis_stats': attrs.get('last_analysis_stats', {}),
                            'subdomains': attrs.get('subdomains', [])[:20],
                        }
                    return {'error': f'VT API error: {resp.status}'}
        except Exception as e:
            return {'error': str(e)}


class HaveIBeenPwnedIntegration:
    def __init__(self, api_key: str = None):
        self.api_key = api_key

    async def check_email(self, email: str) -> dict:
        if not self.api_key:
            return {'error': 'No HIBP API key configured'}
        try:
            url = f"{HIBP_API}/breachedaccount/{email}"
            headers = {'hibp-api-key': self.api_key, 'user-agent': 'VOIS-Scanner/3.0'}
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        breaches = await resp.json()
                        return {
                            'breached': True,
                            'breach_count': len(breaches),
                            'breaches': [
                                {
                                    'name': b.get('Name'),
                                    'date': b.get('BreachDate'),
                                    'data_classes': b.get('DataClasses', []),
                                    'is_verified': b.get('IsVerified'),
                                    'domain': b.get('Domain'),
                                }
                                for b in breaches[:10]
                            ]
                        }
                    elif resp.status == 404:
                        return {'breached': False, 'breach_count': 0, 'breaches': []}
                    return {'error': f'HIBP API error: {resp.status}'}
        except Exception as e:
            return {'error': str(e)}

    async def check_password(self, password: str) -> dict:
        import hashlib
        sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix = sha1[:5]
        suffix = sha1[5:]
        try:
            url = f"https://api.pwnedpasswords.com/range/{prefix}"
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        for line in text.split('\n'):
                            parts = line.strip().split(':')
                            if parts[0] == suffix:
                                return {'pwned': True, 'count': int(parts[1])}
                        return {'pwned': False, 'count': 0}
                    return {'error': f'Pwned Passwords API error: {resp.status}'}
        except Exception as e:
            return {'error': str(e)}


class CensysIntegration:
    def __init__(self, api_id: str = None, api_secret: str = None):
        self.api_id = api_id
        self.api_secret = api_secret

    async def lookup(self, ip: str) -> dict:
        if not self.api_id or not self.api_secret:
            return {'error': 'No Censys API credentials configured'}
        try:
            url = CENSYS_API.format(ip)
            auth = aiohttp.BasicAuth(self.api_id, self.api_secret)
            async with aiohttp.ClientSession() as session:
                async with session.get(url, auth=auth, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        result = data.get('result', {})
                        return {
                            'ip': result.get('ip'),
                            'services': [
                                {
                                    'port': s.get('port'),
                                    'service_name': s.get('service_name'),
                                    'banner': s.get('banner', '')[:200],
                                }
                                for s in result.get('services', [])
                            ],
                            'location': result.get('location', {}),
                            'autonomous_system': result.get('autonomous_system', {}),
                            'last_updated': result.get('last_updated_at'),
                        }
                    return {'error': f'Censys API error: {resp.status}'}
        except Exception as e:
            return {'error': str(e)}
