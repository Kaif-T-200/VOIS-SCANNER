import asyncio
import ssl
import socket
from typing import Optional
from datetime import datetime


class SSLAnalyzer:
    def __init__(self, target: str, port: int = 443, timeout: float = 5.0):
        self.target = target
        self.port = port
        self.timeout = timeout
        self.results = {}

    async def analyze(self) -> dict:
        result = {
            'target': self.target, 'port': self.port,
            'cert': {}, 'protocols': {}, 'ciphers': [],
            'vulnerabilities': [], 'grade': 'A'
        }
        try:
            loop = asyncio.get_event_loop()
            ctx = await loop.run_in_executor(None, self._get_ssl_context)
            cert = ctx.get_peercert()
            if cert:
                result['cert'] = self._parse_cert(cert)
            result['protocols'] = await self._check_protocols()
            result['ciphers'] = await self._check_ciphers()
            result['vulnerabilities'] = self._check_vulns(result)
            result['grade'] = self._calculate_grade(result)
        except Exception as e:
            result['error'] = str(e)
        self.results = result
        return result

    def _get_ssl_context(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((self.target, self.port), timeout=self.timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=self.target) as ssock:
                return ssock

    def _parse_cert(self, cert: dict) -> dict:
        info = {}
        for field in ('subject', 'issuer', 'serialNumber', 'version'):
            if field in cert:
                info[field] = str(cert[field])
        not_before = cert.get('notBefore', '')
        not_after = cert.get('notAfter', '')
        if not_before and not_after:
            try:
                nb = datetime.strptime(not_before, '%b %d %H:%M:%S %Y %Z')
                na = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                info['valid_from'] = nb.isoformat()
                info['valid_to'] = na.isoformat()
                info['days_remaining'] = (na - datetime.now()).days
                info['expired'] = na < datetime.now()
            except:
                pass
        san = cert.get('subjectAltName', [])
        info['sans'] = [s[1] for s in san if s[0] == 'DNS']
        return info

    async def _check_protocols(self) -> dict:
        protocols = {
            'SSLv2': (ssl.PROTOCOL_SSLv23, ssl.TLSVersion.MINIMUM_SUPPORTED, ssl.TLSVersion.SSLv3),
            'SSLv3': (ssl.PROTOCOL_SSLv23, ssl.TLSVersion.SSLv3, ssl.TLSVersion.SSLv3),
            'TLSv1.0': (ssl.PROTOCOL_TLS, ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1),
            'TLSv1.1': (ssl.PROTOCOL_TLS, ssl.TLSVersion.TLSv1_1, ssl.TLSVersion.TLSv1_1),
            'TLSv1.2': (ssl.PROTOCOL_TLS, ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2),
            'TLSv1.3': (ssl.PROTOCOL_TLS, ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3),
        }
        results = {}
        for name, (proto, min_v, max_v) in protocols.items():
            try:
                ctx = ssl.SSLContext(proto)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.minimum_version = min_v
                ctx.maximum_version = max_v
                sock = socket.create_connection((self.target, self.port), timeout=self.timeout)
                ctx.wrap_socket(sock, server_hostname=self.target).close()
                results[name] = {'supported': True, 'risk': 'high' if name in ('SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1') else 'low'}
            except:
                results[name] = {'supported': False}
        return results

    async def _check_ciphers(self) -> list:
        cipher_suites = [
            'ECDHE-RSA-AES256-GCM-SHA384', 'ECDHE-RSA-AES128-GCM-SHA256',
            'ECDHE-RSA-AES256-SHA384', 'ECDHE-RSA-AES128-SHA256',
            'AES256-GCM-SHA384', 'AES128-GCM-SHA256',
            'AES256-SHA256', 'AES128-SHA256',
            'ECDHE-RSA-AES256-SHA', 'ECDHE-RSA-AES128-SHA',
            'AES256-SHA', 'AES128-SHA',
            'DES-CBC3-SHA', 'RC4-SHA', 'RC4-MD5',
            'NULL-SHA', 'NULL-MD5',
            'EXP-RC4-MD5', 'EXP-DES-CBC-SHA',
        ]
        results = []
        for cipher in cipher_suites:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.set_ciphers(cipher)
                sock = socket.create_connection((self.target, self.port), timeout=self.timeout)
                ctx.wrap_socket(sock, server_hostname=self.target).close()
                is_weak = any(w in cipher for w in ['NULL', 'EXP', 'RC4', 'DES', 'MD5'])
                results.append({'cipher': cipher, 'supported': True, 'strength': 'weak' if is_weak else 'strong'})
            except:
                results.append({'cipher': cipher, 'supported': False})
        return results

    def _check_vulns(self, result: dict) -> list:
        vulns = []
        for proto, info in result.get('protocols', {}).items():
            if info.get('supported') and proto in ('SSLv2', 'SSLv3'):
                vulns.append({'name': f'{proto} supported', 'severity': 'critical', 'description': f'{proto} is deprecated and vulnerable'})
            if info.get('supported') and proto in ('TLSv1.0', 'TLSv1.1'):
                vulns.append({'name': f'{proto} supported', 'severity': 'high', 'description': f'{proto} is deprecated'})
        cert = result.get('cert', {})
        if cert.get('expired'):
            vulns.append({'name': 'Certificate expired', 'severity': 'critical', 'description': 'SSL certificate has expired'})
        elif cert.get('days_remaining', 999) < 30:
            vulns.append({'name': 'Certificate expiring soon', 'severity': 'medium', 'description': f"Certificate expires in {cert['days_remaining']} days"})
        weak_ciphers = [c for c in result.get('ciphers', []) if c.get('supported') and c.get('strength') == 'weak']
        if weak_ciphers:
            vulns.append({'name': 'Weak ciphers supported', 'severity': 'high', 'description': f"{len(weak_ciphers)} weak cipher(s) supported"})
        return vulns

    def _calculate_grade(self, result: dict) -> str:
        score = 100
        for v in result.get('vulnerabilities', []):
            if v['severity'] == 'critical':
                score -= 30
            elif v['severity'] == 'high':
                score -= 20
            elif v['severity'] == 'medium':
                score -= 10
            elif v['severity'] == 'low':
                score -= 5
        score = max(0, score)
        if score >= 90:
            return 'A'
        elif score >= 80:
            return 'B'
        elif score >= 70:
            return 'C'
        elif score >= 60:
            return 'D'
        else:
            return 'F'
