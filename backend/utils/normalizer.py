import re
import socket
import subprocess
import os
from urllib.parse import urlparse
from typing import Optional


def normalize_target(raw: str) -> dict:
    raw = raw.strip().rstrip('/')
    if not raw:
        raise ValueError("Empty target")

    if raw.startswith(('http://', 'https://')):
        parsed = urlparse(raw)
        hostname = parsed.hostname or parsed.netloc
        scheme = parsed.scheme
        port = parsed.port or (443 if scheme == 'https' else 80)
    elif raw.startswith('www.'):
        hostname = raw
        scheme = 'https'
        port = 443
    elif re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', raw):
        hostname = raw
        scheme = 'http'
        port = 80
    elif ':' in raw and raw.count(':') == 1:
        host, p = raw.split(':', 1)
        hostname = host
        port = int(p)
        scheme = 'https' if port == 443 else 'http'
    else:
        hostname = raw
        scheme = 'https'
        port = 443

    hostname = hostname.lower()
    if hostname.startswith('www.'):
        hostname = hostname[4:]

    resolved_ip = resolve_hostname(hostname)

    return {
        'raw': raw,
        'hostname': hostname,
        'ip': resolved_ip,
        'scheme': scheme,
        'port': port,
        'base_url': f"{scheme}://{hostname}",
    }


def resolve_hostname(hostname: str) -> Optional[str]:
    """Resolve hostname using multiple methods with aggressive fallback."""
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hostname):
        return hostname

    methods = []

    # 1. Standard socket (fastest)
    def try_socket():
        socket.setdefaulttimeout(5)
        return socket.gethostbyname(hostname)
    methods.append(('socket', try_socket))

    # 2. getent (Linux/WSL - often works when socket fails)
    if os.path.exists('/usr/bin/getent'):
        def try_getent():
            out = subprocess.check_output(
                ['getent', 'hosts', hostname], timeout=5, stderr=subprocess.DEVNULL
            ).decode()
            return out.split()[0]
        methods.append(('getent', try_getent))

    # 3. dig (most reliable on Linux)
    if os.path.exists('/usr/bin/dig'):
        def try_dig():
            out = subprocess.check_output(
                ['dig', '+short', hostname], timeout=5, stderr=subprocess.DEVNULL
            ).decode().strip()
            for line in out.split('\n'):
                line = line.strip()
                if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', line):
                    return line
            return None
        methods.append(('dig', try_dig))

    # 4. nslookup with careful parsing
    if os.path.exists('/usr/bin/nslookup'):
        def try_nslookup():
            out = subprocess.check_output(
                ['nslookup', hostname], timeout=5, stderr=subprocess.DEVNULL
            ).decode()
            lines = out.split('\n')
            in_answer = False
            for line in lines:
                line = line.strip()
                if 'Name:' in line:
                    in_answer = True
                    continue
                if in_answer and line.startswith('Address:'):
                    addr = line.split(':', 1)[1].strip()
                    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', addr):
                        return addr
            # Fallback: find any IPv4 in output
            for line in lines:
                match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                if match:
                    return match.group(1)
            return None
        methods.append(('nslookup', try_nslookup))

    # 5. host command
    if os.path.exists('/usr/bin/host'):
        def try_host():
            out = subprocess.check_output(
                ['host', hostname], timeout=5, stderr=subprocess.DEVNULL
            ).decode()
            for line in out.split('\n'):
                if 'has address' in line:
                    return line.split('has address')[-1].strip()
            return None
        methods.append(('host', try_host))

    # 6. ping parser (works even with restrictive DNS)
    if os.path.exists('/usr/bin/ping'):
        def try_ping():
            out = subprocess.check_output(
                ['ping', '-c', '1', '-W', '3', hostname], timeout=8, stderr=subprocess.DEVNULL
            ).decode()
            match = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)', out)
            if match:
                return match.group(1)
            return None
        methods.append(('ping', try_ping))

    # 7. Python socket with explicit timeout as last resort
    def try_socket_timeout():
        import socket as s
        old_timeout = s.getdefaulttimeout()
        s.setdefaulttimeout(5)
        try:
            return s.gethostbyname(hostname)
        finally:
            s.setdefaulttimeout(old_timeout)
    methods.append(('socket-timeout', try_socket_timeout))

    # Try each method, return first valid result
    for name, method in methods:
        try:
            result = method()
            if result and re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', result):
                return result
        except Exception:
            continue

    return None


def extract_domain(hostname: str) -> str:
    parts = hostname.split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return hostname


def is_ip(target: str) -> bool:
    return bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target))


def is_cidr(target: str) -> bool:
    return '/' in target and bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$', target))


def is_private_ip(ip: str) -> bool:
    import ipaddress
    try:
        return ipaddress.ip_address(ip).is_private
    except:
        return False
