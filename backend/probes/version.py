import re
import asyncio
from typing import Optional
from probes.signatures import SERVICE_PROBES, VERSION_SIGNATURES


class VersionDetector:
    def __init__(self, target: str, timeout: float = 3.0):
        self.target = target
        self.timeout = timeout

    async def grab_banner(self, port: int, protocol: str = 'tcp') -> Optional[str]:
        try:
            if protocol == 'tcp':
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.target, port),
                    timeout=self.timeout
                )
                banner = await asyncio.wait_for(reader.read(1024), timeout=self.timeout)
                writer.close()
                await writer.wait_closed()
                return banner.decode('utf-8', errors='replace').strip()
        except Exception:
            pass
        return None

    async def probe_service(self, port: int, service: str) -> dict:
        probe_config = SERVICE_PROBES.get(service, SERVICE_PROBES['generic'])
        result = {'version': '', 'product': '', 'extrainfo': '', 'cpe': [], 'tunnel': '', 'method': 'table', 'conf': 3}
        banner = await self.grab_banner(port)
        if not banner and probe_config['probe']:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.target, port),
                    timeout=self.timeout
                )
                await writer.drain()
                writer.write(probe_config['probe'])
                await writer.drain()
                response = await asyncio.wait_for(reader.read(4096), timeout=self.timeout)
                writer.close()
                await writer.wait_closed()
                banner = response.decode('utf-8', errors='replace').strip()
            except Exception:
                pass
        if banner:
            result['method'] = 'probe'
            result['conf'] = 8
            best_match = None
            best_conf = 0
            for pattern, field_name, conf in probe_config['patterns']:
                match = re.search(pattern, banner, re.IGNORECASE)
                if match and conf > best_conf:
                    best_match = (field_name, match.group(1).strip() if match.lastindex else match.group(0).strip(), conf)
                    best_conf = conf
            if best_match:
                field_name, value, conf = best_match
                if field_name in ('version', 'product', 'extrainfo'):
                    result[field_name] = value
                result['conf'] = conf
            version_match = re.search(r'(\d+\.\d+(\.\d+)?)', banner)
            if version_match and not result['version']:
                result['version'] = version_match.group(1)
            result['extrainfo'] = banner[:200] if not result['extrainfo'] else result['extrainfo']
        for name, sig in VERSION_SIGNATURES.items():
            if banner:
                match = re.search(sig['pattern'], banner, re.IGNORECASE)
                if match:
                    result['product'] = name
                    result['version'] = match.group(1)
                    result['conf'] = 10
                    result['method'] = 'signature'
                    version_key = match.group(1).split('.')[0]
                    if version_key in sig['cves']:
                        result['cves'] = sig['cves'][version_key]
                    break
        return result

    async def detect_os(self) -> dict:
        result = {'os_family': '', 'os_version': '', 'confidence': 0, 'details': {}}
        try:
            import socket
            import time
            loop = asyncio.get_event_loop()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            start = time.perf_counter()
            result_code = sock.connect_ex((self.target, 80))
            try:
                ttl_raw = sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
            except:
                ttl_raw = 128
            latency = (time.perf_counter() - start) * 1000
            sock.close()
            if ttl_raw <= 32:
                result['os_family'] = 'Windows'
                result['os_version'] = 'NT/2000/XP/2003'
                result['confidence'] = 85
            elif ttl_raw <= 64:
                result['os_family'] = 'Linux/Unix'
                result['os_version'] = '2.6.x - 5.x'
                result['confidence'] = 80
            elif ttl_raw <= 128:
                result['os_family'] = 'Windows'
                result['os_version'] = 'Vista/7/8/10/11/Server'
                result['confidence'] = 85
            elif ttl_raw <= 255:
                result['os_family'] = 'Network Device'
                result['os_version'] = 'Router/Switch/Firewall'
                result['confidence'] = 70
            result['details'] = {
                'initial_ttl_estimate': ttl_raw,
                'latency_ms': round(latency, 2),
                'port_80_state': 'open' if result_code == 0 else 'closed'
            }
        except Exception as e:
            result['error'] = str(e)
        return result
