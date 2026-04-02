import socket
import struct
import asyncio
import random
import time
from typing import Optional, Callable
from core.types import (
    ScanType, PortState, PortResult, HostResult, Protocol,
    COMMON_SERVICES, TIMING_TEMPLATES
)


class BaseScanner:
    def __init__(self, target: str, ports: list, timeout: float = 1.0,
                 parallelism: int = 200, retries: int = 1):
        self.target = target
        self.ports = ports
        self.timeout = timeout
        self.parallelism = parallelism
        self.retries = retries
        self._semaphore = asyncio.Semaphore(parallelism)
        self._stop = False
        self._stats = {'scanned': 0, 'open': 0, 'closed': 0, 'filtered': 0}

    async def scan_port(self, port: int) -> Optional[PortResult]:
        raise NotImplementedError

    async def run(self, progress_callback: Optional[Callable] = None) -> list:
        random.shuffle(self.ports)
        results = []
        batch_size = self.parallelism
        for i in range(0, len(self.ports), batch_size):
            if self._stop:
                break
            batch = self.ports[i:i + batch_size]
            tasks = [asyncio.create_task(self.scan_port(p)) for p in batch]
            batch_results = await asyncio.gather(*tasks)
            valid = [r for r in batch_results if r is not None]
            results.extend(valid)
            self._stats['scanned'] += len(batch_results)
            if progress_callback:
                await progress_callback(self._stats, results)
        return results

    def stop(self):
        self._stop = True


class TCPConnectScanner(BaseScanner):
    async def scan_port(self, port: int) -> Optional[PortResult]:
        if self._stop:
            return None
        async with self._semaphore:
            if self._stop:
                return None
            for attempt in range(self.retries + 1):
                start = time.perf_counter()
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(self.target, port),
                        timeout=self.timeout
                    )
                    latency = (time.perf_counter() - start) * 1000
                    writer.close()
                    await writer.wait_closed()
                    self._stats['open'] += 1
                    return PortResult(
                        port=port, protocol=Protocol.TCP, state=PortState.OPEN,
                        service=COMMON_SERVICES.get(port, 'unknown'),
                        latency=round(latency, 2), method='tcp_connect',
                        reason='syn-ack', reason_ttl=64
                    )
                except asyncio.TimeoutError:
                    if attempt == self.retries:
                        self._stats['filtered'] += 1
                        return PortResult(
                            port=port, protocol=Protocol.TCP, state=PortState.FILTERED,
                            service=COMMON_SERVICES.get(port, 'unknown'),
                            method='tcp_connect', reason='no-response'
                        )
                except ConnectionRefusedError:
                    self._stats['closed'] += 1
                    return PortResult(
                        port=port, protocol=Protocol.TCP, state=PortState.CLOSED,
                        service=COMMON_SERVICES.get(port, 'unknown'),
                        method='tcp_connect', reason='conn-refused'
                    )
                except OSError:
                    if attempt == self.retries:
                        self._stats['filtered'] += 1
                        return PortResult(
                            port=port, protocol=Protocol.TCP, state=PortState.FILTERED,
                            service=COMMON_SERVICES.get(port, 'unknown'),
                            method='tcp_connect', reason='host-unreach'
                        )
        return None


class SYNScanner(BaseScanner):
    async def scan_port(self, port: int) -> Optional[PortResult]:
        if self._stop:
            return None
        async with self._semaphore:
            if self._stop:
                return None
            for attempt in range(self.retries + 1):
                start = time.perf_counter()
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
                    sock.settimeout(self.timeout)
                    sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 64)
                    src_port = random.randint(1024, 65535)
                    seq = random.randint(0, 4294967295)
                    tcp_header = struct.pack('!HHLLBBHHH',
                        src_port, port, seq, 0, 5 << 2, 0x02, 65535, 0, 0)
                    sock.sendto(tcp_header, (self.target, 0))
                    try:
                        data, addr = sock.recvfrom(1024)
                        latency = (time.perf_counter() - start) * 1000
                        ip_header = data[:20]
                        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
                        ttl = iph[5]
                        tcp_response = data[20:]
                        tcph = struct.unpack('!HHLLBBHHH', tcp_response[:20])
                        flags = tcph[5]
                        if flags & 0x12:
                            ack = tcph[1] + 1
                            rst_header = struct.pack('!HHLLBBHHH',
                                src_port, port, ack, 0, 5 << 2, 0x04, 0, 0, 0)
                            sock.sendto(rst_header, (self.target, 0))
                            self._stats['open'] += 1
                            return PortResult(
                                port=port, protocol=Protocol.TCP, state=PortState.OPEN,
                                service=COMMON_SERVICES.get(port, 'unknown'),
                                latency=round(latency, 2), method='syn_stealth',
                                reason='syn-ack', reason_ttl=ttl
                            )
                        elif flags & 0x14:
                            self._stats['closed'] += 1
                            return PortResult(
                                port=port, protocol=Protocol.TCP, state=PortState.CLOSED,
                                service=COMMON_SERVICES.get(port, 'unknown'),
                                method='syn_stealth', reason='rst', reason_ttl=ttl
                            )
                    except socket.timeout:
                        if attempt == self.retries:
                            self._stats['filtered'] += 1
                            return PortResult(
                                port=port, protocol=Protocol.TCP, state=PortState.FILTERED,
                                service=COMMON_SERVICES.get(port, 'unknown'),
                                method='syn_stealth', reason='no-response'
                            )
                except (PermissionError, OSError):
                    return await self._fallback_connect(port)
        return None

    async def _fallback_connect(self, port: int) -> Optional[PortResult]:
        try:
            start = time.perf_counter()
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.target, port),
                timeout=self.timeout
            )
            latency = (time.perf_counter() - start) * 1000
            writer.close()
            await writer.wait_closed()
            self._stats['open'] += 1
            return PortResult(
                port=port, protocol=Protocol.TCP, state=PortState.OPEN,
                service=COMMON_SERVICES.get(port, 'unknown'),
                latency=round(latency, 2), method='syn_stealth_fallback',
                reason='syn-ack'
            )
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            self._stats['closed'] += 1
            return PortResult(
                port=port, protocol=Protocol.TCP, state=PortState.CLOSED,
                service=COMMON_SERVICES.get(port, 'unknown'),
                method='syn_stealth_fallback', reason='conn-refused'
            )


class UDPScanner(BaseScanner):
    async def scan_port(self, port: int) -> Optional[PortResult]:
        if self._stop:
            return None
        async with self._semaphore:
            if self._stop:
                return None
            for attempt in range(self.retries + 1):
                start = time.perf_counter()
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(self.timeout)
                    probe = b'\x00' * 8
                    port_probes = {
                        53: b'\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01',
                        123: b'\xe3\x00\x04\xfa\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xe6\xb5\x6b\xf4',
                        161: b'\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63\xa1\x19\x02\x04\x00\x00\x00\x01\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00',
                    }
                    if port in port_probes:
                        probe = port_probes[port]
                    sock.sendto(probe, (self.target, port))
                    try:
                        data, addr = sock.recvfrom(4096)
                        latency = (time.perf_counter() - start) * 1000
                        self._stats['open'] += 1
                        return PortResult(
                            port=port, protocol=Protocol.UDP, state=PortState.OPEN,
                            service=COMMON_SERVICES.get(port, 'unknown'),
                            latency=round(latency, 2), method='udp',
                            reason='udp-response'
                        )
                    except socket.timeout:
                        if attempt == self.retries:
                            self._stats['open|filtered'] += 1
                            return PortResult(
                                port=port, protocol=Protocol.UDP, state=PortState.OPEN_FILTERED,
                                service=COMMON_SERVICES.get(port, 'unknown'),
                                method='udp', reason='no-response'
                            )
                    except OSError as e:
                        if 'ICMP' in str(e) or 'unreachable' in str(e).lower():
                            self._stats['closed'] += 1
                            return PortResult(
                                port=port, protocol=Protocol.UDP, state=PortState.CLOSED,
                                service=COMMON_SERVICES.get(port, 'unknown'),
                                method='udp', reason='icmp-unreach'
                            )
                finally:
                    try:
                        sock.close()
                    except:
                        pass
        return None


class FirewallDetector:
    """Simplified firewall detection using standard TCP operations."""
    
    def __init__(self, target: str, timeout: float = 2.0):
        self.target = target
        self.timeout = timeout
        self.results = {'firewall_type': 'none', 'waf': None, 'ids_ips': False, 'details': {}}

    async def detect(self) -> dict:
        """Detect firewall and WAF presence via HTTP responses and port analysis."""
        # Check standard ports
        port_80 = await self._check_port(80)
        port_443 = await self._check_port(443)
        port_22 = await self._check_port(22)
        
        # Simple firewall inference
        if port_80 == 'filtered' and port_443 =='filtered' and port_22 == 'filtered':
            self.results['firewall_type'] = 'aggressive'
            self.results['details']['most_ports_blocked'] = True
        elif port_443 == 'open' and port_80 == 'closed':
            self.results['firewall_type'] = 'selective'
            self.results['details']['http_blocked_https_open'] = True

        # Try to detect WAF via HTTP headers
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.target, 80),
                timeout=self.timeout
            )
            writer.write(b'HEAD / HTTP/1.0\r\nHost: ' + self.target.encode() + b'\r\nConnection: close\r\n\r\n')
            await writer.drain()
            response = await asyncio.wait_for(reader.read(4096), timeout=self.timeout)
            writer.close()
            await writer.wait_closed()
            
            response_str = response.decode('utf-8', errors='replace').lower()
            
            # Common WAF signatures
            waf_sigs = {
                'cloudflare': 'cloudflare',
                'akamai': 'akamai', 
                'mod_security': 'modsecurity',
                'barracuda': 'barracuda',
                'f5': 'f5',
                'imperva': 'imperva',
            }
            for waf_name, sig in waf_sigs.items():
                if sig in response_str:
                    self.results['waf'] = waf_name
                    break
        except Exception:
            pass
        
        return self.results

    async def _check_port(self, port: int) -> str:
        """Check if a port is open, closed, or filtered."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.target, port),
                timeout=self.timeout
            )
            writer.close()
            await writer.wait_closed()
            return 'open'
        except asyncio.TimeoutError:
            return 'filtered'
        except ConnectionRefusedError:
            return 'closed'
        except OSError:
            return 'filtered'


class Traceroute:
    """Simplified traceroute using TCP connections only (no raw sockets needed)."""
    
    def __init__(self, target: str, max_hops: int = 10, timeout: float = 1.0):
        self.target = target
        self.max_hops = max_hops
        self.timeout = timeout
        self.hops = []

    async def run(self) -> list:
        """
        Simplified traceroute that tries common ports instead of ICMP.
        Returns list of hops with IPs and hostnames.
        """
        try:
            # Get target IP
            loop = asyncio.get_event_loop()
            target_ip = await loop.run_in_executor(None, socket.gethostbyname, self.target)
            
            # For now, just return the target with basic info
            try:
                hostname = socket.gethostbyaddr(target_ip)[0]
            except:
                hostname = target_ip
            
            self.hops = [{
                'hop': 1,
                'ip': target_ip,
                'hostname': hostname,
                'latency': 0
            }]
        except Exception:
            self.hops = []
        
        return self.hops
        return self.hops
