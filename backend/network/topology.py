import socket
import ipaddress
import asyncio
from utils.normalizer import is_private_ip, resolve_hostname


async def check_port(ip, port, timeout=1.0):
    try:
        loop = asyncio.get_event_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = await loop.run_in_executor(None, lambda: sock.connect_ex((ip, port)))
        sock.close()
        return result == 0
    except:
        return False


async def scan_ports(ip, ports, timeout=1.0):
    semaphore = asyncio.Semaphore(100)
    async def check(p):
        async with semaphore:
            if await check_port(ip, p, timeout):
                return p
            return None
    tasks = [asyncio.create_task(check(p)) for p in ports]
    results = []
    for coro in asyncio.as_completed(tasks):
        r = await coro
        if r:
            results.append(r)
    return sorted(results)


async def ping_host(ip, timeout=0.5):
    common_ports = [80, 443]
    for port in common_ports:
        if await check_port(ip, port, timeout):
            try:
                loop = asyncio.get_event_loop()
                hostname = await loop.run_in_executor(None, socket.gethostbyaddr, ip)
                hostname = hostname[0]
            except:
                hostname = ""
            return {'ip': ip, 'hostname': hostname}
    return None


def guess_device_type(ports, hostname=""):
    port_set = set(ports)
    hn = hostname.lower()
    if any(x in hn for x in ['router', 'gateway', 'switch', 'fw', 'firewall']):
        return 'router'
    if {80, 443, 8080, 8443} & port_set and {3306, 5432, 27017, 1433, 1521} & port_set:
        return 'server'
    if {80, 443, 8080, 8443} & port_set:
        return 'web-server'
    if {3389} & port_set:
        return 'windows'
    if {22} & port_set and not ({80, 443} & port_set):
        return 'server'
    if {161, 162} & port_set:
        return 'network-device'
    if {53} & port_set:
        return 'dns-server'
    if {3389, 445, 139} & port_set:
        return 'windows'
    if {6379, 27017, 3306, 5432} & port_set:
        return 'database'
    return 'host'


class NetworkMapper:
    async def build_topology(self, target):
        target = target.strip()
        try:
            loop = asyncio.get_event_loop()
            target_ip = await loop.run_in_executor(None, resolve_hostname, target)
        except:
            target_ip = None
        if not target_ip:
            return {'nodes': [], 'connections': [], 'error': 'Could not resolve ' + target}

        # External host - just scan ports on single host
        if not is_private_ip(target_ip):
            scan_ports_list = [21, 22, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017]
            open_ports = await scan_ports(target_ip, scan_ports_list, timeout=2.0)
            try:
                hostname = await loop.run_in_executor(None, socket.gethostbyaddr, target_ip)
                hostname = hostname[0]
            except:
                hostname = target
            device_type = guess_device_type(open_ports, hostname)
            return {
                'nodes': [{'ip': target_ip, 'hostname': hostname, 'mac': '', 'device_type': device_type, 'is_gateway': False, 'open_ports': open_ports}],
                'connections': [],
                'gateway': None,
                'message': 'External host - subnet discovery only works for local networks.',
            }

        # Local network - discover subnet
        subnet = str(ipaddress.ip_network(target_ip + "/24", strict=False))
        gateway_ip = None
        try:
            import sys
            result = await loop.run_in_executor(None, lambda: __import__('subprocess').run(
                ['ip', 'route'] if sys.platform != 'win32' else ['route', 'print'],
                capture_output=True, text=True, timeout=5
            ))
            for line in result.stdout.split('\n'):
                if 'default' in line or ('0.0.0.0' in line and '0.0.0.0' in line):
                    parts = line.split()
                    for p in parts:
                        try:
                            if p != '0.0.0.0' and ipaddress.ip_address(p).is_private:
                                gateway_ip = p
                                break
                        except:
                            continue
                    if gateway_ip:
                        break
        except:
            pass

        try:
            network = ipaddress.ip_network(subnet, strict=False)
            hosts = [str(ip) for ip in network.hosts()]
        except:
            return {'nodes': [], 'connections': [], 'error': 'Invalid subnet'}

        semaphore = asyncio.Semaphore(100)
        async def check(ip):
            async with semaphore:
                return await ping_host(ip, timeout=0.5)
        tasks = [asyncio.create_task(check(ip)) for ip in hosts]
        live_hosts = []
        for coro in asyncio.as_completed(tasks):
            r = await coro
            if r:
                live_hosts.append(r)

        if not live_hosts:
            try:
                hostname = await loop.run_in_executor(None, socket.gethostbyaddr, target_ip)
                hostname = hostname[0]
            except:
                hostname = ""
            live_hosts = [{'ip': target_ip, 'hostname': hostname}]

        nodes = []
        connections = []
        for host in live_hosts:
            ports = await scan_ports(host['ip'], [21, 22, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017], timeout=1.0)
            device_type = guess_device_type(ports, host['hostname'])
            is_gw = (gateway_ip and host['ip'] == gateway_ip)
            nodes.append({
                'ip': host['ip'],
                'hostname': host['hostname'] or 'Unknown',
                'mac': '',
                'device_type': device_type,
                'is_gateway': is_gw,
                'open_ports': ports,
            })
            if is_gw:
                for n in nodes[:-1]:
                    if n['ip'] != gateway_ip:
                        connections.append({'from': gateway_ip, 'to': n['ip'], 'type': 'direct'})

        return {
            'nodes': nodes,
            'connections': connections,
            'gateway': {'ip': gateway_ip} if gateway_ip else None,
            'subnet': subnet,
        }
