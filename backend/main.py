from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Query, Response, Body
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import asyncio
import os
import sys
import json
from datetime import datetime

sys.path.insert(0, os.path.dirname(__file__))

from core.types import ScanType, PortState, Protocol, COMMON_SERVICES, TIMING_TEMPLATES, DEFAULT_PROFILES
from core.engine import TCPConnectScanner, SYNScanner, UDPScanner, FirewallDetector, Traceroute
from probes.version import VersionDetector
from intelligence.cve import CVEDatabase, RiskScorer
from network.topology import NetworkMapper
from scripts.engine import ScriptEngine
from database.db import save_scan, get_scan, get_scans, delete_scan, search_scans, init_db
from utils.export import export_json, export_csv, export_xml, export_txt
from utils.normalizer import normalize_target, is_cidr, resolve_hostname

HISTORY_FILE = os.path.join(os.path.dirname(__file__), 'database', 'scan_history.json')
active_scans = {}
ws_connections = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Initialize database
    init_db()
    print("[+] Database initialized")
    yield
    # Shutdown: Clean up active scans
    for scanner in active_scans.values():
        if hasattr(scanner, 'stop'):
            scanner.stop()
    active_scans.clear()
    print("[+] Shutdown complete")


app = FastAPI(title="VOIS Port Scanner", version="3.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

frontend_dir = os.path.join(os.path.dirname(__file__), '..', 'frontend')
if not os.path.exists(frontend_dir):
    frontend_dir = os.path.join(os.getcwd(), 'frontend')

app.mount("/static", StaticFiles(directory=frontend_dir), name="static")

cve_db = CVEDatabase()
script_engine = ScriptEngine()
network_mapper = NetworkMapper()


@app.get("/", response_class=HTMLResponse)
async def index():
    return FileResponse(os.path.join(frontend_dir, 'index.html'))


@app.get("/api/profiles")
async def get_profiles():
    """Get available scanning profiles, types, and timing options."""
    return {
        'profiles': {k: {'ports': v['ports'], 'timing': v['timing'], 'description': v['description']} for k, v in DEFAULT_PROFILES.items()},
        'scan_types': [
            {'id': 'tcp_connect', 'name': 'TCP Connect', 'description': 'Standard full connection - most reliable, no root needed', 'recommended': True},
            {'id': 'syn_stealth', 'name': 'SYN Stealth', 'description': 'Half-open scan - faster, appears less aggressive (requires elevated privileges)', 'recommended': False},
            {'id': 'udp', 'name': 'UDP', 'description': 'UDP port discovery - for DNS, SNMP, and other UDP services', 'recommended': False},
        ],
        'timing_templates': {
            '1': {'name': 'Paranoid', 'label': 'T1', 'description': 'Extremely slow - for IDS evasion (not recommended)'},
            '2': {'name': 'Sneaky', 'label': 'T2', 'description': 'Very slow - for IDS evasion'},
            '3': {'name': 'Polite', 'label': 'T3', 'description': 'Slower - less network load, more time'},
            '4': {'name': 'Normal', 'label': 'T4', 'description': 'Balanced - good for most scans (recommended)'},
            '5': {'name': 'Aggressive', 'label': 'T5', 'description': 'Fast - for responsive networks'},
        }
    }


@app.get("/api/normalize")
async def normalize_endpoint(target: str = Query(...)):
    """
    Normalize and validate a target (IP, domain, URL).
    Returns the resolved IP and normalized target.
    """
    try:
        original_target = target
        target = target.strip()
        port = 80
        scheme = 'http'
        
        # Remove URL protocol if present
        if target.startswith('http://'):
            target = target[7:]
            scheme = 'http'
        elif target.startswith('https://'):
            target = target[8:]
            scheme = 'https'
        
        # Remove path if present
        if '/' in target:
            target = target.split('/')[0]
        
        # Extract port if present
        if ':' in target and not target.endswith(':'):
            target_parts = target.rsplit(':', 1)
            target = target_parts[0]
            try:
                port = int(target_parts[1])
            except ValueError:
                port = 80 if scheme == 'http' else 443
        else:
            port = 80 if scheme == 'http' else 443
        
        # Remove www. prefix
        hostname = target
        if hostname.startswith('www.'):
            hostname = hostname[4:]
        
        # Resolve - non-async function
        resolved = resolve_hostname(hostname)
        if not resolved:
            resolved = hostname
        
        return {
            'target': original_target,
            'hostname': hostname,
            'ip': resolved,
            'scheme': scheme,
            'port': port,
            'valid': True
        }
    except Exception as e:
        return {
            'target': target,
            'hostname': None,
            'ip': None,
            'scheme': 'http',
            'port': 80,
            'valid': False,
            'error': str(e)
        }


def parse_ports(ports_str: str) -> list:
    ports = set()
    for part in ports_str.split(','):
        part = part.strip()
        if '-' in part:
            start, end = part.split('-', 1)
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)


@app.post("/api/scan")
async def start_scan(request_body: dict = Body(...)):
    try:
        raw_target = request_body.get('target', '').strip()
        if not raw_target:
            raise HTTPException(400, "Target is required")

        if is_cidr(raw_target):
            normalized = {'hostname': raw_target, 'ip': None, 'scheme': 'http', 'port': 80, 'base_url': raw_target}
            scan_host = raw_target
        else:
            try:
                normalized = normalize_target(raw_target)
                scan_host = normalized['ip'] or normalized['hostname']
            except Exception as e:
                raise HTTPException(400, f"Invalid target: {str(e)}")

        scan_type = ScanType(request_body.get('scan_type', 'tcp_connect'))
        profile = request_body.get('profile', 'common')
        ports_str = request_body.get('ports')
        timing = int(request_body.get('timing', 3))
        grab_banners = request_body.get('grab_banners', False)
        detect_os = request_body.get('detect_os', False)
        run_scripts = request_body.get('run_scripts', False)
        traceroute = request_body.get('traceroute', False)
        firewall_detect = request_body.get('firewall_detect', False)

        timing_config = TIMING_TEMPLATES.get(timing, TIMING_TEMPLATES[3])
        if ports_str:
            ports = parse_ports(ports_str)
        else:
            ports_str = DEFAULT_PROFILES.get(profile, DEFAULT_PROFILES['common'])['ports']
            ports = parse_ports(ports_str)

        timeout = request_body.get('timeout', timing_config['timeout'])
        parallelism = timing_config['parallelism']

        try:
            loop = asyncio.get_event_loop()
            resolved_ip = await loop.run_in_executor(None, resolve_hostname, scan_host)
            if not resolved_ip:
                resolved_ip = await loop.run_in_executor(None, __import__('socket').gethostbyname, scan_host)
        except Exception as e:
            raise HTTPException(400, f"Failed to resolve target: {e}")

        scan_id = __import__('uuid').uuid4().hex[:8]
        active_scans[scan_id] = {
            'target': raw_target, 'normalized': normalized, 'resolved_ip': resolved_ip,
            'scan_type': scan_type.value, 'profile': profile, 'ports': ports,
            'timing': timing, 'status': 'running', 'results': [], 'os_info': {},
            'risk': {}, 'scripts': [], 'firewall': {}, 'traceroute': [],
            'start_time': datetime.now().isoformat(),
        }
        ws_connections[scan_id] = []

        asyncio.create_task(run_scan_pipeline(
            scan_id, scan_host, resolved_ip, ports, scan_type,
            timeout, parallelism, grab_banners, detect_os, run_scripts, traceroute, firewall_detect
        ))

        return {
            'scan_id': scan_id, 'target': raw_target, 'resolved_ip': resolved_ip,
            'scan_type': scan_type.value, 'total_ports': len(ports), 'normalized': normalized,
        }
    except HTTPException:
        raise
    except Exception as e:
        import traceback
        print(f"[ERROR] Scan start failed: {e}")
        print(traceback.format_exc())
        raise HTTPException(500, f"Server error: {str(e)}")


async def run_scan_pipeline(scan_id, target, resolved_ip, ports, scan_type,
                            timeout, parallelism, grab_banners, detect_os,
                            run_scripts, do_traceroute, firewall_detect):

    scanner = None
    if scan_type == ScanType.TCP_CONNECT:
        scanner = TCPConnectScanner(target, ports, timeout, parallelism)
    elif scan_type == ScanType.SYN:
        scanner = SYNScanner(target, ports, timeout, parallelism)
    elif scan_type == ScanType.UDP:
        scanner = UDPScanner(target, ports, timeout, parallelism // 2)
    else:
        # Fallback to TCP Connect for unknown scan types
        scanner = TCPConnectScanner(target, ports, timeout, parallelism)

    async def progress_callback(stats, results):
        open_ports = [r for r in results if r.state == PortState.OPEN]
        await broadcast_to_ws(scan_id, {
            'type': 'progress', 'scanned': stats['scanned'], 'total': len(ports),
            'status': 'running',
            'open_ports': [port_to_dict(p) for p in open_ports[-50:]],
            'stats': stats,
        })

    results = await scanner.run(progress_callback)
    open_ports = [r for r in results if r.state == PortState.OPEN]
    active_scans[scan_id]['results'] = results

    if grab_banners and open_ports:
        detector = VersionDetector(target, timeout=3.0)
        for port_result in open_ports:
            version_info = await detector.probe_service(port_result.port, port_result.service)
            port_result.version = version_info.get('version', '')
            port_result.product = version_info.get('product', '')
            port_result.extrainfo = version_info.get('extrainfo', '')
            port_result.banner = version_info.get('extrainfo', '')[:200]
            port_result.cpe = version_info.get('cpe', [])
            port_result.conf = version_info.get('conf', 3)
            port_result.method = version_info.get('method', 'table')
            if 'cves' in version_info:
                port_result.cves = version_info['cves']
            await broadcast_to_ws(scan_id, {
                'type': 'version', 'port': port_result.port,
                'version': port_result.version, 'product': port_result.product,
                'banner': port_result.banner[:100],
            })

    if detect_os:
        detector = VersionDetector(target)
        os_info = await detector.detect_os()
        active_scans[scan_id]['os_info'] = os_info

    if do_traceroute:
        tracer = Traceroute(target, timeout=3.0)
        active_scans[scan_id]['traceroute'] = await tracer.run()

    if firewall_detect:
        fd = FirewallDetector(target, timeout=2.0)
        active_scans[scan_id]['firewall'] = await fd.detect()

    for port_result in open_ports:
        # Ensure cves is a list of dicts, not strings
        raw_cves = port_result.cves
        if isinstance(raw_cves, list):
            port_result.cves = [{'id': c} if isinstance(c, str) else c for c in raw_cves]
        elif isinstance(raw_cves, str):
            port_result.cves = [{'id': raw_cves}]
        else:
            port_result.cves = []
        risk = RiskScorer.calculate_port_risk(port_result.port, port_result.cves)
        port_result.risk_score = risk['score']
        port_result.risk_level = risk['level']

    if run_scripts:
        script_results = await script_engine.run_all(target)
        active_scans[scan_id]['scripts'] = [
            {'name': s.name, 'category': s.category, 'output': s.output, 'risk': s.risk, 'findings': s.findings}
            for s in script_results
        ]

    host_risk = RiskScorer.calculate_host_risk(open_ports)
    active_scans[scan_id]['risk'] = host_risk
    active_scans[scan_id]['status'] = 'completed'
    active_scans[scan_id]['elapsed'] = (datetime.now() - datetime.fromisoformat(active_scans[scan_id]['start_time'])).total_seconds()

    try:
        save_scan(
            scan_id=scan_id, target=target, resolved_ip=resolved_ip, hostname='',
            scan_type=scan_type.value, profile=active_scans[scan_id].get('profile', ''),
            start_port=min(ports) if ports else 1, end_port=max(ports) if ports else 65535, 
            timing=active_scans[scan_id].get('timing', 3), status='completed',
            elapsed=active_scans[scan_id]['elapsed'], total_ports=len(ports),
            open_ports=results, os_info=active_scans[scan_id].get('os_info'), risk=host_risk,
        )
        print(f"[+] Scan data saved for {scan_id}")
    except Exception as e:
        print(f"[!] Error saving scan {scan_id}: {e}")
        import traceback
        traceback.print_exc()

    # Small delay to ensure DB write completes before WebSocket broadcast
    await asyncio.sleep(0.1)

    await broadcast_to_ws(scan_id, {
        'type': 'complete', 'status': 'completed',
        'open_ports_count': len(open_ports), 'risk': host_risk,
        'os_info': active_scans[scan_id].get('os_info', {}),
        'scripts': active_scans[scan_id].get('scripts', []),
        'firewall': active_scans[scan_id].get('firewall', {}),
        'traceroute': active_scans[scan_id].get('traceroute', []),
        'elapsed': active_scans[scan_id]['elapsed'],
        'scan_id': scan_id,
    })
    
    print(f"[+] Scan {scan_id} completed - {len(open_ports)} open ports found")


def port_to_dict(p):
    return {
        'port': p.port, 'protocol': p.protocol.value, 'state': p.state.value,
        'service': p.service, 'version': p.version, 'product': p.product,
        'extrainfo': p.extrainfo, 'banner': p.banner, 'latency': p.latency,
        'risk_score': p.risk_score, 'risk_level': p.risk_level, 'cves': p.cves,
        'conf': p.conf, 'method': p.method,
    }


async def broadcast_to_ws(scan_id: str, data: dict):
    if scan_id not in ws_connections:
        return
    dead = []
    for ws in ws_connections[scan_id]:
        try:
            await ws.send_json(data)
        except Exception:
            dead.append(ws)
    for ws in dead:
        ws_connections[scan_id].remove(ws)


@app.post("/api/scan/{scan_id}/stop")
async def stop_scan(scan_id: str):
    if scan_id not in active_scans:
        raise HTTPException(404, "Scan not found")
    active_scans[scan_id]['status'] = 'stopped'
    return {'message': 'Scan stopping'}


@app.websocket("/ws/{scan_id}")
async def websocket_endpoint(websocket: WebSocket, scan_id: str):
    await websocket.accept()
    if scan_id not in ws_connections:
        ws_connections[scan_id] = []
    ws_connections[scan_id].append(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        if scan_id in ws_connections:
            ws_connections[scan_id].remove(websocket)


@app.get("/api/scan/{scan_id}")
async def get_scan_result(scan_id: str):
    result = get_scan(scan_id)
    if not result:
        raise HTTPException(404, "Scan not found")
    return result


@app.get("/api/scans")
async def list_scans(limit: int = Query(50, le=200), offset: int = 0):
    return {'scans': get_scans(limit, offset)}


@app.delete("/api/scan/{scan_id}")
async def delete_scan_endpoint(scan_id: str):
    delete_scan(scan_id)
    return {'message': 'Scan deleted'}


@app.get("/api/search")
async def search_scans_endpoint(target: str = Query(None), status: str = Query(None), risk_level: str = Query(None)):
    return {'scans': search_scans(target, status, risk_level)}


@app.get("/api/scan/{scan_id}/export")
async def export_scan(scan_id: str, format: str = Query('json')):
    scan_data = get_scan(scan_id)
    if not scan_data:
        raise HTTPException(404, "Scan not found")
    exporters = {'json': export_json, 'csv': export_csv, 'xml': export_xml, 'txt': export_txt}
    exporter = exporters.get(format, export_json)
    content, content_type, filename = exporter(scan_data)
    return Response(content=content, media_type=content_type, headers={'Content-Disposition': f'attachment; filename="{filename}"'})


@app.get("/api/scripts")
async def list_scripts():
    return {'scripts': script_engine.list_scripts()}


@app.post("/api/scripts/{name}/run")
async def run_script(name: str, request_body: dict = Body(...)):
    target = request_body.get('target')
    port = request_body.get('port')
    if not target:
        raise HTTPException(400, "Target is required")
    result = await script_engine.run_script(name, target, port)
    if not result:
        raise HTTPException(404, "Script not found")
    return {'name': result.name, 'category': result.category, 'output': result.output, 'findings': result.findings, 'risk': result.risk}


@app.get("/api/cve/{cve_id}")
async def lookup_cve(cve_id: str):
    result = await cve_db.lookup_cve(cve_id)
    if not result:
        raise HTTPException(404, "CVE not found")
    return result


@app.get("/api/discovery")
async def discover_hosts(targets: str = Query(...), method: str = Query('auto')):
    """
    Discover active hosts on a network.
    
    Examples:
    - Single IP: /api/discovery?targets=192.168.1.1
    - Network: /api/discovery?targets=192.168.1.0/24
    """
    try:
        from discovery.simple import SimpleNetworkDiscovery, NetworkTopology
        
        target_list = [t.strip() for t in targets.split(',')]
        all_hosts = []
        errors = []
        
        for target in target_list:
            try:
                discovery = SimpleNetworkDiscovery(target, timeout=3.0)
                hosts = await discovery.discover()
                all_hosts.extend(hosts)
            except Exception as e:
                errors.append(f"Target '{target}': {str(e)}")
        
        # Build topology for visualization
        topology = NetworkTopology(all_hosts)
        result = topology.to_graph_data()
        
        if errors:
            result['warnings'] = errors
        
        return result
    
    except ImportError as e:
        return {'nodes': [], 'links': [], 'error': f'Module import failed: {str(e)}', 'message': 'Discovery module not found', 'total_hosts': 0}
    except Exception as e:
        import traceback
        return {'nodes': [], 'links': [], 'error': str(e), 'message': f'Discovery failed: {str(e)}', 'traceback': traceback.format_exc(), 'total_hosts': 0}


@app.post("/api/subdomains")
async def enumerate_subdomains(request_body: dict = Body(...)):
    domain = request_body.get('domain', '').strip()
    if not domain:
        raise HTTPException(400, "Domain is required")
    use_api = request_body.get('use_api', True)
    brute_force = request_body.get('brute_force', False)
    from discovery.subdomains import SubdomainEnumerator, DNSBruteForcer
    enum = SubdomainEnumerator(domain)
    results = await enum.enumerate(use_api=use_api)
    if brute_force:
        bf = DNSBruteForcer(domain)
        bf_results = await bf.brute_force()
        existing_ips = {r['ip'] for r in results}
        for r in bf_results:
            if r['ip'] not in existing_ips:
                results.append(r)
    return {'domain': domain, 'subdomains': results, 'count': len(results)}


@app.post("/api/web-scan")
async def web_scan(request_body: dict = Body(...)):
    target = request_body.get('target', '').strip()
    if not target:
        raise HTTPException(400, "Target is required")
    from webapp.scanner import WebAppScanner
    scanner = WebAppScanner(target)
    return await scanner.scan()


@app.post("/api/ssl-scan")
async def ssl_scan(request_body: dict = Body(...)):
    target = request_body.get('target', '').strip()
    port = request_body.get('port', 443)
    if not target:
        raise HTTPException(400, "Target is required")
    from vulns.ssl import SSLAnalyzer
    analyzer = SSLAnalyzer(target, port)
    return await analyzer.analyze()


@app.post("/api/bruteforce")
async def bruteforce(request_body: dict = Body(...)):
    target = request_body.get('target', '').strip()
    services = request_body.get('services', ['ssh', 'ftp'])
    if not target:
        raise HTTPException(400, "Target is required")
    from bruteforce.engine import BruteForceEngine
    engine = BruteForceEngine(target)
    results = await engine.run(services)
    return {'target': target, 'services': services, 'found': results, 'count': len(results)}


@app.get("/api/external/shodan")
async def shodan_lookup(ip: str = Query(...), key: str = Query(None)):
    from integrations.external import ShodanIntegration
    return await ShodanIntegration(key).lookup(ip)


@app.get("/api/external/virustotal")
async def vt_lookup(ip: str = Query(None), domain: str = Query(None), key: str = Query(None)):
    from integrations.external import VirusTotalIntegration
    vt = VirusTotalIntegration(key)
    if ip:
        return await vt.lookup_ip(ip)
    elif domain:
        return await vt.lookup_domain(domain)
    raise HTTPException(400, "ip or domain required")


@app.get("/api/external/hibp")
async def hibp_lookup(email: str = Query(None), password: str = Query(None), key: str = Query(None)):
    from integrations.external import HaveIBeenPwnedIntegration
    hibp = HaveIBeenPwnedIntegration(key)
    if email:
        return await hibp.check_email(email)
    elif password:
        return await hibp.check_password(password)
    raise HTTPException(400, "email or password required")


@app.get("/api/external/censys")
async def censys_lookup(ip: str = Query(...), api_id: str = Query(None), api_secret: str = Query(None)):
    from integrations.external import CensysIntegration
    return await CensysIntegration(api_id, api_secret).lookup(ip)


@app.post("/api/report/generate")
async def generate_report(request_body: dict = Body(...)):
    scan_id = request_body.get('scan_id')
    if not scan_id:
        raise HTTPException(400, "scan_id is required")
    scan_data = get_scan(scan_id)
    if not scan_data:
        raise HTTPException(404, "Scan not found")
    from reports.generator import PDFReportGenerator
    gen = PDFReportGenerator()
    output_path = gen.generate(scan_data)
    return {'report_path': output_path, 'format': 'pdf' if gen._available else 'txt'}


@app.get("/api/report/{scan_id}")
async def download_report(scan_id: str, format: str = Query('txt')):
    scan_data = get_scan(scan_id)
    if not scan_data:
        raise HTTPException(404, "Scan not found")
    from reports.generator import PDFReportGenerator
    gen = PDFReportGenerator()
    ext = 'pdf' if gen._available and format == 'pdf' else 'txt'
    output_path = gen.generate(scan_data)
    from fastapi.responses import FileResponse
    return FileResponse(output_path, filename=f"vois_report_{scan_id}.{ext}")


@app.get("/api/normalize")
async def normalize_url(target: str = Query(...)):
    from utils.normalizer import normalize_target, is_ip, is_cidr, extract_domain
    if is_cidr(target):
        return {'type': 'cidr', 'target': target}
    result = normalize_target(target)
    result['is_ip'] = is_ip(result['hostname'])
    result['domain'] = extract_domain(result['hostname'])
    return result
