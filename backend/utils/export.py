import json
import csv
import io
import xml.etree.ElementTree as ET
from xml.dom import minidom
from datetime import datetime
from typing import Optional


def export_json(scan_data: dict) -> tuple:
    return json.dumps(scan_data, indent=2), 'application/json', 'scan.json'


def export_csv(scan_data: dict) -> tuple:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Port', 'Protocol', 'State', 'Service', 'Version', 'Banner', 'Latency (ms)', 'Risk', 'CVEs'])
    for p in scan_data.get('ports', []):
        writer.writerow([
            p.get('port'), p.get('protocol'), p.get('state'),
            p.get('service'), p.get('version'), p.get('banner', ''),
            p.get('latency', ''), p.get('risk_level', ''),
            p.get('cves', '')
        ])
    return output.getvalue(), 'text/csv', 'scan.csv'


def export_xml(scan_data: dict) -> tuple:
    root = ET.Element('nmaprun')
    root.set('scanner', 'VOIS')
    root.set('version', '2.0')
    root.set('args', f"-sV -p {scan_data.get('start_port', '')}-{scan_data.get('end_port', '')} {scan_data.get('target', '')}")
    root.set('start', str(int(datetime.now().timestamp())))
    root.set('startstr', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

    scaninfo = ET.SubElement(root, 'scaninfo')
    scaninfo.set('type', scan_data.get('scan_type', 'connect'))
    scaninfo.set('protocol', 'tcp')

    host_elem = ET.SubElement(root, 'host')
    ET.SubElement(host_elem, 'address').set('addr', scan_data.get('resolved_ip', ''))
    ET.SubElement(host_elem, 'address').set('addrtype', 'ipv4')

    if scan_data.get('hostname'):
        host_elem.find('.//address').set('addr', scan_data['resolved_ip'])
        hostname_elem = ET.SubElement(host_elem, 'hostnames')
        ET.SubElement(hostname_elem, 'hostname').set('name', scan_data['hostname'])
        ET.SubElement(hostname_elem, 'hostname').set('type', 'PTR')

    ports_elem = ET.SubElement(host_elem, 'ports')
    for p in scan_data.get('ports', []):
        port_elem = ET.SubElement(ports_elem, 'port')
        port_elem.set('portid', str(p.get('port', 0)))
        port_elem.set('protocol', p.get('protocol', 'tcp'))

        state_elem = ET.SubElement(port_elem, 'state')
        state_elem.set('state', p.get('state', 'unknown'))

        service_elem = ET.SubElement(port_elem, 'service')
        service_elem.set('name', p.get('service', 'unknown'))
        if p.get('version'):
            service_elem.set('version', p['version'])
        if p.get('banner'):
            service_elem.set('product', p['banner'][:50])

    runstats = ET.SubElement(root, 'runstats')
    ET.SubElement(runstats, 'finished').set('time', str(int(datetime.now().timestamp())))
    ET.SubElement(runstats, 'hosts').set('up', '1')

    xml_str = minidom.parseString(ET.tostring(root, encoding='unicode')).toprettyxml(indent='  ')
    return xml_str, 'application/xml', 'scan.xml'


def export_txt(scan_data: dict) -> tuple:
    lines = []
    lines.append(f"VOIS Port Scanner Report")
    lines.append(f"{'=' * 60}")
    lines.append(f"Target: {scan_data.get('target', 'N/A')} ({scan_data.get('resolved_ip', 'N/A')})")
    lines.append(f"Scan Type: {scan_data.get('scan_type', 'N/A')}")
    lines.append(f"Ports: {scan_data.get('start_port', '')}-{scan_data.get('end_port', '')}")
    lines.append(f"Elapsed: {scan_data.get('elapsed', 0):.2f}s")
    lines.append(f"Open Ports: {scan_data.get('open_ports_count', 0)}")
    if scan_data.get('risk_level'):
        lines.append(f"Risk Level: {scan_data['risk_level']} ({scan_data.get('risk_score', 0)})")
    lines.append(f"{'=' * 60}\n")

    if scan_data.get('os_family'):
        lines.append(f"OS Detection: {scan_data['os_family']} {scan_data.get('os_version', '')}")
        lines.append(f"Confidence: {scan_data.get('os_confidence', 'N/A')}%\n")

    lines.append("PORT      STATE    SERVICE         VERSION")
    lines.append("-" * 60)

    for p in sorted(scan_data.get('ports', []), key=lambda x: x.get('port', 0)):
        version_str = f" {p.get('version', '')}" if p.get('version') else ''
        banner_str = f" ({p.get('banner', '')[:30]})" if p.get('banner') else ''
        risk_str = f" [{p.get('risk_level', '')}]" if p.get('risk_level') else ''
        lines.append(f"{p.get('port', 0):<10}{p.get('state', 'unknown'):<9}{p.get('service', 'unknown'):<16}{version_str}{banner_str}{risk_str}")

    scripts = scan_data.get('scripts', [])
    if scripts:
        lines.append(f"\n{'=' * 60}")
        lines.append("SCRIPT RESULTS")
        lines.append("-" * 60)
        for s in scripts:
            lines.append(f"\n[{s.get('risk', 'info').upper()}] {s.get('script_name', 'unknown')}")
            lines.append(f"  {s.get('output', '')}")

    lines.append(f"\n{'=' * 60}")
    lines.append(f"Scan completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    return '\n'.join(lines), 'text/plain', 'scan.txt'


def export_nmap_xml(scan_data: dict) -> tuple:
    return export_xml(scan_data)
