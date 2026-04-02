import json
from datetime import datetime
from typing import Optional


class PDFReportGenerator:
    def __init__(self):
        self._available = False
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.lib import colors
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image
            from reportlab.lib.units import inch
            self._available = True
        except ImportError:
            pass

    def generate(self, scan_data: dict, output_path: str = None) -> Optional[str]:
        if not self._available:
            return self._generate_text_report(scan_data, output_path)
        return self._generate_pdf_report(scan_data, output_path)

    def _generate_pdf_report(self, scan_data: dict, output_path: str = None) -> str:
        from reportlab.lib.pagesizes import letter
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
        from reportlab.lib.units import inch
        from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY

        output_path = output_path or f"vois_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        doc = SimpleDocTemplate(output_path, pagesize=letter, rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=72)
        styles = getSampleStyleSheet()
        styles.add(ParagraphStyle(name='Title', fontSize=24, spaceAfter=20, alignment=TA_CENTER, textColor=colors.HexColor('#6366f1')))
        styles.add(ParagraphStyle(name='Heading1', fontSize=16, spaceBefore=20, spaceAfter=10, textColor=colors.HexColor('#1a1b2e')))
        styles.add(ParagraphStyle(name='Heading2', fontSize=13, spaceBefore=15, spaceAfter=8, textColor=colors.HexColor('#3d4159')))
        styles.add(ParagraphStyle(name='Body', fontSize=10, spaceAfter=8, alignment=TA_JUSTIFY))
        styles.add(ParagraphStyle(name='Small', fontSize=8, spaceAfter=4, textColor=colors.HexColor('#6b7280')))

        elements = []
        elements.append(Paragraph("VOIS Security Scan Report", styles['Title']))
        elements.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Small']))
        elements.append(Paragraph(f"Target: {scan_data.get('target', 'N/A')} ({scan_data.get('resolved_ip', 'N/A')})", styles['Small']))
        elements.append(Spacer(1, 20))

        elements.append(Paragraph("Executive Summary", styles['Heading1']))
        risk = scan_data.get('risk', {})
        elements.append(Paragraph(f"Overall Risk Level: <b>{risk.get('level', 'UNKNOWN')}</b> (Score: {risk.get('score', 0)}/10)", styles['Body']))
        elements.append(Paragraph(f"Open Ports: {scan_data.get('open_ports_count', 0)}", styles['Body']))
        elements.append(Paragraph(f"Scan Duration: {scan_data.get('elapsed', 0):.2f} seconds", styles['Body']))
        elements.append(Paragraph(f"Scan Type: {scan_data.get('scan_type', 'N/A')}", styles['Body']))
        elements.append(Spacer(1, 10))

        if scan_data.get('os_family'):
            elements.append(Paragraph("Operating System Detection", styles['Heading1']))
            elements.append(Paragraph(f"OS: {scan_data.get('os_family', '')} {scan_data.get('os_version', '')}", styles['Body']))
            elements.append(Spacer(1, 10))

        elements.append(Paragraph("Open Ports", styles['Heading1']))
        ports = scan_data.get('ports', [])
        open_ports = [p for p in ports if p.get('state') == 'open']
        if open_ports:
            table_data = [['Port', 'Protocol', 'Service', 'Version', 'Risk', 'CVEs']]
            for p in open_ports:
                cves = json.loads(p.get('cves', '[]')) if isinstance(p.get('cves'), str) else p.get('cves', [])
                table_data.append([
                    str(p.get('port', '')),
                    p.get('protocol', ''),
                    p.get('service', ''),
                    p.get('version', '') or p.get('product', '') or '—',
                    p.get('risk_level', '—'),
                    ', '.join(cves) if cves else '—'
                ])
            t = Table(table_data, colWidths=[0.6*inch, 0.6*inch, 1.2*inch, 1.5*inch, 0.8*inch, 1.3*inch])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#6366f1')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e4e9')),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f5f6f8')]),
            ]))
            elements.append(t)

        elements.append(PageBreak())
        elements.append(Paragraph("Vulnerability Details", styles['Heading1']))
        vulns = []
        for p in open_ports:
            cves = json.loads(p.get('cves', '[]')) if isinstance(p.get('cves'), str) else p.get('cves', [])
            for cve in cves:
                vulns.append({'port': p.get('port'), 'service': p.get('service'), 'cve': cve, 'risk': p.get('risk_level', 'unknown')})
        if vulns:
            for v in vulns:
                elements.append(Paragraph(f"<b>{v['cve']}</b> — Port {v['port']}/{v['service']} [{v['risk'].upper()}]", styles['Heading2']))
        else:
            elements.append(Paragraph("No known vulnerabilities detected.", styles['Body']))

        elements.append(Spacer(1, 20))
        elements.append(Paragraph("Recommendations", styles['Heading1']))
        recommendations = []
        if risk.get('level') in ('CRITICAL', 'HIGH'):
            recommendations.append("Immediate action required. Critical/high risk services detected.")
        for p in open_ports:
            if p.get('port') == 23:
                recommendations.append("Disable Telnet (port 23) and use SSH instead.")
            if p.get('port') == 21:
                recommendations.append("Consider replacing FTP with SFTP or SCP.")
            if p.get('port') == 3389:
                recommendations.append("Restrict RDP access to specific IPs and enable NLA.")
            if p.get('port') == 445:
                recommendations.append("Ensure SMB is patched against EternalBlue (MS17-010).")
            cves = json.loads(p.get('cves', '[]')) if isinstance(p.get('cves'), str) else p.get('cves', [])
            if cves:
                recommendations.append(f"Update {p.get('service', 'service')} on port {p.get('port')} — {len(cves)} known CVE(s).")
        for rec in recommendations:
            elements.append(Paragraph(f"• {rec}", styles['Body']))

        elements.append(Spacer(1, 30))
        elements.append(Paragraph(f"Report generated by VOIS Port Scanner v3.0 — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Small']))

        doc.build(elements)
        return output_path

    def _generate_text_report(self, scan_data: dict, output_path: str = None) -> str:
        output_path = output_path or f"vois_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        lines = []
        lines.append("=" * 70)
        lines.append("VOIS SECURITY SCAN REPORT")
        lines.append("=" * 70)
        lines.append(f"Target: {scan_data.get('target', 'N/A')} ({scan_data.get('resolved_ip', 'N/A')})")
        lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"Scan Type: {scan_data.get('scan_type', 'N/A')}")
        lines.append(f"Risk Level: {scan_data.get('risk', {}).get('level', 'UNKNOWN')}")
        lines.append(f"Open Ports: {scan_data.get('open_ports_count', 0)}")
        lines.append(f"Duration: {scan_data.get('elapsed', 0):.2f}s")
        lines.append("=" * 70)
        lines.append("")
        lines.append("OPEN PORTS:")
        lines.append("-" * 70)
        for p in scan_data.get('ports', []):
            if p.get('state') == 'open':
                cves = json.loads(p.get('cves', '[]')) if isinstance(p.get('cves'), str) else p.get('cves', [])
                lines.append(f"  Port {p.get('port')}/{p.get('protocol')} - {p.get('service')} {p.get('version', '')} [{p.get('risk_level', 'unknown')}]")
                if cves:
                    for cve in cves:
                        lines.append(f"    CVE: {cve}")
        lines.append("")
        lines.append("=" * 70)
        lines.append(f"Generated by VOIS Port Scanner v3.0")
        with open(output_path, 'w') as f:
            f.write('\n'.join(lines))
        return output_path
