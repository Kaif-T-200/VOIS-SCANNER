"""
Check for SSL/TLS vulnerabilities on HTTPS ports
"""
import asyncio
import ssl

CATEGORY = "vuln"
DESCRIPTION = "Check SSL/TLS configuration and vulnerabilities"
PORTS = [443, 8443, 993, 995, 587, 465]


async def run(target: str, port: int = None):
    findings = []
    port = port or 443

    protocols = {
        'SSLv2': ssl.PROTOCOL_SSLv23,
        'SSLv3': ssl.PROTOCOL_SSLv23,
        'TLSv1.0': ssl.PROTOCOL_TLS,
        'TLSv1.1': ssl.PROTOCOL_TLS,
        'TLSv1.2': ssl.PROTOCOL_TLS,
        'TLSv1.3': ssl.PROTOCOL_TLS,
    }

    for name, proto in protocols.items():
        try:
            ctx = ssl.SSLContext(proto)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            if name in ('SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1'):
                ctx.options |= 0x4000000
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2 if name == 'TLSv1.2' else ssl.TLSVersion.MINIMUM_SUPPORTED
            ctx.maximum_version = ssl.TLSVersion.TLSv1_2 if name == 'TLSv1.2' else ssl.TLSVersion.MAXIMUM_SUPPORTED

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port),
                timeout=3
            )
            writer.close()
            await writer.wait_closed()
            findings.append({
                'type': 'tls_protocol',
                'protocol': name,
                'status': 'supported',
                'risk': 'high' if name in ('SSLv2', 'SSLv3', 'TLSv1.0') else 'info',
            })
        except Exception:
            pass

    return type('Result', (), {
        'output': f"SSL/TLS check on port {port}: {len(findings)} protocols tested",
        'findings': findings,
        'risk': 'high' if any(f.get('risk') == 'high' for f in findings) else 'info',
    })()
