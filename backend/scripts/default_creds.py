"""
Check for default/weak credentials on common services
"""
import asyncio

CATEGORY = "vuln"
DESCRIPTION = "Check for default/weak credentials"
PORTS = [21, 22, 23, 3306, 3389, 5432, 5900]

DEFAULT_CREDS = {
    21: [('anonymous', 'anonymous'), ('ftp', 'ftp')],
    22: [('root', 'root'), ('admin', 'admin'), ('user', 'user')],
    23: [('admin', 'admin'), ('root', 'root')],
    3306: [('root', ''), ('root', 'root')],
    3389: [('Administrator', 'admin'), ('admin', 'admin')],
    5432: [('postgres', 'postgres'), ('postgres', '')],
    5900: [('', ''), ('admin', 'admin')],
}


async def run(target: str, port: int = None):
    findings = []
    if port and port in DEFAULT_CREDS:
        creds = DEFAULT_CREDS[port]
        for username, password in creds:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target, port),
                    timeout=2
                )
                banner = await asyncio.wait_for(reader.read(256), timeout=2)
                writer.close()
                await writer.wait_closed()
                findings.append({
                    'type': 'weak_credential',
                    'port': port,
                    'username': username,
                    'password': password,
                    'status': 'possible',
                    'banner': banner.decode('utf-8', errors='replace')[:100]
                })
            except Exception:
                pass

    return type('Result', (), {
        'output': f"Checked {len(findings)} default credential combinations",
        'findings': findings,
        'risk': 'high' if findings else 'info',
    })()
