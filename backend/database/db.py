import sqlite3
import os
import json
from datetime import datetime
from typing import Optional


DB_PATH = os.path.join(os.path.dirname(__file__), 'vois.db')


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            target TEXT NOT NULL,
            resolved_ip TEXT,
            hostname TEXT,
            scan_type TEXT DEFAULT 'tcp_connect',
            profile TEXT,
            start_port INTEGER,
            end_port INTEGER,
            timing_template INTEGER DEFAULT 3,
            status TEXT DEFAULT 'running',
            started_at TEXT,
            completed_at TEXT,
            elapsed REAL,
            total_ports INTEGER,
            open_ports_count INTEGER DEFAULT 0,
            os_family TEXT,
            os_version TEXT,
            risk_score REAL,
            risk_level TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_ports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT NOT NULL,
            port INTEGER NOT NULL,
            protocol TEXT DEFAULT 'tcp',
            state TEXT NOT NULL,
            service TEXT,
            version TEXT,
            banner TEXT,
            latency REAL,
            risk_score REAL,
            risk_level TEXT,
            cves TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_scripts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT NOT NULL,
            script_name TEXT NOT NULL,
            category TEXT,
            output TEXT,
            findings TEXT,
            risk TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_history (
            id TEXT PRIMARY KEY,
            target TEXT NOT NULL,
            resolved_ip TEXT,
            start_port INTEGER,
            end_port INTEGER,
            open_ports_count INTEGER,
            elapsed REAL,
            status TEXT,
            timestamp TEXT
        )
    ''')

    cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_scan_ports_scan_id ON scan_ports(scan_id)
    ''')
    cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target)
    ''')
    cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at)
    ''')

    conn.commit()
    conn.close()


def save_scan(scan_id: str, target: str, resolved_ip: str, hostname: str,
              scan_type: str, profile: str, start_port: int, end_port: int,
              timing: int, status: str, elapsed: float, total_ports: int,
              open_ports: list, os_info: dict = None, risk: dict = None):
    conn = get_connection()
    cursor = conn.cursor()

    open_count = len([p for p in open_ports if hasattr(p, 'state') and p.state.value == 'open'])
    
    cursor.execute('''
        INSERT OR REPLACE INTO scans (
            id, target, resolved_ip, hostname, scan_type, profile,
            start_port, end_port, timing_template, status,
            started_at, completed_at, elapsed, total_ports,
            open_ports_count, os_family, os_version, risk_score, risk_level
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        scan_id, target, resolved_ip, hostname, scan_type, profile,
        start_port, end_port, timing, status,
        datetime.now().isoformat(), datetime.now().isoformat(), elapsed, total_ports,
        open_count,
        os_info.get('os_family', '') if os_info else '',
        os_info.get('os_version', '') if os_info else '',
        risk.get('score', 0) if risk else 0,
        risk.get('level', 'UNKNOWN') if risk else 'UNKNOWN',
    ))

    for port_result in open_ports:
        # Safely extract CVEs
        cves_list = getattr(port_result, 'cves', [])
        if isinstance(cves_list, str):
            cves_list = [{'id': cves_list}]
        elif not isinstance(cves_list, list):
            cves_list = []
        cves = json.dumps(cves_list)
        
        cursor.execute('''
            INSERT INTO scan_ports (
                scan_id, port, protocol, state, service, version,
                banner, latency, risk_score, risk_level, cves
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            scan_id, port_result.port, port_result.protocol.value, port_result.state.value,
            port_result.service, port_result.version, getattr(port_result, 'banner', ''),
            getattr(port_result, 'latency', 0), 
            getattr(port_result, 'risk_score', 0),
            getattr(port_result, 'risk_level', ''), cves
        ))

    conn.commit()
    conn.close()


def get_scan(scan_id: str) -> Optional[dict]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM scans WHERE id = ?', (scan_id,))
    scan = cursor.fetchone()
    if not scan:
        conn.close()
        return None

    cursor.execute('SELECT * FROM scan_ports WHERE scan_id = ? ORDER BY port', (scan_id,))
    ports = [dict(row) for row in cursor.fetchall()]

    cursor.execute('SELECT * FROM scan_scripts WHERE scan_id = ?', (scan_id,))
    scripts = [dict(row) for row in cursor.fetchall()]

    conn.close()
    return {**dict(scan), 'ports': ports, 'scripts': scripts}


def get_scans(limit: int = 50, offset: int = 0) -> list:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        'SELECT * FROM scans ORDER BY created_at DESC LIMIT ? OFFSET ?',
        (limit, offset)
    )
    scans = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return scans


def delete_scan(scan_id: str):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM scan_ports WHERE scan_id = ?', (scan_id,))
    cursor.execute('DELETE FROM scan_scripts WHERE scan_id = ?', (scan_id,))
    cursor.execute('DELETE FROM scans WHERE id = ?', (scan_id,))
    conn.commit()
    conn.close()


def search_scans(target: str = None, status: str = None, risk_level: str = None) -> list:
    conn = get_connection()
    cursor = conn.cursor()
    query = 'SELECT * FROM scans WHERE 1=1'
    params = []

    if target:
        query += ' AND target LIKE ?'
        params.append(f'%{target}%')
    if status:
        query += ' AND status = ?'
        params.append(status)
    if risk_level:
        query += ' AND risk_level = ?'
        params.append(risk_level)

    query += ' ORDER BY created_at DESC'
    cursor.execute(query, params)
    scans = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return scans


init_db()
