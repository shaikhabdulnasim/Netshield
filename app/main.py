"""NetShield v0.1: basic DNS domain blocking, persistent stats, and read-only API."""
import os
import socket
import sqlite3
import threading
import time
from pathlib import Path

import uvicorn
from dnslib import DNSRecord, RCODE, QTYPE
from dnslib.server import BaseResolver, DNSServer, DNSLogger
from fastapi import FastAPI
from fastapi.responses import HTMLResponse

DB_PATH = Path(os.getenv('DB_PATH', '/app/data/queries.db'))
BLOCKLIST_PATH = Path(os.getenv('BLOCKLIST_PATH', '/app/data/blocklist.txt'))
UPSTREAM_HOST = os.getenv('UPSTREAM_HOST', '1.1.1.1')
UPSTREAM_PORT = int(os.getenv('UPSTREAM_PORT', '53'))
DNS_PORT = int(os.getenv('DNS_PORT', '53'))


def connect_db():
    con = sqlite3.connect(DB_PATH, timeout=5)
    con.execute('PRAGMA busy_timeout=5000')
    return con


def initialize():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with connect_db() as con:
        con.execute('''CREATE TABLE IF NOT EXISTS queries
          (id INTEGER PRIMARY KEY, timestamp REAL NOT NULL, client TEXT NOT NULL,
           domain TEXT NOT NULL, qtype TEXT NOT NULL, outcome TEXT NOT NULL)''')


def load_blocklist():
    if not BLOCKLIST_PATH.exists():
        return set()
    return {line.strip().lower().strip('.') for line in BLOCKLIST_PATH.read_text().splitlines()
            if line.strip() and not line.lstrip().startswith('#')}


class Resolver(BaseResolver):
    def __init__(self):
        self.blocked_domains = load_blocklist()

    def resolve(self, request, handler):
        name = str(request.q.qname).lower().rstrip('.')
        qtype = QTYPE[request.q.qtype]
        client = handler.client_address[0]
        labels = name.split('.')
        blocked = any('.'.join(labels[i:]) in self.blocked_domains for i in range(len(labels)))
        outcome = 'blocked' if blocked else 'allowed'
        if blocked:
            response = request.reply()
            response.header.rcode = RCODE.NXDOMAIN
        else:
            try:
                payload = request.send(UPSTREAM_HOST, UPSTREAM_PORT, timeout=3, tcp=handler.protocol == 'tcp')
                response = DNSRecord.parse(payload)
                # Match original transaction ID when forwarding a request.
                response.header.id = request.header.id
            except Exception:
                outcome = 'upstream_error'
                response = request.reply()
                response.header.rcode = RCODE.SERVFAIL
        try:
            with connect_db() as con:
                con.execute('INSERT INTO queries(timestamp,client,domain,qtype,outcome) VALUES (?,?,?,?,?)',
                            (time.time(), client, name, qtype, outcome))
        except sqlite3.Error as ex:
            print(f'Unable to log query: {ex}', flush=True)
        return response


app = FastAPI(title='NetShield', docs_url='/docs')


@app.get('/health')
def health():
    return {'status': 'ok'}


@app.get('/api/stats')
def stats():
    with connect_db() as con:
        rows = con.execute('SELECT outcome, COUNT(*) FROM queries GROUP BY outcome').fetchall()
    counts = dict(rows)
    return {'total': sum(counts.values()), 'blocked': counts.get('blocked', 0),
            'allowed': counts.get('allowed', 0), 'upstream_error': counts.get('upstream_error', 0)}


@app.get('/api/recent')
def recent():
    with connect_db() as con:
        rows = con.execute('SELECT timestamp,client,domain,qtype,outcome FROM queries ORDER BY id DESC LIMIT 30').fetchall()
    return [{'timestamp': r[0], 'client': r[1], 'domain': r[2], 'qtype': r[3], 'outcome': r[4]} for r in rows]


@app.get('/', response_class=HTMLResponse)
def dashboard():
    return '''<!doctype html><html><head><meta charset="utf-8"><title>NetShield</title>
<style>body{font:16px system-ui;margin:3rem auto;max-width:850px;padding:0 1rem;background:#101827;color:#edf4ff} .stats{display:flex;gap:12px;flex-wrap:wrap} .tile{padding:20px;background:#233049;border-radius:10px;min-width:100px} table{width:100%;border-collapse:collapse;margin-top:16px} td,th{padding:9px;border-bottom:1px solid #34445e;text-align:left} small{color:#b1bfd2}</style>
</head><body><h1>NetShield <small>v0.1</small></h1><p>Local DNS filtering and query activity</p>
<div class="stats" id="stats">Loading...</div><h2>Recent queries</h2><table><thead><tr><th>Domain</th><th>Type</th><th>Result</th></tr></thead><tbody id="recent"></tbody></table>
<script>async function reload(){let s=await(await fetch('/api/stats')).json();document.getElementById('stats').replaceChildren(...Object.entries(s).map(([k,v])=>{let d=document.createElement('div');d.className='tile';d.textContent=k+': '+v;return d}));let q=await(await fetch('/api/recent')).json();let b=document.getElementById('recent');b.replaceChildren(...q.map(r=>{let tr=document.createElement('tr');for(let v of [r.domain,r.qtype,r.outcome]){let td=document.createElement('td');td.textContent=v;tr.append(td)}return tr}))}reload();setInterval(reload,5000)</script></body></html>'''


def main():
    initialize()
    resolver = Resolver()
    udp = DNSServer(resolver, port=DNS_PORT, address='0.0.0.0', logger=DNSLogger('-request,-reply,-truncated,-error'))
    tcp = DNSServer(resolver, port=DNS_PORT, address='0.0.0.0', tcp=True, logger=DNSLogger('-request,-reply,-truncated,-error'))
    udp.start_thread()
    tcp.start_thread()
    print(f'NetShield DNS ready on UDP/TCP {DNS_PORT}, upstream {UPSTREAM_HOST}', flush=True)
    uvicorn.run(app, host='0.0.0.0', port=8080)


if __name__ == '__main__':
    main()
