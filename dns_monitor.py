#!/usr/bin/env python3
"""DNS Chain Monitor - Async DNS monitoring for diagnosing upstream DNS issues.

Tests multiple DNS servers, tracks TTLs, checks DoH, validates end-to-end
reachability of resolved IPs, and detects transparent DNS interception.

Designed for Rogers ISP DNS troubleshooting in Calgary.

Usage:
    python3 dns_monitor.py                        # 24-hour run, 60s interval
    DURATION=300 INTERVAL=15 python3 dns_monitor.py  # 5-min quick test
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import sqlite3
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

try:
    import dns.asyncquery
    import dns.flags
    import dns.message
    import dns.rcode
    import dns.rdatatype
    import dns.asyncresolver
    import httpx
except ImportError:
    print("Missing dependencies. Install with:")
    print("  pip install -r requirements.txt")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SCRIPT_DIR = Path(__file__).parent
DATA_DIR = SCRIPT_DIR / "data"
DB_FILE = DATA_DIR / "dns_monitoring.db"
LOG_FILE = DATA_DIR / f"dns_test_{time.strftime('%Y%m%d_%H%M%S')}.log"

DURATION = int(os.environ.get("DURATION", 86400))
INTERVAL = int(os.environ.get("INTERVAL", 60))

DNS_SERVERS: dict[str, str] = {
    "8.8.8.8":        "Google Primary",
    "8.8.4.4":        "Google Secondary",
    "1.1.1.1":        "Cloudflare Primary",
    "1.0.0.1":        "Cloudflare Secondary",
    "64.59.135.135":  "Rogers Primary",
    "64.59.128.112":  "Rogers Secondary",
}

STREAMING_DOMAINS = [
    "netflix.com", "nflxvideo.net", "nflxext.com", "nflxso.net",
    "tv.apple.com", "play.itunes.apple.com", "hls.itunes.apple.com", "ocsp.apple.com",
    "youtube.com", "googlevideo.com", "ytimg.com",
    "facebook.com", "fbcdn.net", "instagram.com",
]

TEST_DOMAINS = [
    "google.com", "cloudflare.com", "github.com", "stackoverflow.com",
] + STREAMING_DOMAINS

CDN_DOMAINS = {
    "netflix.com", "nflxvideo.net", "googlevideo.com", "ytimg.com",
    "fbcdn.net", "instagram.com",
}

HTTP_TEST_DOMAINS = ["youtube.com", "facebook.com", "google.com", "netflix.com"]

DOH_PROVIDERS = {
    "https://dns.google/dns-query":       "Google DoH",
    "https://cloudflare-dns.com/dns-query": "Cloudflare DoH",
}

# Servers and domains used for end-to-end reachability validation
E2E_SERVERS = ["64.59.135.135", "8.8.8.8", "1.1.1.1"]
E2E_DOMAINS = ["youtube.com", "facebook.com", "instagram.com", "netflix.com"]

# How often (in iterations) to run expensive/periodic tests
HTTP_EVERY   = 5
E2E_EVERY    = 5
INTERCEPT_EVERY = 10
HIJACK_EVERY    = 10
DOH_EVERY       = 10

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class QueryResult:
    server: str
    server_name: str
    domain: str
    query_type: str
    status: str
    response_time_ms: float
    addresses: list[str] = field(default_factory=list)
    ttl: int | None = None
    failure_mode: str = ""

@dataclass
class ReachabilityResult:
    server: str
    server_name: str
    reachable: bool
    response_time_ms: float

@dataclass
class HttpResult:
    domain: str
    http_code: int
    total_time_ms: float

@dataclass
class InterceptionResult:
    server: str
    server_name: str
    domain: str
    udp_result: str
    tcp_result: str
    is_intercepted: bool

@dataclass
class HijackResult:
    server: str
    server_name: str
    test_domain: str
    returned_ip: str
    is_hijacked: bool

@dataclass
class DohResult:
    provider: str
    provider_name: str
    domain: str
    status: str
    addresses: list[str] = field(default_factory=list)
    response_time_ms: float = 0
    ttl: int | None = None

@dataclass
class E2EResult:
    dns_server: str
    dns_server_name: str
    domain: str
    resolved_ip: str
    reachable: bool
    connect_time_ms: float

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def setup_logging() -> logging.Logger:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    log = logging.getLogger("dns_monitor")
    log.setLevel(logging.INFO)
    fmt = logging.Formatter("[%(asctime)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")

    fh = logging.FileHandler(LOG_FILE)
    fh.setFormatter(fmt)
    log.addHandler(fh)

    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(fmt)
    log.addHandler(ch)

    return log

log = setup_logging()

# ---------------------------------------------------------------------------
# System detection
# ---------------------------------------------------------------------------

def detect_router_ip() -> str | None:
    """Detect the default gateway (router) IP."""
    try:
        r = subprocess.run(["ip", "route", "show", "default"],
                           capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines():
            parts = line.split()
            if "via" in parts:
                return parts[parts.index("via") + 1]
    except Exception:
        pass
    return None

def detect_system_nameservers() -> list[str]:
    """Read nameservers from /etc/resolv.conf (skip loopback)."""
    ns = []
    try:
        for line in Path("/etc/resolv.conf").read_text().splitlines():
            if line.strip().startswith("nameserver"):
                ip = line.split()[1]
                if not ip.startswith("127."):
                    ns.append(ip)
    except Exception:
        pass
    return ns

# ---------------------------------------------------------------------------
# DNS query functions
# ---------------------------------------------------------------------------

async def query_dns(server: str, domain: str, rdtype: str = "A",
                    use_tcp: bool = False, timeout: float = 2.0) -> QueryResult:
    """Query a specific DNS server for a domain record."""
    server_name = DNS_SERVERS.get(server, server)
    start = time.monotonic()
    try:
        q = dns.message.make_query(domain, rdtype)
        if use_tcp:
            resp = await dns.asyncquery.tcp(q, server, timeout=timeout)
        else:
            resp = await dns.asyncquery.udp(q, server, timeout=timeout)

        # Retry over TCP if response was truncated
        if not use_tcp and resp.flags & dns.flags.TC:
            return await query_dns(server, domain, rdtype, use_tcp=True, timeout=timeout)

        elapsed = (time.monotonic() - start) * 1000
        rc = resp.rcode()
        for code, label in ((dns.rcode.NXDOMAIN, "NXDOMAIN"),
                            (dns.rcode.SERVFAIL, "SERVFAIL"),
                            (dns.rcode.REFUSED,  "REFUSED")):
            if rc == code:
                return QueryResult(server, server_name, domain, rdtype,
                                   label, elapsed, [], None, label)

        target = dns.rdatatype.from_text(rdtype)
        addresses: list[str] = []
        min_ttl: int | None = None
        for rrset in resp.answer:
            if rrset.rdtype == target:
                if min_ttl is None or rrset.ttl < min_ttl:
                    min_ttl = rrset.ttl
                addresses.extend(rdata.address for rdata in rrset)

        if addresses:
            return QueryResult(server, server_name, domain, rdtype,
                               "OK", elapsed, addresses, min_ttl, "")
        return QueryResult(server, server_name, domain, rdtype,
                           "NODATA", elapsed, [], None, "NODATA")

    except dns.exception.Timeout:
        elapsed = (time.monotonic() - start) * 1000
        return QueryResult(server, server_name, domain, rdtype,
                           "TIMEOUT", elapsed, [], None, "TIMEOUT")
    except OSError as e:
        elapsed = (time.monotonic() - start) * 1000
        mode = "NETUNREACH" if "unreachable" in str(e).lower() else str(e)[:80]
        status = "NETUNREACH" if mode == "NETUNREACH" else "FAIL"
        return QueryResult(server, server_name, domain, rdtype,
                           status, elapsed, [], None, mode)
    except Exception as e:
        elapsed = (time.monotonic() - start) * 1000
        return QueryResult(server, server_name, domain, rdtype,
                           "FAIL", elapsed, [], None, str(e)[:80])


async def query_system_dns(domain: str, rdtype: str = "A") -> QueryResult:
    """Query using the system resolver (what devices on the network actually use)."""
    start = time.monotonic()
    try:
        resolver = dns.asyncresolver.Resolver()
        answers = await asyncio.wait_for(
            resolver.resolve(domain, rdtype), timeout=3.0
        )
        elapsed = (time.monotonic() - start) * 1000
        addresses = [rdata.address for rdata in answers]
        ttl = answers.rrset.ttl if answers.rrset else None
        return QueryResult("system", "System Resolver", domain, rdtype,
                           "OK", elapsed, addresses, ttl, "")
    except dns.resolver.NXDOMAIN:
        elapsed = (time.monotonic() - start) * 1000
        return QueryResult("system", "System Resolver", domain, rdtype,
                           "NXDOMAIN", elapsed, [], None, "NXDOMAIN")
    except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        elapsed = (time.monotonic() - start) * 1000
        return QueryResult("system", "System Resolver", domain, rdtype,
                           "NODATA", elapsed, [], None, "NODATA")
    except (dns.exception.Timeout, asyncio.TimeoutError):
        elapsed = (time.monotonic() - start) * 1000
        return QueryResult("system", "System Resolver", domain, rdtype,
                           "TIMEOUT", elapsed, [], None, "TIMEOUT")
    except Exception as e:
        elapsed = (time.monotonic() - start) * 1000
        return QueryResult("system", "System Resolver", domain, rdtype,
                           "FAIL", elapsed, [], None, str(e)[:80])

# ---------------------------------------------------------------------------
# Auxiliary test functions
# ---------------------------------------------------------------------------

async def test_reachability(server: str) -> ReachabilityResult:
    """Test DNS server reachability with a lightweight root NS query."""
    name = DNS_SERVERS.get(server, server)
    start = time.monotonic()
    try:
        q = dns.message.make_query(".", "NS")
        await dns.asyncquery.udp(q, server, timeout=1.5)
        return ReachabilityResult(server, name, True,
                                  (time.monotonic() - start) * 1000)
    except Exception:
        return ReachabilityResult(server, name, False,
                                  (time.monotonic() - start) * 1000)


async def test_http(domain: str) -> HttpResult:
    """Test HTTPS connectivity and measure total time."""
    start = time.monotonic()
    try:
        async with httpx.AsyncClient(
            follow_redirects=True, timeout=10.0, verify=True,
            http2=True,
        ) as client:
            resp = await client.get(f"https://{domain}/")
            elapsed = (time.monotonic() - start) * 1000
            return HttpResult(domain, resp.status_code, elapsed)
    except Exception:
        elapsed = (time.monotonic() - start) * 1000
        return HttpResult(domain, 0, elapsed)


async def test_interception(server: str) -> InterceptionResult:
    """Detect transparent DNS interception (ISP hijacking UDP port 53)."""
    name = DNS_SERVERS.get(server, server)
    domain = "google.com"
    try:
        udp = await query_dns(server, domain, "A", use_tcp=False)
        tcp = await query_dns(server, domain, "A", use_tcp=True)
        udp_ips = sorted(udp.addresses) if udp.status == "OK" else []
        tcp_ips = sorted(tcp.addresses) if tcp.status == "OK" else []
        intercepted = bool(udp_ips and tcp_ips and udp_ips != tcp_ips)
        return InterceptionResult(server, name, domain,
                                  ",".join(udp_ips), ",".join(tcp_ips), intercepted)
    except Exception:
        return InterceptionResult(server, name, domain, "", "", False)


async def test_hijacking(server: str) -> HijackResult:
    """Query a guaranteed-nonexistent domain to detect NXDOMAIN hijacking."""
    name = DNS_SERVERS.get(server, server)
    fake = f"nxtest{int(time.time()*1000)}.example.invalid"
    r = await query_dns(server, fake, "A")
    ip = r.addresses[0] if r.addresses else ""
    return HijackResult(server, name, fake, ip, bool(r.addresses))


async def test_doh(provider_url: str, domain: str) -> DohResult:
    """Perform a DNS-over-HTTPS query (RFC 8484 wire format)."""
    pname = DOH_PROVIDERS.get(provider_url, provider_url)
    start = time.monotonic()
    try:
        q = dns.message.make_query(domain, "A")
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(
                provider_url, content=q.to_wire(),
                headers={"Content-Type": "application/dns-message",
                         "Accept": "application/dns-message"},
            )
        elapsed = (time.monotonic() - start) * 1000
        if resp.status_code != 200:
            return DohResult(provider_url, pname, domain, "HTTP_ERROR",
                             [], elapsed, None)
        dr = dns.message.from_wire(resp.content)
        if dr.rcode() != dns.rcode.NOERROR:
            return DohResult(provider_url, pname, domain,
                             dns.rcode.to_text(dr.rcode()), [], elapsed, None)
        addrs: list[str] = []
        ttl: int | None = None
        for rrset in dr.answer:
            if rrset.rdtype == dns.rdatatype.A:
                if ttl is None or rrset.ttl < ttl:
                    ttl = rrset.ttl
                addrs.extend(rd.address for rd in rrset)
        return DohResult(provider_url, pname, domain,
                         "OK" if addrs else "NODATA", addrs, elapsed, ttl)
    except Exception:
        elapsed = (time.monotonic() - start) * 1000
        return DohResult(provider_url, pname, domain, "FAIL", [], elapsed, None)


async def test_e2e(server: str, domain: str,
                   query_results: list[QueryResult]) -> E2EResult | None:
    """End-to-end: find the IP this server resolved, then TCP-connect to it."""
    name = DNS_SERVERS.get(server, server)
    # Find the A-record result for this server+domain from this iteration
    for qr in query_results:
        if qr.server == server and qr.domain == domain and qr.query_type == "A" and qr.addresses:
            ip = qr.addresses[0]
            start = time.monotonic()
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, 443), timeout=5.0)
                elapsed = (time.monotonic() - start) * 1000
                writer.close()
                await writer.wait_closed()
                return E2EResult(server, name, domain, ip, True, elapsed)
            except (asyncio.TimeoutError, OSError):
                elapsed = (time.monotonic() - start) * 1000
                return E2EResult(server, name, domain, ip, False, elapsed)
    return None

# ---------------------------------------------------------------------------
# IP change tracker (in-memory, avoids per-domain DB queries)
# ---------------------------------------------------------------------------

class IPChangeTracker:
    def __init__(self) -> None:
        self.last_seen: dict[tuple[str, str], set[str]] = {}
        self.last_change_ts: dict[tuple[str, str], float] = {}

    def check(self, domain: str, server: str, new_ips: list[str]
              ) -> tuple[bool, set[str], set[str], int]:
        """Returns (changed, old_set, new_set, seconds_since_last_change)."""
        key = (domain, server)
        new_set = set(sorted(new_ips))
        old_set = self.last_seen.get(key, set())
        now = time.time()
        changed = bool(old_set) and old_set != new_set
        secs = 0
        if changed:
            prev = self.last_change_ts.get(key)
            secs = int(now - prev) if prev else 0
            self.last_change_ts[key] = now
        self.last_seen[key] = new_set
        return changed, old_set, new_set, secs

# ---------------------------------------------------------------------------
# Consistency checker (uses already-collected results, no extra queries)
# ---------------------------------------------------------------------------

def check_consistency(domain: str, query_results: list[QueryResult]
                      ) -> tuple[bool, str]:
    """Compare A-record IPs across all servers for a domain."""
    server_ips: dict[str, str] = {}
    for qr in query_results:
        if qr.domain == domain and qr.query_type == "A" and qr.status == "OK":
            server_ips[qr.server] = ",".join(sorted(qr.addresses))
    if len(server_ips) < 2:
        return True, ""
    vals = list(server_ips.values())
    consistent = all(v == vals[0] for v in vals)
    detail = ";".join(f"{s}={ips}" for s, ips in server_ips.items())
    return consistent, detail

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS test_runs (
    run_id INTEGER PRIMARY KEY AUTOINCREMENT,
    start_time DATETIME DEFAULT CURRENT_TIMESTAMP,
    end_time DATETIME,
    total_tests INTEGER,
    total_failures INTEGER
);

CREATE TABLE IF NOT EXISTS dns_queries (
    query_id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    dns_server TEXT,
    dns_server_name TEXT,
    domain TEXT,
    query_type TEXT DEFAULT 'A',
    status TEXT,
    response_time_ms REAL,
    ip_addresses TEXT,
    ttl INTEGER,
    failure_mode TEXT,
    FOREIGN KEY (run_id) REFERENCES test_runs(run_id)
);

CREATE TABLE IF NOT EXISTS ip_changes (
    change_id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT,
    dns_server TEXT,
    dns_server_name TEXT,
    old_ips TEXT,
    new_ips TEXT,
    change_time DATETIME DEFAULT CURRENT_TIMESTAMP,
    time_since_last_change_seconds INTEGER
);

CREATE TABLE IF NOT EXISTS dns_reachability (
    reach_id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    dns_server TEXT,
    dns_server_name TEXT,
    reachable BOOLEAN,
    ping_time_ms REAL,
    FOREIGN KEY (run_id) REFERENCES test_runs(run_id)
);

CREATE TABLE IF NOT EXISTS recursion_tests (
    recursion_id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    domain TEXT,
    dns_server TEXT,
    dns_server_name TEXT,
    recursion_depth INTEGER,
    root_servers_queried TEXT,
    tld_servers_queried TEXT,
    authoritative_servers_queried TEXT,
    total_time_ms REAL,
    status TEXT,
    failure_point TEXT,
    FOREIGN KEY (run_id) REFERENCES test_runs(run_id)
);

CREATE TABLE IF NOT EXISTS dns_hijacking (
    hijack_id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    dns_server TEXT,
    dns_server_name TEXT,
    test_domain TEXT,
    returned_ip TEXT,
    is_hijacked BOOLEAN,
    FOREIGN KEY (run_id) REFERENCES test_runs(run_id)
);

CREATE TABLE IF NOT EXISTS consistency_checks (
    check_id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    domain TEXT,
    is_consistent BOOLEAN,
    server_responses TEXT,
    FOREIGN KEY (run_id) REFERENCES test_runs(run_id)
);

CREATE TABLE IF NOT EXISTS interception_tests (
    test_id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    dns_server TEXT,
    dns_server_name TEXT,
    domain TEXT,
    udp_result TEXT,
    tcp_result TEXT,
    is_intercepted BOOLEAN,
    FOREIGN KEY (run_id) REFERENCES test_runs(run_id)
);

CREATE TABLE IF NOT EXISTS http_tests (
    http_id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    domain TEXT,
    http_code INTEGER,
    dns_time_ms REAL,
    connect_time_ms REAL,
    total_time_ms REAL,
    FOREIGN KEY (run_id) REFERENCES test_runs(run_id)
);

CREATE TABLE IF NOT EXISTS doh_tests (
    doh_id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    provider TEXT,
    provider_name TEXT,
    domain TEXT,
    query_type TEXT DEFAULT 'A',
    status TEXT,
    ip_addresses TEXT,
    response_time_ms REAL,
    ttl INTEGER,
    FOREIGN KEY (run_id) REFERENCES test_runs(run_id)
);

CREATE TABLE IF NOT EXISTS e2e_tests (
    e2e_id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    dns_server TEXT,
    dns_server_name TEXT,
    domain TEXT,
    resolved_ip TEXT,
    reachable BOOLEAN,
    connect_time_ms REAL,
    FOREIGN KEY (run_id) REFERENCES test_runs(run_id)
);

CREATE INDEX IF NOT EXISTS idx_queries_run ON dns_queries(run_id);
CREATE INDEX IF NOT EXISTS idx_queries_domain ON dns_queries(domain);
CREATE INDEX IF NOT EXISTS idx_queries_timestamp ON dns_queries(timestamp);
CREATE INDEX IF NOT EXISTS idx_queries_status ON dns_queries(status);
CREATE INDEX IF NOT EXISTS idx_ip_changes_domain ON ip_changes(domain);
CREATE INDEX IF NOT EXISTS idx_recursion_status ON recursion_tests(status);
CREATE INDEX IF NOT EXISTS idx_doh_run ON doh_tests(run_id);
CREATE INDEX IF NOT EXISTS idx_e2e_run ON e2e_tests(run_id);
"""


def init_database() -> None:
    conn = sqlite3.connect(DB_FILE)
    conn.executescript(SCHEMA_SQL)
    # Migration: add ttl column to existing databases
    try:
        conn.execute("SELECT ttl FROM dns_queries LIMIT 0")
    except sqlite3.OperationalError:
        conn.execute("ALTER TABLE dns_queries ADD COLUMN ttl INTEGER")
    conn.commit()
    conn.close()


def start_run() -> int:
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT INTO test_runs (start_time) VALUES (datetime('now'))")
    run_id = c.lastrowid
    conn.commit()
    conn.close()
    return run_id


def end_run(run_id: int, iterations: int, failures: int) -> None:
    conn = sqlite3.connect(DB_FILE)
    conn.execute(
        "UPDATE test_runs SET end_time=datetime('now'), total_tests=?, total_failures=? WHERE run_id=?",
        (iterations, failures, run_id))
    conn.commit()
    conn.close()


def batch_insert(run_id: int, *,
                 queries: list[QueryResult],
                 reachability: list[ReachabilityResult],
                 http_results: list[HttpResult],
                 interceptions: list[InterceptionResult],
                 hijacks: list[HijackResult],
                 consistency: list[tuple[str, bool, str]],
                 ip_changes: list[tuple[str, str, str, str, str, int]],
                 doh_results: list[DohResult],
                 e2e_results: list[E2EResult]) -> None:
    conn = sqlite3.connect(DB_FILE)
    try:
        c = conn.cursor()
        if queries:
            c.executemany(
                """INSERT INTO dns_queries
                   (run_id,dns_server,dns_server_name,domain,query_type,
                    status,response_time_ms,ip_addresses,ttl,failure_mode)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                [(run_id, r.server, r.server_name, r.domain, r.query_type,
                  r.status, r.response_time_ms, ",".join(r.addresses),
                  r.ttl, r.failure_mode) for r in queries])
        if reachability:
            c.executemany(
                """INSERT INTO dns_reachability
                   (run_id,dns_server,dns_server_name,reachable,ping_time_ms)
                   VALUES (?,?,?,?,?)""",
                [(run_id, r.server, r.server_name, r.reachable,
                  r.response_time_ms) for r in reachability])
        if http_results:
            c.executemany(
                """INSERT INTO http_tests
                   (run_id,domain,http_code,dns_time_ms,connect_time_ms,total_time_ms)
                   VALUES (?,?,?,0,0,?)""",
                [(run_id, r.domain, r.http_code, r.total_time_ms)
                 for r in http_results])
        if interceptions:
            c.executemany(
                """INSERT INTO interception_tests
                   (run_id,dns_server,dns_server_name,domain,udp_result,tcp_result,is_intercepted)
                   VALUES (?,?,?,?,?,?,?)""",
                [(run_id, r.server, r.server_name, r.domain,
                  r.udp_result, r.tcp_result, r.is_intercepted)
                 for r in interceptions])
        if hijacks:
            c.executemany(
                """INSERT INTO dns_hijacking
                   (run_id,dns_server,dns_server_name,test_domain,returned_ip,is_hijacked)
                   VALUES (?,?,?,?,?,?)""",
                [(run_id, r.server, r.server_name, r.test_domain,
                  r.returned_ip, r.is_hijacked) for r in hijacks])
        if consistency:
            c.executemany(
                """INSERT INTO consistency_checks
                   (run_id,domain,is_consistent,server_responses)
                   VALUES (?,?,?,?)""",
                [(run_id, d, con, resp) for d, con, resp in consistency])
        if ip_changes:
            c.executemany(
                """INSERT INTO ip_changes
                   (domain,dns_server,dns_server_name,old_ips,new_ips,time_since_last_change_seconds)
                   VALUES (?,?,?,?,?,?)""",
                ip_changes)
        if doh_results:
            c.executemany(
                """INSERT INTO doh_tests
                   (run_id,provider,provider_name,domain,query_type,status,
                    ip_addresses,response_time_ms,ttl)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                [(run_id, r.provider, r.provider_name, r.domain, "A",
                  r.status, ",".join(r.addresses), r.response_time_ms, r.ttl)
                 for r in doh_results])
        if e2e_results:
            c.executemany(
                """INSERT INTO e2e_tests
                   (run_id,dns_server,dns_server_name,domain,resolved_ip,reachable,connect_time_ms)
                   VALUES (?,?,?,?,?,?,?)""",
                [(run_id, r.dns_server, r.dns_server_name, r.domain,
                  r.resolved_ip, r.reachable, r.connect_time_ms)
                 for r in e2e_results])
        conn.commit()
    finally:
        conn.close()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

FAILURE_STATUSES = {"FAIL", "TIMEOUT", "NETUNREACH", "NOSERVER", "SERVFAIL", "REFUSED"}

def pct(data: list[float], p: float) -> float:
    """Percentile calculation."""
    if not data:
        return 0.0
    s = sorted(data)
    k = (len(s) - 1) * p / 100
    lo = int(k)
    hi = min(lo + 1, len(s) - 1)
    return s[lo] + (k - lo) * (s[hi] - s[lo])

# ---------------------------------------------------------------------------
# Main monitoring loop
# ---------------------------------------------------------------------------

async def run_iteration(run_id: int, iteration: int,
                        ip_tracker: IPChangeTracker,
                        query_results_out: list[QueryResult]) -> int:
    """Run one monitoring iteration. Returns number of failures detected."""
    failures = 0
    all_servers = list(DNS_SERVERS.keys())

    # ------ Phase 1: Build and launch all async tasks ------
    dns_tasks: list[asyncio.Task] = []

    # A records for all domains × all servers + system
    for domain in TEST_DOMAINS:
        dns_tasks.append(asyncio.ensure_future(query_system_dns(domain, "A")))
        for srv in all_servers:
            dns_tasks.append(asyncio.ensure_future(query_dns(srv, domain, "A")))

    # AAAA records for streaming domains × all servers + system
    for domain in STREAMING_DOMAINS:
        dns_tasks.append(asyncio.ensure_future(query_system_dns(domain, "AAAA")))
        for srv in all_servers:
            dns_tasks.append(asyncio.ensure_future(query_dns(srv, domain, "AAAA")))

    # Reachability
    reach_tasks = [asyncio.ensure_future(test_reachability(s)) for s in all_servers]

    # Periodic: HTTP
    http_tasks = []
    if iteration % HTTP_EVERY == 0:
        http_tasks = [asyncio.ensure_future(test_http(d)) for d in HTTP_TEST_DOMAINS]

    # Periodic: Interception + hijacking
    intercept_tasks = []
    hijack_tasks = []
    if iteration % INTERCEPT_EVERY == 0:
        intercept_tasks = [asyncio.ensure_future(test_interception(s)) for s in all_servers]
        hijack_tasks = [asyncio.ensure_future(test_hijacking(s)) for s in all_servers]

    # Periodic: DoH
    doh_tasks = []
    if iteration % DOH_EVERY == 0:
        for url in DOH_PROVIDERS:
            for d in E2E_DOMAINS:
                doh_tasks.append(asyncio.ensure_future(test_doh(url, d)))

    # Await all DNS queries + other tasks concurrently
    all_tasks = dns_tasks + reach_tasks + http_tasks + intercept_tasks + hijack_tasks + doh_tasks
    raw_results = await asyncio.gather(*all_tasks, return_exceptions=True)

    # ------ Phase 2: Classify results ------
    query_results: list[QueryResult] = []
    reach_results: list[ReachabilityResult] = []
    http_results: list[HttpResult] = []
    intercept_results: list[InterceptionResult] = []
    hijack_results: list[HijackResult] = []
    doh_results_list: list[DohResult] = []

    for r in raw_results:
        if isinstance(r, QueryResult):
            query_results.append(r)
        elif isinstance(r, ReachabilityResult):
            reach_results.append(r)
        elif isinstance(r, HttpResult):
            http_results.append(r)
        elif isinstance(r, InterceptionResult):
            intercept_results.append(r)
        elif isinstance(r, HijackResult):
            hijack_results.append(r)
        elif isinstance(r, DohResult):
            doh_results_list.append(r)
        elif isinstance(r, Exception):
            log.warning(f"Task exception: {r}")

    # Share query results with caller for E2E tests
    query_results_out.extend(query_results)

    # ------ Phase 3: E2E tests (need query results first) ------
    e2e_results: list[E2EResult] = []
    if iteration % E2E_EVERY == 0:
        e2e_tasks = []
        for srv in E2E_SERVERS:
            for d in E2E_DOMAINS:
                e2e_tasks.append(test_e2e(srv, d, query_results))
        e2e_raw = await asyncio.gather(*e2e_tasks, return_exceptions=True)
        e2e_results = [r for r in e2e_raw if isinstance(r, E2EResult)]

    # ------ Phase 4: In-memory analysis ------

    # IP change detection
    ip_change_records: list[tuple[str, str, str, str, str, int]] = []
    for qr in query_results:
        if (qr.domain in STREAMING_DOMAINS and qr.query_type == "A"
                and qr.status == "OK" and qr.addresses):
            changed, old_set, new_set, secs = ip_tracker.check(
                qr.domain, qr.server, qr.addresses)
            if changed:
                sname = DNS_SERVERS.get(qr.server, qr.server)
                ip_change_records.append((
                    qr.domain, qr.server, sname,
                    ",".join(sorted(old_set)), ",".join(sorted(new_set)), secs))
                log.info(f"IP CHANGE: {qr.domain} via {sname}: "
                         f"{','.join(sorted(old_set))} -> {','.join(sorted(new_set))}")

    # Consistency checks (every 5th, skip CDN domains)
    consistency_records: list[tuple[str, bool, str]] = []
    if iteration % HTTP_EVERY == 0:
        for domain in TEST_DOMAINS:
            if domain in CDN_DOMAINS:
                continue
            consistent, detail = check_consistency(domain, query_results)
            consistency_records.append((domain, consistent, detail))
            if not consistent:
                log.warning(f"INCONSISTENT: {domain} - {detail}")

    # ------ Phase 5: Batch insert ------
    batch_insert(
        run_id,
        queries=query_results,
        reachability=reach_results,
        http_results=http_results,
        interceptions=intercept_results,
        hijacks=hijack_results,
        consistency=consistency_records,
        ip_changes=ip_change_records,
        doh_results=doh_results_list,
        e2e_results=e2e_results,
    )

    # ------ Phase 6: Console summary ------

    # Count failures
    a_results = [q for q in query_results if q.query_type == "A"]
    ok_count = sum(1 for q in a_results if q.status == "OK")
    fail_details = [q for q in a_results if q.status in FAILURE_STATUSES]
    failures += len(fail_details)
    times = [q.response_time_ms for q in a_results if q.status == "OK"]

    log.info(f"  Queries(A): {ok_count}/{len(a_results)} OK  "
             f"avg={pct(times,50):.0f}ms  p95={pct(times,95):.0f}ms  p99={pct(times,99):.0f}ms")

    for q in fail_details:
        log.info(f"    !! {q.status} {q.server_name} -> {q.domain} ({q.response_time_ms:.0f}ms)")

    # AAAA summary
    aaaa_results = [q for q in query_results if q.query_type == "AAAA"]
    if aaaa_results:
        aaaa_ok = sum(1 for q in aaaa_results if q.status == "OK")
        log.info(f"  Queries(AAAA): {aaaa_ok}/{len(aaaa_results)} OK")

    # Reachability
    reach_up = sum(1 for r in reach_results if r.reachable)
    log.info(f"  Reachability: {reach_up}/{len(reach_results)} UP")
    for r in reach_results:
        if not r.reachable:
            log.info(f"    !! DOWN {r.server_name} ({r.server})")
            failures += 1

    # TTL summary for key domains
    ttl_info = []
    for d in ("youtube.com", "facebook.com", "instagram.com"):
        for q in query_results:
            if q.domain == d and q.server == "64.59.135.135" and q.query_type == "A" and q.ttl is not None:
                ttl_info.append(f"{d}={q.ttl}s")
                break
    if ttl_info:
        log.info(f"  TTL(Rogers): {' '.join(ttl_info)}")

    # HTTP
    if http_results:
        http_ok = sum(1 for h in http_results if h.http_code and h.http_code < 400)
        log.info(f"  HTTP: {http_ok}/{len(http_results)} OK  "
                 f"avg={sum(h.total_time_ms for h in http_results)/len(http_results):.0f}ms")
        for h in http_results:
            if not h.http_code:
                log.info(f"    !! FAIL {h.domain} ({h.total_time_ms:.0f}ms)")
                failures += 1

    # E2E
    if e2e_results:
        e2e_ok = sum(1 for e in e2e_results if e.reachable)
        log.info(f"  E2E: {e2e_ok}/{len(e2e_results)} reachable")
        for e in e2e_results:
            if not e.reachable:
                log.info(f"    !! UNREACHABLE {e.dns_server_name} -> {e.domain} "
                         f"IP {e.resolved_ip} ({e.connect_time_ms:.0f}ms)")
                failures += 1

    # Interception
    for i in intercept_results:
        if i.is_intercepted:
            log.info(f"    !! INTERCEPTED {i.server_name}: UDP={i.udp_result} TCP={i.tcp_result}")
            failures += 1

    # Hijacking
    for h in hijack_results:
        if h.is_hijacked:
            log.info(f"    !! HIJACKED {h.server_name} returns {h.returned_ip} for nonexistent domain")
            failures += 1

    # DoH
    if doh_results_list:
        doh_ok = sum(1 for d in doh_results_list if d.status == "OK")
        log.info(f"  DoH: {doh_ok}/{len(doh_results_list)} OK")

    # IP changes
    if ip_change_records:
        log.info(f"  IP changes: {len(ip_change_records)} detected")

    return failures


async def run_monitor() -> None:
    """Main entry point for the monitoring loop."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    init_database()

    # Detect and add router/gateway to server list
    router = detect_router_ip()
    if router and router not in DNS_SERVERS:
        DNS_SERVERS[router] = "Router"
        log.info(f"Auto-detected router: {router}")

    sys_ns = detect_system_nameservers()
    for ns in sys_ns:
        if ns not in DNS_SERVERS:
            DNS_SERVERS[ns] = "System NS"
            log.info(f"Auto-detected system nameserver: {ns}")

    run_id = start_run()
    servers_list = ", ".join(f"{v} ({k})" for k, v in DNS_SERVERS.items())
    n_queries = len(TEST_DOMAINS) * (len(DNS_SERVERS) + 1) + len(STREAMING_DOMAINS) * (len(DNS_SERVERS) + 1)

    log.info("=" * 60)
    log.info("DNS Monitor Started")
    log.info(f"Duration: {DURATION//3600}h {DURATION%3600//60}m | Interval: {INTERVAL}s")
    log.info(f"Run ID: {run_id}")
    log.info(f"Servers: {servers_list}")
    log.info(f"Domains: {len(TEST_DOMAINS)} (A) + {len(STREAMING_DOMAINS)} (AAAA) = ~{n_queries} queries/iter")
    log.info(f"Log: {LOG_FILE}")
    log.info(f"DB:  {DB_FILE}")
    log.info("=" * 60)

    ip_tracker = IPChangeTracker()
    start_time = time.monotonic()
    total_iterations = 0
    total_failures = 0
    shutdown = asyncio.Event()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, shutdown.set)

    try:
        while not shutdown.is_set():
            elapsed = time.monotonic() - start_time
            if elapsed >= DURATION:
                break

            total_iterations += 1
            iter_start = time.monotonic()
            hms = time.strftime("%H:%M:%S", time.gmtime(elapsed))
            log.info(f"--- #{total_iterations} ({hms} elapsed) ---")

            query_results: list[QueryResult] = []
            failures = await run_iteration(run_id, total_iterations,
                                           ip_tracker, query_results)
            total_failures += failures

            iter_ms = (time.monotonic() - iter_start) * 1000
            log.info(f"  Iteration took {iter_ms:.0f}ms")

            # Sleep remaining interval
            remaining = INTERVAL - (time.monotonic() - iter_start)
            if remaining > 0 and not shutdown.is_set():
                try:
                    await asyncio.wait_for(shutdown.wait(), timeout=remaining)
                except asyncio.TimeoutError:
                    pass
    finally:
        end_run(run_id, total_iterations, total_failures)
        log.info("=" * 60)
        log.info(f"Monitor complete. Run {run_id}: "
                 f"{total_iterations} iterations, {total_failures} failures")
        log.info(f"View results: python3 web_dashboard.py")
        log.info("=" * 60)


def main() -> None:
    try:
        asyncio.run(run_monitor())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
