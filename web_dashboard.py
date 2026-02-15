#!/usr/bin/env python3
"""DNS Monitoring Dashboard - Zero-dependency web app (stdlib only).

Reads from the SQLite database written by dns_monitor.py and serves
an auto-refreshing dashboard with charts and tables.

Usage:
    python3 web_dashboard.py              # http://0.0.0.0:5000
    python3 web_dashboard.py --port 8080  # custom port
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from functools import partial
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse

SCRIPT_DIR = Path(__file__).parent
DB_FILE = SCRIPT_DIR / "data" / "dns_monitoring.db"
TEMPLATE_FILE = SCRIPT_DIR / "templates" / "dashboard.html"


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def q(sql: str, params: tuple = ()) -> list[dict]:
    conn = get_db()
    try:
        return [dict(r) for r in conn.execute(sql, params).fetchall()]
    finally:
        conn.close()


def q1(sql: str, params: tuple = ()) -> dict | None:
    rows = q(sql, params)
    return rows[0] if rows else None


# ---------------------------------------------------------------------------
# API handlers — each returns a JSON-serializable object
# ---------------------------------------------------------------------------

def api_runs() -> list[dict]:
    return q("SELECT run_id, datetime(start_time,'localtime') as start, "
             "datetime(end_time,'localtime') as end, total_tests, total_failures "
             "FROM test_runs ORDER BY run_id DESC LIMIT 50")


def api_summary(run_id: int) -> dict:
    total = q1("SELECT COUNT(*) as n FROM dns_queries WHERE run_id=? AND query_type='A'", (run_id,))
    ok = q1("SELECT COUNT(*) as n FROM dns_queries WHERE run_id=? AND query_type='A' AND status='OK'", (run_id,))
    return {"total_queries": total["n"] if total else 0, "ok_queries": ok["n"] if ok else 0}


def api_server_reliability(run_id: int) -> list[dict]:
    return q("""
        SELECT dns_server_name as server, dns_server as ip,
               COUNT(*) as total,
               SUM(CASE WHEN status='OK' THEN 1 ELSE 0 END) as ok,
               SUM(CASE WHEN status!='OK' THEN 1 ELSE 0 END) as failed,
               ROUND(AVG(CASE WHEN status='OK' THEN response_time_ms END), 1) as avg_ms,
               ROUND(SUM(CASE WHEN status!='OK' THEN 1 ELSE 0 END)*100.0/COUNT(*), 2) as fail_pct
        FROM dns_queries
        WHERE run_id=? AND query_type='A'
        GROUP BY dns_server ORDER BY fail_pct DESC
    """, (run_id,))


def api_failures(run_id: int) -> list[dict]:
    return q("""
        SELECT datetime(timestamp,'localtime') as time,
               dns_server_name as server, domain, status, failure_mode,
               ROUND(response_time_ms, 0) as ms
        FROM dns_queries
        WHERE run_id=? AND status IN ('FAIL','TIMEOUT','SERVFAIL','REFUSED','NETUNREACH','NOSERVER')
        ORDER BY timestamp DESC LIMIT 200
    """, (run_id,))


def api_failure_timeline(run_id: int) -> list[dict]:
    return q("""
        SELECT strftime('%Y-%m-%d %H:%M', timestamp, 'localtime',
               '-' || (strftime('%M', timestamp) % 5) || ' minutes') as bucket,
               COUNT(*) as failures
        FROM dns_queries
        WHERE run_id=? AND status IN ('FAIL','TIMEOUT','SERVFAIL','REFUSED','NETUNREACH','NOSERVER')
        GROUP BY bucket ORDER BY bucket
    """, (run_id,))


def api_ttl(run_id: int) -> list[dict]:
    return q("""
        SELECT domain, dns_server_name as server,
               MIN(ttl) as min_ttl, MAX(ttl) as max_ttl,
               ROUND(AVG(ttl), 0) as avg_ttl, COUNT(*) as samples
        FROM dns_queries
        WHERE run_id=? AND query_type='A' AND status='OK' AND ttl IS NOT NULL
        GROUP BY domain, dns_server ORDER BY avg_ttl ASC LIMIT 100
    """, (run_id,))


def api_ip_changes(run_id: int) -> list[dict]:
    return q("""
        SELECT domain, dns_server_name as server,
               COUNT(*) as changes,
               ROUND(AVG(time_since_last_change_seconds)/60.0, 1) as avg_interval_min,
               MIN(time_since_last_change_seconds) as min_interval_sec
        FROM ip_changes
        WHERE change_time >= (SELECT start_time FROM test_runs WHERE run_id=?)
        GROUP BY domain, dns_server ORDER BY changes DESC
    """, (run_id,))


def api_ip_change_log(run_id: int) -> list[dict]:
    return q("""
        SELECT domain, dns_server_name as server,
               old_ips, new_ips,
               datetime(change_time, 'localtime') as time,
               time_since_last_change_seconds as interval_sec
        FROM ip_changes
        WHERE change_time >= (SELECT start_time FROM test_runs WHERE run_id=?)
        ORDER BY change_time DESC LIMIT 100
    """, (run_id,))


def api_http(run_id: int) -> list[dict]:
    return q("""
        SELECT domain, COUNT(*) as tests,
               ROUND(AVG(total_time_ms), 0) as avg_ms,
               MAX(total_time_ms) as max_ms,
               SUM(CASE WHEN http_code=0 THEN 1 ELSE 0 END) as failures
        FROM http_tests WHERE run_id=? GROUP BY domain
    """, (run_id,))


def api_e2e(run_id: int) -> list[dict]:
    return q("""
        SELECT dns_server_name as server, domain, resolved_ip,
               SUM(reachable) as times_ok,
               COUNT(*)-SUM(reachable) as times_fail,
               ROUND(AVG(connect_time_ms), 0) as avg_connect_ms
        FROM e2e_tests WHERE run_id=?
        GROUP BY dns_server, domain ORDER BY times_fail DESC
    """, (run_id,))


def api_doh(run_id: int) -> list[dict]:
    return q("""
        SELECT provider_name as provider, domain, status,
               ip_addresses as ips,
               ROUND(AVG(response_time_ms), 0) as avg_ms,
               ROUND(AVG(ttl)) as avg_ttl
        FROM doh_tests WHERE run_id=?
        GROUP BY provider, domain
    """, (run_id,))


def api_interception(run_id: int) -> list[dict]:
    return q("""
        SELECT dns_server_name as server, dns_server as ip,
               SUM(is_intercepted) as detections, COUNT(*) as tests
        FROM interception_tests WHERE run_id=? GROUP BY dns_server
    """, (run_id,))


def api_hijacking(run_id: int) -> list[dict]:
    return q("""
        SELECT dns_server_name as server, dns_server as ip,
               SUM(is_hijacked) as detections, COUNT(*) as tests
        FROM dns_hijacking WHERE run_id=? GROUP BY dns_server
    """, (run_id,))


def api_consistency(run_id: int) -> list[dict]:
    return q("""
        SELECT domain,
               SUM(is_consistent) as consistent_checks,
               COUNT(*)-SUM(is_consistent) as inconsistent_checks
        FROM consistency_checks WHERE run_id=?
        GROUP BY domain HAVING inconsistent_checks > 0
        ORDER BY inconsistent_checks DESC
    """, (run_id,))


def api_latency_distribution(run_id: int) -> list[dict]:
    return q("""
        SELECT
            CASE
                WHEN response_time_ms < 10 THEN '<10ms'
                WHEN response_time_ms < 25 THEN '10-25ms'
                WHEN response_time_ms < 50 THEN '25-50ms'
                WHEN response_time_ms < 100 THEN '50-100ms'
                WHEN response_time_ms < 250 THEN '100-250ms'
                WHEN response_time_ms < 500 THEN '250-500ms'
                WHEN response_time_ms < 1000 THEN '500ms-1s'
                ELSE '>1s'
            END as bucket, COUNT(*) as count
        FROM dns_queries
        WHERE run_id=? AND query_type='A' AND status='OK'
        GROUP BY bucket ORDER BY MIN(response_time_ms)
    """, (run_id,))


def api_reachability(run_id: int) -> list[dict]:
    return q("""
        SELECT dns_server_name as server, dns_server as ip,
               SUM(reachable) as up, COUNT(*)-SUM(reachable) as down,
               ROUND(AVG(ping_time_ms), 1) as avg_ms
        FROM dns_reachability WHERE run_id=? GROUP BY dns_server
    """, (run_id,))


# Map URL prefix -> handler (handler receives run_id)
API_ROUTES: dict[str, callable] = {
    "/api/runs":                  lambda _: api_runs(),
    "/api/summary":               api_summary,
    "/api/server_reliability":    api_server_reliability,
    "/api/failures":              api_failures,
    "/api/failure_timeline":      api_failure_timeline,
    "/api/ttl":                   api_ttl,
    "/api/ip_changes":            api_ip_changes,
    "/api/ip_change_log":         api_ip_change_log,
    "/api/http":                  api_http,
    "/api/e2e":                   api_e2e,
    "/api/doh":                   api_doh,
    "/api/interception":          api_interception,
    "/api/hijacking":             api_hijacking,
    "/api/consistency":           api_consistency,
    "/api/latency_distribution":  api_latency_distribution,
    "/api/reachability":          api_reachability,
}


def render_index() -> str:
    """Load the template and inject run data (simple server-side rendering)."""
    runs = api_runs()
    # Build the <option> elements
    options = []
    for i, r in enumerate(runs):
        selected = "selected" if i == 0 else ""
        status = f"({r['total_tests']} iters, {r['total_failures']} fails)" if r['total_tests'] else "(running)"
        options.append(
            f'<option value="{r["run_id"]}" {selected}>'
            f'Run #{r["run_id"]} &mdash; {r["start"]} {status}</option>'
        )
    options_html = "\n".join(options)

    template = TEMPLATE_FILE.read_text()
    # Replace the Jinja2 block with rendered HTML
    # The template has a {% for %} block for runs — replace the entire select contents
    import re
    template = re.sub(
        r'{% for r in runs %}.*?{% endfor %}',
        options_html,
        template,
        flags=re.DOTALL
    )
    return template


class DashboardHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # Quiet logging

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"

        # Serve the main page
        if path == "/" or path == "/index.html":
            html = render_index()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(html.encode())
            return

        # API routes: /api/<name>/<run_id>
        for prefix, handler in API_ROUTES.items():
            if path == prefix or path.startswith(prefix + "/"):
                run_id = 0
                remainder = path[len(prefix):]
                if remainder.startswith("/"):
                    try:
                        run_id = int(remainder[1:])
                    except ValueError:
                        pass
                try:
                    data = handler(run_id)
                    body = json.dumps(data).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Cache-Control", "no-cache")
                    self.end_headers()
                    self.wfile.write(body)
                except Exception as e:
                    self.send_response(500)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": str(e)}).encode())
                return

        self.send_response(404)
        self.end_headers()


def main():
    parser = argparse.ArgumentParser(description="DNS Monitoring Dashboard")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--host", default="0.0.0.0")
    args = parser.parse_args()

    if not DB_FILE.exists():
        print(f"Database not found: {DB_FILE}")
        print("Run dns_monitor.py first to create data.")
        sys.exit(1)

    server = HTTPServer((args.host, args.port), DashboardHandler)
    print(f"Dashboard: http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutdown.")
        server.server_close()


if __name__ == "__main__":
    main()
