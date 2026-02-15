#!/usr/bin/env python3
"""Tests for dns_monitor.py — run with: python3 -m pytest tests/ -v"""

from __future__ import annotations

import asyncio
import sqlite3
import tempfile
from pathlib import Path
from unittest.mock import patch

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

import dns_monitor as mon


def run(coro):
    """Helper to run async functions in tests."""
    return asyncio.get_event_loop().run_until_complete(coro)


class TestQueryDNS:
    def test_google_resolves(self):
        r = run(mon.query_dns("8.8.8.8", "google.com", "A"))
        assert r.status == "OK"
        assert len(r.addresses) > 0
        assert r.ttl is not None
        assert r.response_time_ms > 0

    def test_nxdomain(self):
        r = run(mon.query_dns("8.8.8.8", "this-does-not-exist.example.invalid", "A"))
        assert r.status == "NXDOMAIN"

    def test_aaaa(self):
        r = run(mon.query_dns("8.8.8.8", "google.com", "AAAA"))
        assert r.status == "OK"
        # Google should have AAAA records
        assert any(":" in a for a in r.addresses)

    def test_timeout_bad_server(self):
        r = run(mon.query_dns("192.0.2.1", "google.com", "A", timeout=1.0))
        assert r.status in ("TIMEOUT", "NETUNREACH", "FAIL")

    def test_server_name_lookup(self):
        r = run(mon.query_dns("8.8.8.8", "google.com", "A"))
        assert r.server_name == "Google Primary"
        assert r.server == "8.8.8.8"


class TestSystemDNS:
    def test_resolves(self):
        r = run(mon.query_system_dns("google.com", "A"))
        assert r.status == "OK"
        assert r.server == "system"

    def test_nxdomain(self):
        r = run(mon.query_system_dns("this-does-not-exist.example.invalid", "A"))
        assert r.status in ("NXDOMAIN", "NODATA")


class TestReachability:
    def test_google_reachable(self):
        r = run(mon.test_reachability("8.8.8.8"))
        assert r.reachable is True
        assert r.response_time_ms > 0

    def test_unreachable(self):
        r = run(mon.test_reachability("192.0.2.1"))
        assert r.reachable is False


class TestHijacking:
    def test_google_not_hijacked(self):
        r = run(mon.test_hijacking("8.8.8.8"))
        assert r.is_hijacked is False
        assert r.returned_ip == ""


class TestIPChangeTracker:
    def test_initial_no_change(self):
        t = mon.IPChangeTracker()
        changed, old, new, secs = t.check("example.com", "8.8.8.8", ["1.2.3.4"])
        assert changed is False
        assert old == set()

    def test_detects_change(self):
        t = mon.IPChangeTracker()
        t.check("example.com", "8.8.8.8", ["1.2.3.4"])
        changed, old, new, _ = t.check("example.com", "8.8.8.8", ["5.6.7.8"])
        assert changed is True
        assert old == {"1.2.3.4"}
        assert new == {"5.6.7.8"}

    def test_no_false_positive_on_order(self):
        t = mon.IPChangeTracker()
        t.check("example.com", "8.8.8.8", ["1.1.1.1", "2.2.2.2"])
        changed, _, _, _ = t.check("example.com", "8.8.8.8", ["2.2.2.2", "1.1.1.1"])
        assert changed is False

    def test_different_servers_independent(self):
        t = mon.IPChangeTracker()
        t.check("example.com", "8.8.8.8", ["1.1.1.1"])
        t.check("example.com", "1.1.1.1", ["2.2.2.2"])
        changed, _, _, _ = t.check("example.com", "8.8.8.8", ["1.1.1.1"])
        assert changed is False  # Same as before for this server


class TestConsistency:
    def test_consistent(self):
        results = [
            mon.QueryResult("8.8.8.8", "Google", "example.com", "A", "OK", 10, ["1.2.3.4"], 300, ""),
            mon.QueryResult("1.1.1.1", "Cloudflare", "example.com", "A", "OK", 10, ["1.2.3.4"], 300, ""),
        ]
        consistent, _ = mon.check_consistency("example.com", results)
        assert consistent is True

    def test_inconsistent(self):
        results = [
            mon.QueryResult("8.8.8.8", "Google", "example.com", "A", "OK", 10, ["1.2.3.4"], 300, ""),
            mon.QueryResult("1.1.1.1", "Cloudflare", "example.com", "A", "OK", 10, ["5.6.7.8"], 300, ""),
        ]
        consistent, detail = mon.check_consistency("example.com", results)
        assert consistent is False
        assert "8.8.8.8" in detail


class TestDatabase:
    def setup_method(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.db_path = Path(self.tmp.name)

    def teardown_method(self):
        self.db_path.unlink(missing_ok=True)

    def test_init_creates_tables(self):
        with patch.object(mon, "DB_FILE", self.db_path):
            mon.init_database()
        conn = sqlite3.connect(self.db_path)
        tables = [r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        ).fetchall()]
        conn.close()
        assert "dns_queries" in tables
        assert "doh_tests" in tables
        assert "e2e_tests" in tables
        assert "test_runs" in tables

    def test_start_and_end_run(self):
        with patch.object(mon, "DB_FILE", self.db_path):
            mon.init_database()
            run_id = mon.start_run()
            assert run_id >= 1
            mon.end_run(run_id, 10, 2)

        conn = sqlite3.connect(self.db_path)
        row = conn.execute("SELECT total_tests, total_failures FROM test_runs WHERE run_id=?",
                           (run_id,)).fetchone()
        conn.close()
        assert row == (10, 2)

    def test_batch_insert(self):
        with patch.object(mon, "DB_FILE", self.db_path):
            mon.init_database()
            run_id = mon.start_run()
            mon.batch_insert(
                run_id,
                queries=[
                    mon.QueryResult("8.8.8.8", "Google", "example.com", "A",
                                    "OK", 25.0, ["1.2.3.4"], 300, ""),
                ],
                reachability=[
                    mon.ReachabilityResult("8.8.8.8", "Google", True, 15.0),
                ],
                http_results=[],
                interceptions=[],
                hijacks=[],
                consistency=[("example.com", True, "")],
                ip_changes=[],
                doh_results=[],
                e2e_results=[],
            )

        conn = sqlite3.connect(self.db_path)
        count = conn.execute("SELECT COUNT(*) FROM dns_queries WHERE run_id=?",
                             (run_id,)).fetchone()[0]
        ttl = conn.execute("SELECT ttl FROM dns_queries WHERE run_id=?",
                           (run_id,)).fetchone()[0]
        conn.close()
        assert count == 1
        assert ttl == 300


class TestPercentile:
    def test_basic(self):
        data = list(range(100))
        assert mon.pct(data, 50) == 49.5
        assert mon.pct(data, 0) == 0
        assert mon.pct(data, 100) == 99

    def test_empty(self):
        assert mon.pct([], 50) == 0.0

    def test_single(self):
        assert mon.pct([42], 50) == 42
        assert mon.pct([42], 99) == 42


class TestDetection:
    def test_detect_router(self):
        # Just verify it runs without error and returns str or None
        result = mon.detect_router_ip()
        assert result is None or isinstance(result, str)

    def test_detect_nameservers(self):
        result = mon.detect_system_nameservers()
        assert isinstance(result, list)


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
