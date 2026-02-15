#!/usr/bin/env python3
"""Standalone test runner for dns_monitor.py (no pytest needed)."""

from __future__ import annotations

import asyncio
import sqlite3
import sys
import tempfile
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
import dns_monitor as mon

PASSED = 0
FAILED = 0


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def test(name, func):
    global PASSED, FAILED
    try:
        func()
        print(f"  PASS: {name}")
        PASSED += 1
    except Exception as e:
        print(f"  FAIL: {name}")
        traceback.print_exc()
        FAILED += 1


# --- Query DNS ---

print("--- Query DNS ---")


def test_google_a():
    r = run(mon.query_dns("8.8.8.8", "google.com", "A"))
    assert r.status == "OK", f"got {r.status}"
    assert len(r.addresses) > 0
    assert r.ttl is not None
    assert r.response_time_ms > 0
    assert r.server_name == "Google Primary"
test("Google A record", test_google_a)


def test_nxdomain():
    r = run(mon.query_dns("8.8.8.8", "nope.example.invalid", "A"))
    assert r.status == "NXDOMAIN", f"got {r.status}"
test("NXDOMAIN", test_nxdomain)


def test_aaaa():
    r = run(mon.query_dns("8.8.8.8", "google.com", "AAAA"))
    assert r.status == "OK", f"got {r.status}"
    assert any(":" in a for a in r.addresses), f"no IPv6 in {r.addresses}"
test("AAAA record", test_aaaa)


# --- System DNS ---

print("\n--- System DNS ---")


def test_system():
    r = run(mon.query_system_dns("google.com"))
    assert r.status == "OK", f"got {r.status}"
    assert r.server == "system"
test("System resolves google.com", test_system)


# --- Reachability ---

print("\n--- Reachability ---")


def test_reachable():
    r = run(mon.test_reachability("8.8.8.8"))
    assert r.reachable is True
    assert r.response_time_ms > 0
test("Google DNS reachable", test_reachable)


# --- Hijacking ---

print("\n--- Hijacking ---")


def test_hijack():
    r = run(mon.test_hijacking("8.8.8.8"))
    assert r.is_hijacked is False
    assert r.returned_ip == ""
test("Google not hijacked", test_hijack)


# --- IP Change Tracker ---

print("\n--- IP Change Tracker ---")


def test_tracker_basic():
    t = mon.IPChangeTracker()
    c, old, new, secs = t.check("ex.com", "8.8.8.8", ["1.2.3.4"])
    assert c is False, "should not detect change on first check"
    assert old == set()
test("First check no change", test_tracker_basic)


def test_tracker_detects():
    t = mon.IPChangeTracker()
    t.check("ex.com", "8.8.8.8", ["1.2.3.4"])
    c, old, new, _ = t.check("ex.com", "8.8.8.8", ["5.6.7.8"])
    assert c is True
    assert old == {"1.2.3.4"}
    assert new == {"5.6.7.8"}
test("Detects IP change", test_tracker_detects)


def test_tracker_order():
    t = mon.IPChangeTracker()
    t.check("ex.com", "8.8.8.8", ["1.1.1.1", "2.2.2.2"])
    c, _, _, _ = t.check("ex.com", "8.8.8.8", ["2.2.2.2", "1.1.1.1"])
    assert c is False, "order difference should not be a change"
test("Order-insensitive", test_tracker_order)


def test_tracker_independent_servers():
    t = mon.IPChangeTracker()
    t.check("ex.com", "8.8.8.8", ["1.1.1.1"])
    t.check("ex.com", "1.1.1.1", ["2.2.2.2"])
    c, _, _, _ = t.check("ex.com", "8.8.8.8", ["1.1.1.1"])
    assert c is False, "different servers should be tracked independently"
test("Servers tracked independently", test_tracker_independent_servers)


# --- Consistency ---

print("\n--- Consistency ---")


def test_consistent():
    results = [
        mon.QueryResult("8.8.8.8", "G", "ex.com", "A", "OK", 10, ["1.2.3.4"], 300, ""),
        mon.QueryResult("1.1.1.1", "C", "ex.com", "A", "OK", 10, ["1.2.3.4"], 300, ""),
    ]
    c, _ = mon.check_consistency("ex.com", results)
    assert c is True
test("Consistent responses", test_consistent)


def test_inconsistent():
    results = [
        mon.QueryResult("8.8.8.8", "G", "ex.com", "A", "OK", 10, ["1.2.3.4"], 300, ""),
        mon.QueryResult("1.1.1.1", "C", "ex.com", "A", "OK", 10, ["5.6.7.8"], 300, ""),
    ]
    c, detail = mon.check_consistency("ex.com", results)
    assert c is False
    assert "8.8.8.8" in detail
test("Inconsistent responses", test_inconsistent)


# --- Database ---

print("\n--- Database ---")


def test_db():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        dbpath = Path(f.name)
    original = mon.DB_FILE
    mon.DB_FILE = dbpath
    try:
        mon.init_database()

        # Check tables
        conn = sqlite3.connect(dbpath)
        tables = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        ).fetchall()}
        assert "dns_queries" in tables
        assert "doh_tests" in tables
        assert "e2e_tests" in tables
        conn.close()

        # Start/end run
        rid = mon.start_run()
        assert rid >= 1

        # Batch insert
        mon.batch_insert(
            rid,
            queries=[mon.QueryResult("8.8.8.8", "G", "ex.com", "A", "OK", 25, ["1.2.3.4"], 300, "")],
            reachability=[mon.ReachabilityResult("8.8.8.8", "G", True, 15)],
            http_results=[],
            interceptions=[],
            hijacks=[],
            consistency=[("ex.com", True, "")],
            ip_changes=[],
            doh_results=[],
            e2e_results=[],
        )

        mon.end_run(rid, 10, 2)

        conn = sqlite3.connect(dbpath)
        assert conn.execute("SELECT COUNT(*) FROM dns_queries WHERE run_id=?", (rid,)).fetchone()[0] == 1
        assert conn.execute("SELECT ttl FROM dns_queries WHERE run_id=?", (rid,)).fetchone()[0] == 300
        assert conn.execute("SELECT total_tests FROM test_runs WHERE run_id=?", (rid,)).fetchone()[0] == 10
        conn.close()
    finally:
        mon.DB_FILE = original
        dbpath.unlink(missing_ok=True)
test("DB init, insert, run lifecycle", test_db)


# --- Percentile ---

print("\n--- Percentile ---")


def test_pct():
    assert mon.pct(list(range(100)), 50) == 49.5
    assert mon.pct([], 50) == 0.0
    assert mon.pct([42], 50) == 42
    assert mon.pct([42], 99) == 42
test("Percentile calculation", test_pct)


# --- Detection ---

print("\n--- System Detection ---")


def test_detect():
    r = mon.detect_router_ip()
    assert r is None or isinstance(r, str)
    ns = mon.detect_system_nameservers()
    assert isinstance(ns, list)
test("Router and nameserver detection", test_detect)


# --- Summary ---

print()
print(f"{'='*40}")
print(f" {PASSED} passed, {FAILED} failed")
print(f"{'='*40}")
sys.exit(1 if FAILED else 0)
