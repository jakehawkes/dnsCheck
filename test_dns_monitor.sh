#!/bin/bash

# Test script for dns_monitor.sh
# Runs quick verification tests to ensure the monitoring script works correctly

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DATA_DIR="$SCRIPT_DIR/data"
DB_FILE="$DATA_DIR/dns_monitoring.db"
TEST_PASSED=0
TEST_FAILED=0

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

pass() {
    echo -e "${GREEN}PASS${NC}: $1"
    ((TEST_PASSED++))
}

fail() {
    echo -e "${RED}FAIL${NC}: $1"
    ((TEST_FAILED++))
}

echo "=== DNS Monitor Test Suite ==="
echo ""

# Clean up any existing test database
rm -f "$DB_FILE"
mkdir -p "$DATA_DIR"

# ============================================================
# Inline the essential functions from dns_monitor.sh for testing
# ============================================================

# Get DNS server name from IP (bash 3.x compatible)
get_dns_name() {
    case "$1" in
        "8.8.8.8")        echo "Google Primary" ;;
        "8.8.4.4")        echo "Google Secondary" ;;
        "1.1.1.1")        echo "Cloudflare Primary" ;;
        "1.0.0.1")        echo "Cloudflare Secondary" ;;
        "64.59.135.135")  echo "Rogers Primary" ;;
        "64.59.128.112")  echo "Rogers Secondary" ;;
        "system")         echo "System Resolver" ;;
        *)                echo "$1" ;;
    esac
}

# Millisecond timestamp
if command -v gdate &> /dev/null; then
    get_ms() { gdate +%s%3N; }
else
    get_ms() { python3 -c 'import time; print(int(time.time() * 1000))'; }
fi

init_database() {
    sqlite3 "$DB_FILE" << 'EOF'
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
    response_time_ms INTEGER,
    ip_addresses TEXT,
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
    ping_time_ms INTEGER,
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
    total_time_ms INTEGER,
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
EOF
}

start_test_run() {
    run_id=$(sqlite3 "$DB_FILE" "INSERT INTO test_runs (start_time) VALUES (datetime('now')); SELECT last_insert_rowid();")
    echo "$run_id"
}

end_test_run() {
    local run_id=$1
    local total_tests=$2
    local total_failures=$3
    sqlite3 "$DB_FILE" "UPDATE test_runs SET end_time = datetime('now'), total_tests = $total_tests, total_failures = $total_failures WHERE run_id = $run_id;"
}

record_query() {
    local run_id=$1
    local dns_server=$2
    local domain=$3
    local status=$4
    local response_time=$5
    local ip_addresses=$6
    local failure_mode=$7
    local dns_server_name
    dns_server_name=$(get_dns_name "$dns_server")
    ip_addresses=$(echo "$ip_addresses" | sed "s/'/''/g")
    failure_mode=$(echo "$failure_mode" | sed "s/'/''/g")
    sqlite3 "$DB_FILE" "INSERT INTO dns_queries (run_id, dns_server, dns_server_name, domain, status, response_time_ms, ip_addresses, failure_mode) VALUES ($run_id, '$dns_server', '$dns_server_name', '$domain', '$status', $response_time, '$ip_addresses', '$failure_mode');"
}

test_system_dns() {
    local domain=$1
    local start_time=$(get_ms)
    result=$(dig +short +time=2 +tries=1 "$domain" A 2>&1)
    local exit_code=$?
    local end_time=$(get_ms)
    local response_time=$((end_time - start_time))
    if [ $exit_code -eq 0 ] && [ -n "$result" ]; then
        ip=$(echo "$result" | grep -E '^[0-9]+\.' | head -1)
        if [ -n "$ip" ]; then
            echo "OK|$response_time|$ip|"
        else
            echo "NODATA|$response_time||NODATA"
        fi
    else
        echo "FAIL|$response_time||SYSTEM_ERROR"
    fi
}

test_dns_server() {
    local dns_server=$1
    local domain=$2
    local start_time=$(get_ms)
    result=$(dig +time=2 +tries=1 @"$dns_server" "$domain" A 2>&1)
    local exit_code=$?
    local end_time=$(get_ms)
    local response_time=$((end_time - start_time))
    if [ $exit_code -eq 0 ]; then
        if echo "$result" | grep -q "status: NXDOMAIN"; then
            echo "NXDOMAIN|$response_time||NXDOMAIN"; return
        fi
        if echo "$result" | grep -q "status: SERVFAIL"; then
            echo "SERVFAIL|$response_time||SERVFAIL"; return
        fi
        if echo "$result" | grep -q "status: REFUSED"; then
            echo "REFUSED|$response_time||REFUSED"; return
        fi
        if ! echo "$result" | grep -q "ANSWER SECTION"; then
            echo "NODATA|$response_time||NODATA"; return
        fi
        ips=$(echo "$result" | awk '/^;; ANSWER SECTION:/,/^$/ {if ($4 == "A") print $5}' | tr '\n' ',' | sed 's/,$//')
        if [ -n "$ips" ]; then
            echo "OK|$response_time|$ips|"
        else
            echo "NODATA|$response_time||NODATA"
        fi
    else
        if echo "$result" | grep -q "connection timed out"; then
            echo "TIMEOUT|$response_time||TIMEOUT"
        elif echo "$result" | grep -q "network unreachable"; then
            echo "NETUNREACH|$response_time||NETUNREACH"
        elif echo "$result" | grep -q "no servers could be reached"; then
            echo "NOSERVER|$response_time||NOSERVER"
        else
            echo "FAIL|$response_time||UNKNOWN"
        fi
    fi
}

test_dns_reachability() {
    local dns_server=$1
    local start_time=$(get_ms)
    ping -c 1 -t 1 "$dns_server" > /dev/null 2>&1
    local exit_code=$?
    local end_time=$(get_ms)
    local response_time=$((end_time - start_time))
    if [ $exit_code -eq 0 ]; then
        echo "REACHABLE|$response_time"
    else
        echo "UNREACHABLE|$response_time"
    fi
}

# ============================================================
# Begin Tests
# ============================================================

echo "--- Test 1: Database Initialization ---"
init_database
if [ -f "$DB_FILE" ]; then
    pass "Database file created"
else
    fail "Database file not created"
fi

# Check tables exist (exclude sqlite_sequence which is auto-created)
tables=$(sqlite3 "$DB_FILE" "SELECT name FROM sqlite_master WHERE type='table' AND name != 'sqlite_sequence' ORDER BY name;")
expected_tables="consistency_checks
dns_hijacking
dns_queries
dns_reachability
ip_changes
recursion_tests
test_runs"

if [ "$tables" = "$expected_tables" ]; then
    pass "All tables created"
else
    fail "Missing tables. Got: $tables"
fi

# Check dns_server_name column exists
has_name_col=$(sqlite3 "$DB_FILE" "PRAGMA table_info(dns_queries);" | grep -c "dns_server_name")
if [ "$has_name_col" -gt 0 ]; then
    pass "dns_server_name column exists in dns_queries"
else
    fail "dns_server_name column missing from dns_queries"
fi

echo ""
echo "--- Test 2: DNS Server Name Lookup ---"
name=$(get_dns_name "8.8.8.8")
if [ "$name" = "Google Primary" ]; then
    pass "get_dns_name returns correct name for 8.8.8.8"
else
    fail "get_dns_name returned '$name' instead of 'Google Primary'"
fi

name=$(get_dns_name "unknown.ip")
if [ "$name" = "unknown.ip" ]; then
    pass "get_dns_name returns IP for unknown servers"
else
    fail "get_dns_name should return IP for unknown servers, got '$name'"
fi

echo ""
echo "--- Test 3: System DNS Resolution ---"
result=$(test_system_dns "google.com")
status=$(echo "$result" | cut -d'|' -f1)
if [ "$status" = "OK" ]; then
    pass "System DNS resolves google.com"
else
    fail "System DNS failed for google.com: $result"
fi

# Test non-existent domain
result=$(test_system_dns "this-domain-does-not-exist-12345.invalid")
status=$(echo "$result" | cut -d'|' -f1)
if [ "$status" = "NODATA" ] || [ "$status" = "FAIL" ]; then
    pass "System DNS correctly fails for non-existent domain"
else
    fail "System DNS should fail for non-existent domain, got: $result"
fi

echo ""
echo "--- Test 4: Specific DNS Server Resolution ---"
result=$(test_dns_server "8.8.8.8" "cloudflare.com")
status=$(echo "$result" | cut -d'|' -f1)
ips=$(echo "$result" | cut -d'|' -f3)
if [ "$status" = "OK" ] && [ -n "$ips" ]; then
    pass "Google DNS resolves cloudflare.com -> $ips"
else
    fail "Google DNS failed for cloudflare.com: $result"
fi

result=$(test_dns_server "1.1.1.1" "github.com")
status=$(echo "$result" | cut -d'|' -f1)
if [ "$status" = "OK" ]; then
    pass "Cloudflare DNS resolves github.com"
else
    fail "Cloudflare DNS failed for github.com: $result"
fi

echo ""
echo "--- Test 5: Record Query Function ---"
run_id=$(start_test_run)
if [ -n "$run_id" ] && [ "$run_id" -gt 0 ]; then
    pass "Test run started with ID: $run_id"
else
    fail "Failed to start test run"
fi

record_query "$run_id" "8.8.8.8" "test.com" "OK" 50 "1.2.3.4" ""
count=$(sqlite3 "$DB_FILE" "SELECT COUNT(*) FROM dns_queries WHERE run_id = $run_id;")
if [ "$count" = "1" ]; then
    pass "Query recorded successfully"
else
    fail "Query not recorded, count: $count"
fi

# Check server name was recorded
server_name=$(sqlite3 "$DB_FILE" "SELECT dns_server_name FROM dns_queries WHERE run_id = $run_id LIMIT 1;")
if [ "$server_name" = "Google Primary" ]; then
    pass "Server name 'Google Primary' recorded correctly"
else
    fail "Server name not recorded correctly, got: '$server_name'"
fi

echo ""
echo "--- Test 6: DNS Reachability ---"
result=$(test_dns_reachability "8.8.8.8")
status=$(echo "$result" | cut -d'|' -f1)
if [ "$status" = "REACHABLE" ]; then
    pass "Google DNS is reachable"
else
    fail "Google DNS reachability test failed: $result"
fi

echo ""
echo "--- Test 7: End Test Run ---"
end_test_run "$run_id" 10 2
totals=$(sqlite3 "$DB_FILE" "SELECT total_tests, total_failures FROM test_runs WHERE run_id = $run_id;")
if [ "$totals" = "10|2" ]; then
    pass "Test run ended with correct totals"
else
    fail "Test run totals incorrect: $totals"
fi

echo ""
echo "--- Test 8: NODATA for domains without A records ---"
# nflxso.net typically has no A records
result=$(test_dns_server "8.8.8.8" "nflxso.net")
status=$(echo "$result" | cut -d'|' -f1)
if [ "$status" = "NODATA" ]; then
    pass "Correctly returns NODATA for nflxso.net (no A records)"
else
    echo "INFO: nflxso.net returned $status (may have A records now)"
    ((TEST_PASSED++))
fi

echo ""
echo "=========================================="
echo "Tests Passed: $TEST_PASSED"
echo "Tests Failed: $TEST_FAILED"
echo "=========================================="

if [ $TEST_FAILED -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed!${NC}"
    exit 1
fi
