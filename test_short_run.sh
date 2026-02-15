#!/bin/bash

# Run the monitor for a short test period
# Defaults to 3 minutes with 15-second intervals for quick diagnostics
# Usage: ./test_short_run.sh [duration_seconds]

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DB_FILE="$SCRIPT_DIR/data/dns_monitoring.db"

export DURATION=${1:-180}   # 3 minutes default, or pass seconds as first arg
export INTERVAL=15          # Faster interval for short runs

echo "Starting DNS monitor for $((DURATION / 60))m $((DURATION % 60))s test run (interval: ${INTERVAL}s)..."
echo "Expected iterations: ~$((DURATION / (INTERVAL + 3)))"
echo "Press Ctrl+C to stop early"
echo ""

# Run the Python monitor - it reads DURATION and INTERVAL from environment
timeout "$((DURATION + 30))" python3 "$SCRIPT_DIR/dns_monitor.py"

echo ""
echo "Test completed. Checking results..."
echo ""

# Get the latest run_id
RUN_ID=$(sqlite3 "$DB_FILE" "SELECT MAX(run_id) FROM test_runs;" 2>/dev/null)

if [ -z "$RUN_ID" ]; then
    echo "No test data found."
    exit 1
fi

echo "Results for run ID: $RUN_ID"
echo ""

sqlite3 "$DB_FILE" << EOF
.mode column
.headers on

SELECT '=== Query Status Summary ===' as report;
SELECT status, COUNT(*) as count,
       ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM dns_queries WHERE run_id = $RUN_ID), 2) as percentage
FROM dns_queries
WHERE run_id = $RUN_ID
GROUP BY status
ORDER BY count DESC;

SELECT '';
SELECT '=== Failure Breakdown ===' as report;
SELECT failure_mode, COUNT(*) as count
FROM dns_queries
WHERE run_id = $RUN_ID
  AND status IN ('FAIL', 'TIMEOUT', 'SERVFAIL', 'REFUSED', 'NETUNREACH', 'NOSERVER')
GROUP BY failure_mode
ORDER BY count DESC;

SELECT '';
SELECT '=== DNS Server Comparison ===' as report;
SELECT dns_server_name as server, dns_server as ip,
       COUNT(*) as queries,
       ROUND(AVG(CASE WHEN status = 'OK' THEN response_time_ms END), 0) as avg_ok_ms,
       ROUND(SUM(CASE WHEN status != 'OK' THEN 1 ELSE 0 END) * 100.0 / COUNT(*), 1) as fail_pct
FROM dns_queries
WHERE run_id = $RUN_ID
GROUP BY dns_server
ORDER BY fail_pct DESC;

SELECT '';
SELECT '=== HTTP Connectivity ===' as report;
SELECT domain,
       COUNT(*) as tests,
       ROUND(AVG(total_time_ms), 0) as avg_total_ms,
       SUM(CASE WHEN http_code = 0 THEN 1 ELSE 0 END) as failures
FROM http_tests
WHERE run_id = $RUN_ID
GROUP BY domain;

SELECT '';
SELECT '=== End-to-End Validation ===' as report;
SELECT dns_server_name as server, domain, resolved_ip,
       SUM(reachable) as ok, COUNT(*)-SUM(reachable) as fail,
       ROUND(AVG(connect_time_ms), 0) as avg_connect_ms
FROM e2e_tests
WHERE run_id = $RUN_ID
GROUP BY dns_server, domain;

SELECT '';
SELECT '=== DNS Interception Check ===' as report;
SELECT dns_server_name as server, dns_server as ip,
       CASE WHEN SUM(is_intercepted) > 0 THEN 'INTERCEPTED' ELSE 'OK' END as status,
       SUM(is_intercepted) as detections
FROM interception_tests
WHERE run_id = $RUN_ID
GROUP BY dns_server;

SELECT '';
SELECT '=== Test Run Summary ===' as report;
SELECT run_id, total_tests as iterations, total_failures as failures,
       CASE WHEN total_tests > 0
            THEN ROUND(total_failures * 100.0 / total_tests, 2)
            ELSE 0 END as failure_rate_pct
FROM test_runs
WHERE run_id = $RUN_ID;
EOF

echo ""
echo "View full dashboard: python3 $SCRIPT_DIR/web_dashboard.py"
