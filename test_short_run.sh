#!/bin/bash

# Run the monitor for just 3 minutes (3 iterations at 60 second intervals)
# This will demonstrate the fixes working

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Temporarily modify the script to run for only 3 minutes
export DURATION=180  # 3 minutes

echo "Starting DNS monitor for 3 minute test run..."
echo "Press Ctrl+C to stop early"
echo ""

timeout 180 bash "$SCRIPT_DIR/dns_monitor.sh"

echo ""
echo "Test completed. Checking results..."
echo ""

# Show summary
sqlite3 "$SCRIPT_DIR/data/dns_monitoring.db" << 'EOF'
.mode column
.headers on

SELECT 'Query Status Summary' as report;
SELECT status, COUNT(*) as count,
       ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM dns_queries), 2) as percentage
FROM dns_queries
GROUP BY status
ORDER BY count DESC;

SELECT '';
SELECT 'Failure Breakdown (actual errors only)' as report;
SELECT failure_mode, COUNT(*) as count
FROM dns_queries
WHERE status IN ('FAIL', 'TIMEOUT', 'SERVFAIL', 'REFUSED', 'NETUNREACH', 'NOSERVER')
GROUP BY failure_mode
ORDER BY count DESC;

SELECT '';
SELECT 'Test Run Summary' as report;
SELECT total_tests, total_failures,
       ROUND(total_failures * 100.0 / total_tests, 2) as failure_rate_pct
FROM test_runs
ORDER BY run_id DESC
LIMIT 1;
EOF
