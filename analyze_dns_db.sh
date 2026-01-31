#!/bin/bash

# DNS Database Analysis Tool

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DATA_DIR="$SCRIPT_DIR/data"
DB_FILE="$DATA_DIR/dns_monitoring.db"

if [ ! -f "$DB_FILE" ]; then
    echo "Database not found: $DB_FILE"
    exit 1
fi

# Function to show menu
show_menu() {
    echo ""
    echo "=== DNS Monitoring Analysis Tool ==="
    echo "1.  Show all test runs"
    echo "2.  Show IP change patterns for streaming services"
    echo "3.  Show DNS server reliability comparison"
    echo "4.  Show failure timeline"
    echo "5.  Show recursion failure analysis"
    echo "6.  Show ISP DNS vs Public DNS comparison"
    echo "7.  Show streaming service instability patterns"
    echo "8.  Show hourly failure distribution"
    echo "9.  Export data to CSV"
    echo "10. Custom SQL query"
    echo "0.  Exit"
    echo ""
}

# Function 1: Show test runs
show_test_runs() {
    sqlite3 -column -header "$DB_FILE" << 'EOF'
SELECT run_id, 
       datetime(start_time, 'localtime') as start,
       datetime(end_time, 'localtime') as end,
       total_tests,
       total_failures,
       ROUND(total_failures * 100.0 / (total_tests * 
           (SELECT COUNT(DISTINCT domain) FROM dns_queries WHERE run_id = test_runs.run_id) *
           (SELECT COUNT(DISTINCT dns_server) FROM dns_queries WHERE run_id = test_runs.run_id)), 2) as failure_rate_pct
FROM test_runs
ORDER BY run_id DESC
LIMIT 10;
EOF
}

# Function 2: IP change patterns
show_ip_changes() {
    echo "Enter run_id (or press Enter for latest):"
    read run_id
    
    if [ -z "$run_id" ]; then
        run_id=$(sqlite3 "$DB_FILE" "SELECT MAX(run_id) FROM test_runs;")
    fi
    
    sqlite3 -column -header "$DB_FILE" << EOF
SELECT domain,
       COUNT(*) as total_changes,
       ROUND(AVG(time_since_last_change_seconds), 0) as avg_interval_sec,
       ROUND(AVG(time_since_last_change_seconds) / 60.0, 1) as avg_interval_min,
       MIN(time_since_last_change_seconds) as min_interval_sec,
       MAX(time_since_last_change_seconds) as max_interval_sec,
       CASE 
           WHEN AVG(time_since_last_change_seconds) < 3600 THEN 'UNSTABLE'
           WHEN AVG(time_since_last_change_seconds) < 7200 THEN 'MODERATE'
           ELSE 'STABLE'
       END as stability_rating
FROM ip_changes
WHERE change_time >= (SELECT start_time FROM test_runs WHERE run_id = $run_id)
GROUP BY domain
ORDER BY total_changes DESC;

SELECT '';
SELECT 'IP Change Timeline for Most Unstable Domain:';
SELECT domain,
       datetime(change_time, 'localtime') as when_changed,
       old_ips,
       new_ips,
       ROUND(time_since_last_change_seconds / 60.0, 1) as minutes_since_last
FROM ip_changes
WHERE domain = (
    SELECT domain FROM ip_changes
    WHERE change_time >= (SELECT start_time FROM test_runs WHERE run_id = $run_id)
    GROUP BY domain
    ORDER BY COUNT(*) DESC
    LIMIT 1
)
ORDER BY change_time;
EOF
}

# Function 3: DNS server reliability
show_server_reliability() {
    echo "Enter run_id (or press Enter for latest):"
    read run_id
    
    if [ -z "$run_id" ]; then
        run_id=$(sqlite3 "$DB_FILE" "SELECT MAX(run_id) FROM test_runs;")
    fi
    
    sqlite3 -column -header "$DB_FILE" << EOF
SELECT dns_server_name as server,
       dns_server as ip,
       COUNT(*) as total_queries,
       SUM(CASE WHEN status = 'OK' THEN 1 ELSE 0 END) as successful,
       SUM(CASE WHEN status != 'OK' THEN 1 ELSE 0 END) as failed,
       ROUND(AVG(CASE WHEN status = 'OK' THEN response_time_ms END), 2) as avg_ok_response_ms,
       MAX(CASE WHEN status = 'OK' THEN response_time_ms END) as max_ok_response_ms,
       ROUND(SUM(CASE WHEN status != 'OK' THEN 1 ELSE 0 END) * 100.0 / COUNT(*), 2) as failure_rate_pct,
       CASE
           WHEN ROUND(SUM(CASE WHEN status != 'OK' THEN 1 ELSE 0 END) * 100.0 / COUNT(*), 2) < 1 THEN 'EXCELLENT'
           WHEN ROUND(SUM(CASE WHEN status != 'OK' THEN 1 ELSE 0 END) * 100.0 / COUNT(*), 2) < 5 THEN 'GOOD'
           WHEN ROUND(SUM(CASE WHEN status != 'OK' THEN 1 ELSE 0 END) * 100.0 / COUNT(*), 2) < 10 THEN 'FAIR'
           ELSE 'POOR'
       END as rating
FROM dns_queries
WHERE run_id = $run_id
GROUP BY dns_server
ORDER BY failure_rate_pct;

SELECT '';
SELECT 'Reachability Stats:';
SELECT dns_server_name as server,
       dns_server as ip,
       SUM(reachable) as times_reachable,
       COUNT(*) - SUM(reachable) as times_unreachable,
       ROUND(AVG(ping_time_ms), 2) as avg_ping_ms
FROM dns_reachability
WHERE run_id = $run_id
GROUP BY dns_server;
EOF
}

# Function 4: Failure timeline
show_failure_timeline() {
    echo "Enter run_id (or press Enter for latest):"
    read run_id
    
    if [ -z "$run_id" ]; then
        run_id=$(sqlite3 "$DB_FILE" "SELECT MAX(run_id) FROM test_runs;")
    fi
    
    sqlite3 -column -header "$DB_FILE" << EOF
SELECT strftime('%Y-%m-%d %H:00', timestamp, 'localtime') as hour,
       COUNT(*) as failures,
       GROUP_CONCAT(DISTINCT failure_mode) as failure_types
FROM dns_queries
WHERE run_id = $run_id AND status != 'OK'
GROUP BY strftime('%Y-%m-%d %H:00', timestamp, 'localtime')
ORDER BY hour;
EOF
}

# Function 5: Recursion analysis
show_recursion_analysis() {
    echo "Enter run_id (or press Enter for latest):"
    read run_id
    
    if [ -z "$run_id" ]; then
        run_id=$(sqlite3 "$DB_FILE" "SELECT MAX(run_id) FROM test_runs;")
    fi
    
    sqlite3 -column -header "$DB_FILE" << EOF
SELECT 'Recursion Success Rate:' as metric;
SELECT status,
       COUNT(*) as count,
       ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM recursion_tests WHERE run_id = $run_id), 2) as percentage
FROM recursion_tests
WHERE run_id = $run_id
GROUP BY status;

SELECT '';
SELECT 'Failure Points:' as metric;
SELECT failure_point,
       COUNT(*) as count,
       GROUP_CONCAT(DISTINCT domain) as affected_domains
FROM recursion_tests
WHERE run_id = $run_id AND status = 'FAIL'
GROUP BY failure_point
ORDER BY count DESC;

SELECT '';
SELECT 'Recursion Depth Analysis:' as metric;
SELECT recursion_depth as hops,
       COUNT(*) as occurrences,
       ROUND(AVG(total_time_ms), 2) as avg_time_ms
FROM recursion_tests
WHERE run_id = $run_id AND status = 'OK'
GROUP BY recursion_depth
ORDER BY recursion_depth;
EOF
}

# Function 6: ISP vs Public DNS
show_isp_vs_public() {
    echo "Enter your ISP DNS server IP:"
    read isp_dns
    
    echo "Enter run_id (or press Enter for latest):"
    read run_id
    
    if [ -z "$run_id" ]; then
        run_id=$(sqlite3 "$DB_FILE" "SELECT MAX(run_id) FROM test_runs;")
    fi
    
    sqlite3 -column -header "$DB_FILE" << EOF
SELECT 
    CASE 
        WHEN dns_server = '$isp_dns' THEN 'ISP DNS'
        ELSE 'Public DNS (' || dns_server || ')'
    END as dns_type,
    COUNT(*) as queries,
    SUM(CASE WHEN status = 'OK' THEN 1 ELSE 0 END) as successful,
    ROUND(AVG(CASE WHEN status = 'OK' THEN response_time_ms END), 2) as avg_response_ms,
    ROUND(SUM(CASE WHEN status != 'OK' THEN 1 ELSE 0 END) * 100.0 / COUNT(*), 2) as failure_rate_pct
FROM dns_queries
WHERE run_id = $run_id
GROUP BY dns_server
ORDER BY failure_rate_pct;
EOF
}

# Function 7: Streaming instability
show_streaming_instability() {
    sqlite3 -column -header "$DB_FILE" << 'EOF'
SELECT domain,
       COUNT(DISTINCT DATE(change_time)) as days_with_changes,
       COUNT(*) as total_changes,
       ROUND(AVG(time_since_last_change_seconds) / 60.0, 1) as avg_minutes_between_changes,
       CASE 
           WHEN AVG(time_since_last_change_seconds) < 1800 THEN 'HIGHLY UNSTABLE (<30min)'
           WHEN AVG(time_since_last_change_seconds) < 3600 THEN 'UNSTABLE (<1hr)'
           WHEN AVG(time_since_last_change_seconds) < 7200 THEN 'MODERATELY UNSTABLE (<2hr)'
           ELSE 'RELATIVELY STABLE'
       END as instability_assessment
FROM ip_changes
WHERE domain IN ('netflix.com', 'nflxvideo.net', 'nflxext.com', 'nflxso.net',
                 'tv.apple.com', 'play.itunes.apple.com', 'hls.itunes.apple.com')
GROUP BY domain
ORDER BY total_changes DESC;

SELECT '';
SELECT 'Correlation: IP Changes vs Query Failures';
SELECT ic.domain,
       COUNT(DISTINCT ic.change_id) as ip_changes,
       (SELECT COUNT(*) 
        FROM dns_queries dq 
        WHERE dq.domain = ic.domain 
        AND dq.status != 'OK'
        AND datetime(dq.timestamp) BETWEEN datetime(ic.change_time, '-5 minutes') 
        AND datetime(ic.change_time, '+5 minutes')) as failures_near_change
FROM ip_changes ic
WHERE ic.domain IN ('netflix.com', 'nflxvideo.net', 'nflxext.com', 'nflxso.net',
                    'tv.apple.com', 'play.itunes.apple.com', 'hls.itunes.apple.com')
GROUP BY ic.domain;
EOF
}

# Function 8: Hourly distribution
show_hourly_distribution() {
    echo "Enter run_id (or press Enter for latest):"
    read run_id
    
    if [ -z "$run_id" ]; then
        run_id=$(sqlite3 "$DB_FILE" "SELECT MAX(run_id) FROM test_runs;")
    fi
    
    sqlite3 -column -header "$DB_FILE" << EOF
SELECT strftime('%H:00', timestamp, 'localtime') as hour_of_day,
       COUNT(*) as total_queries,
       SUM(CASE WHEN status != 'OK' THEN 1 ELSE 0 END) as failures,
       ROUND(SUM(CASE WHEN status != 'OK' THEN 1 ELSE 0 END) * 100.0 / COUNT(*), 2) as failure_rate_pct
FROM dns_queries
WHERE run_id = $run_id
GROUP BY strftime('%H', timestamp, 'localtime')
ORDER BY hour_of_day;
EOF
}

# Function 9: Export to CSV
export_to_csv() {
    OUTPUT_DIR="$DATA_DIR/exports"
    mkdir -p "$OUTPUT_DIR"
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    
    echo "Exporting to $OUTPUT_DIR..."
    
    sqlite3 -header -csv "$DB_FILE" "SELECT * FROM dns_queries;" > "$OUTPUT_DIR/dns_queries_$TIMESTAMP.csv"
    sqlite3 -header -csv "$DB_FILE" "SELECT * FROM ip_changes;" > "$OUTPUT_DIR/ip_changes_$TIMESTAMP.csv"
    sqlite3 -header -csv "$DB_FILE" "SELECT * FROM recursion_tests;" > "$OUTPUT_DIR/recursion_tests_$TIMESTAMP.csv"
    sqlite3 -header -csv "$DB_FILE" "SELECT * FROM dns_reachability;" > "$OUTPUT_DIR/dns_reachability_$TIMESTAMP.csv"
    
    echo "Exported:"
    echo "  - dns_queries_$TIMESTAMP.csv"
    echo "  - ip_changes_$TIMESTAMP.csv"
    echo "  - recursion_tests_$TIMESTAMP.csv"
    echo "  - dns_reachability_$TIMESTAMP.csv"
}

# Function 10: Custom query
custom_query() {
    echo "Enter your SQL query (or 'tables' to see available tables):"
    read query
    
    if [ "$query" = "tables" ]; then
        sqlite3 -column -header "$DB_FILE" "SELECT name FROM sqlite_master WHERE type='table';"
        echo ""
        echo "Use .schema <table_name> to see table structure"
        return
    fi
    
    sqlite3 -column -header "$DB_FILE" "$query"
}

# Main loop
while true; do
    show_menu
    echo -n "Select option: "
    read choice
    
    case $choice in
        1) show_test_runs ;;
        2) show_ip_changes ;;
        3) show_server_reliability ;;
        4) show_failure_timeline ;;
        5) show_recursion_analysis ;;
        6) show_isp_vs_public ;;
        7) show_streaming_instability ;;
        8) show_hourly_distribution ;;
        9) export_to_csv ;;
        10) custom_query ;;
        0) echo "Goodbye!"; exit 0 ;;
        *) echo "Invalid option" ;;
    esac
    
    echo ""
    echo "Press Enter to continue..."
    read
done
