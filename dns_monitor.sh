#!/bin/bash

# DNS Chain Monitor - 24 Hour Test with SQLite tracking and full recursion analysis
# Tests multiple DNS servers and resolution paths to identify intermittent issues

# Configuration
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DATA_DIR="$SCRIPT_DIR/data"
LOG_FILE="$DATA_DIR/dns_test_$(date +%Y%m%d_%H%M%S).log"
DB_FILE="$DATA_DIR/dns_monitoring.db"
INTERVAL=${INTERVAL:-60}          # Test interval in seconds (configurable via env)
DURATION=${DURATION:-$((24 * 60 * 60))}  # Duration in seconds (configurable via env)

# DNS servers to test
DNS_SERVERS=(
    "8.8.8.8"
    "8.8.4.4"
    "1.1.1.1"
    "1.0.0.1"
    "64.59.135.135"
    "64.59.128.112"
)

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

# Streaming service domains - tracked for IP changes
STREAMING_DOMAINS=(
    "netflix.com"
    "nflxvideo.net"
    "nflxext.com"
    "nflxso.net"
    "tv.apple.com"
    "play.itunes.apple.com"
    "hls.itunes.apple.com"
    "ocsp.apple.com"
    "youtube.com"
    "googlevideo.com"
    "ytimg.com"
    "facebook.com"
    "fbcdn.net"
    "instagram.com"
)

# General test domains
TEST_DOMAINS=(
    "google.com"
    "cloudflare.com"
    "github.com"
    "stackoverflow.com"
    "${STREAMING_DOMAINS[@]}"
)

# CDN-heavy domains where IP inconsistency across servers is normal
CDN_DOMAINS=(
    "netflix.com"
    "nflxvideo.net"
    "googlevideo.com"
    "ytimg.com"
    "fbcdn.net"
    "instagram.com"
)

# Domains to test with HTTP connectivity checks
HTTP_TEST_DOMAINS=(
    "youtube.com"
    "facebook.com"
    "google.com"
    "netflix.com"
)

# Create data directory
mkdir -p "$DATA_DIR"

# Millisecond timestamp: prefer native date (Linux), then gdate (macOS), then python3
if [[ "$(date +%s%3N 2>/dev/null)" =~ ^[0-9]+$ ]]; then
    get_ms() { date +%s%3N; }
elif command -v gdate &> /dev/null; then
    get_ms() { gdate +%s%3N; }
else
    get_ms() { python3 -c 'import time; print(int(time.time() * 1000))'; }
fi

# Function to log with timestamp
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Initialize SQLite database
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

CREATE INDEX IF NOT EXISTS idx_queries_domain ON dns_queries(domain);
CREATE INDEX IF NOT EXISTS idx_queries_timestamp ON dns_queries(timestamp);
CREATE INDEX IF NOT EXISTS idx_queries_status ON dns_queries(status);
CREATE INDEX IF NOT EXISTS idx_ip_changes_domain ON ip_changes(domain);
CREATE INDEX IF NOT EXISTS idx_recursion_status ON recursion_tests(status);
EOF

    log "Database initialized at $DB_FILE"
}

# Start a new test run
start_test_run() {
    run_id=$(sqlite3 "$DB_FILE" "INSERT INTO test_runs (start_time) VALUES (datetime('now')); SELECT last_insert_rowid();")
    echo "$run_id"
}

# End test run
end_test_run() {
    local run_id=$1
    local total_tests=$2
    local total_failures=$3

    sqlite3 "$DB_FILE" << EOF
UPDATE test_runs
SET end_time = datetime('now'),
    total_tests = $total_tests,
    total_failures = $total_failures
WHERE run_id = $run_id;
EOF
}

# Record DNS query result
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

    # Escape single quotes for SQL
    ip_addresses=$(echo "$ip_addresses" | sed "s/'/''/g")
    failure_mode=$(echo "$failure_mode" | sed "s/'/''/g")

    sqlite3 "$DB_FILE" << EOF
INSERT INTO dns_queries (run_id, dns_server, dns_server_name, domain, status, response_time_ms, ip_addresses, failure_mode)
VALUES ($run_id, '$dns_server', '$dns_server_name', '$domain', '$status', $response_time, '$ip_addresses', '$failure_mode');
EOF
}

# Check and record IP changes
check_ip_change() {
    local domain=$1
    local dns_server=$2
    local new_ips=$3

    # Get last known IPs for this domain/server combo
    old_ips=$(sqlite3 "$DB_FILE" << EOF
SELECT ip_addresses
FROM dns_queries
WHERE domain = '$domain' AND dns_server = '$dns_server' AND status = 'OK' AND ip_addresses != ''
ORDER BY timestamp DESC
LIMIT 1;
EOF
    )

    # Sort IPs before comparing to avoid detecting order-only changes as real changes
    old_ips_sorted=$(echo "$old_ips" | tr ',' '\n' | sort | tr '\n' ',' | sed 's/,$//')
    new_ips_sorted=$(echo "$new_ips" | tr ',' '\n' | sort | tr '\n' ',' | sed 's/,$//')

    if [ -n "$old_ips" ] && [ "$old_ips_sorted" != "$new_ips_sorted" ]; then
        # Calculate time since last change
        last_change=$(sqlite3 "$DB_FILE" << EOF
SELECT strftime('%s', 'now') - strftime('%s', change_time)
FROM ip_changes
WHERE domain = '$domain' AND dns_server = '$dns_server'
ORDER BY change_time DESC
LIMIT 1;
EOF
        )

        last_change=${last_change:-0}

        local dns_server_name
        dns_server_name=$(get_dns_name "$dns_server")

        sqlite3 "$DB_FILE" << EOF
INSERT INTO ip_changes (domain, dns_server, dns_server_name, old_ips, new_ips, time_since_last_change_seconds)
VALUES ('$domain', '$dns_server', '$dns_server_name', '$old_ips', '$new_ips', $last_change);
EOF

        log "IP CHANGE DETECTED: $domain via $dns_server_name ($dns_server): $old_ips -> $new_ips (last change: ${last_change}s ago)"

        # Check if this is a streaming domain with frequent changes (possible instability)
        if [[ " ${STREAMING_DOMAINS[@]} " =~ " ${domain} " ]]; then
            if [ "$last_change" -lt 3600 ]; then  # Changed within last hour
                log "WARNING: Service $domain changing IPs frequently (instability indicator)"
            fi
        fi
    fi
}

# Test DNS resolution with specific server
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
            echo "NXDOMAIN|$response_time||NXDOMAIN"
            return
        fi

        if echo "$result" | grep -q "status: SERVFAIL"; then
            echo "SERVFAIL|$response_time||SERVFAIL"
            return
        fi

        if echo "$result" | grep -q "status: REFUSED"; then
            echo "REFUSED|$response_time||REFUSED"
            return
        fi

        if ! echo "$result" | grep -q "ANSWER SECTION"; then
            echo "NODATA|$response_time||NODATA"
            return
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

# Test system DNS (uses system resolver via dig without @server)
test_system_dns() {
    local domain=$1
    local start_time=$(get_ms)

    result=$(dig +short +time=2 +tries=1 "$domain" A 2>&1)
    local exit_code=$?
    local end_time=$(get_ms)
    local response_time=$((end_time - start_time))

    if [ $exit_code -eq 0 ]; then
        if [ -n "$result" ]; then
            # Filter to only IP addresses (dig +short may include CNAMEs)
            ip=$(echo "$result" | grep -E '^[0-9]+\.' | head -1)
            if [ -n "$ip" ]; then
                echo "OK|$response_time|$ip|"
            else
                echo "NODATA|$response_time||NODATA"
            fi
        else
            # Empty result but successful exit code = NODATA (domain exists, no A records)
            echo "NODATA|$response_time||NODATA"
        fi
    else
        echo "FAIL|$response_time||SYSTEM_ERROR"
    fi
}

# Test DNS server reachability using a lightweight DNS query
test_dns_reachability() {
    local dns_server=$1
    local start_time=$(get_ms)

    # Use a root NS query instead of ping - tests actual DNS service, not just ICMP
    dig +time=1 +tries=1 @"$dns_server" . NS +short > /dev/null 2>&1
    local exit_code=$?
    local end_time=$(get_ms)
    local response_time=$((end_time - start_time))

    if [ $exit_code -eq 0 ]; then
        echo "REACHABLE|$response_time"
    else
        echo "UNREACHABLE|$response_time"
    fi
}

# Test full DNS recursion to root
test_full_recursion() {
    local run_id=$1
    local domain=$2
    local dns_server=$3
    local start_time=$(get_ms)

    # Use dig +trace to follow the full recursion path
    result=$(dig +trace +time=10 +tries=1 @"$dns_server" "$domain" A 2>&1)
    local exit_code=$?
    local end_time=$(get_ms)
    local total_time=$((end_time - start_time))

    if [ $exit_code -eq 0 ]; then
        # Extract root servers queried
        root_servers=$(echo "$result" | grep -A1 "^\." | grep "Received" | sed 's/.*from \([^#]*\)#.*/\1/' | tr '\n' ',' | sed 's/,$//')

        # Extract TLD servers
        tld_servers=$(echo "$result" | grep -E "^[^.]+\.$" | grep "Received" | sed 's/.*from \([^#]*\)#.*/\1/' | tr '\n' ',' | sed 's/,$//')

        # Extract authoritative servers
        auth_servers=$(echo "$result" | grep "^$domain" | grep "Received" | sed 's/.*from \([^#]*\)#.*/\1/' | tr '\n' ',' | sed 's/,$//')

        # Count recursion depth (number of hops)
        depth=$(echo "$result" | grep -c "Received .* bytes from")

        status="OK"
        failure_point=""
    else
        root_servers=""
        tld_servers=""
        auth_servers=""
        depth=0
        status="FAIL"

        # Determine where recursion failed
        if echo "$result" | grep -q "communications error"; then
            failure_point="ROOT_TIMEOUT"
        elif echo "$result" | grep -q "SERVFAIL"; then
            if echo "$result" | grep -q "^\." && ! echo "$result" | grep -q "Received"; then
                failure_point="ROOT_SERVFAIL"
            elif echo "$result" | grep -qE "^[^.]+\.$"; then
                failure_point="TLD_SERVFAIL"
            else
                failure_point="AUTH_SERVFAIL"
            fi
        else
            failure_point="UNKNOWN"
        fi
    fi

    # Escape single quotes for SQL
    root_servers=$(echo "$root_servers" | sed "s/'/''/g")
    tld_servers=$(echo "$tld_servers" | sed "s/'/''/g")
    auth_servers=$(echo "$auth_servers" | sed "s/'/''/g")
    failure_point=$(echo "$failure_point" | sed "s/'/''/g")

    local dns_server_name
    dns_server_name=$(get_dns_name "$dns_server")

    sqlite3 "$DB_FILE" << EOF
INSERT INTO recursion_tests (run_id, domain, dns_server, dns_server_name, recursion_depth, root_servers_queried,
                             tld_servers_queried, authoritative_servers_queried, total_time_ms, status, failure_point)
VALUES ($run_id, '$domain', '$dns_server', '$dns_server_name', $depth, '$root_servers', '$tld_servers', '$auth_servers',
        $total_time, '$status', '$failure_point');
EOF

    echo "$status|$depth|$failure_point|$total_time"
}

# Test for DNS hijacking (parallel-safe: returns result without DB insert)
test_dns_hijacking_check() {
    local dns_server=$1

    # Generate a definitely non-existent domain
    local fake_domain="nonexistent$(date +%s%N).example.invalid"
    local result
    result=$(dig +short +time=2 +tries=1 @"$dns_server" "$fake_domain" A 2>&1)

    local is_hijacked=0
    local returned_ip=""

    # If we get an IP back for a non-existent domain, DNS might be hijacked
    if echo "$result" | grep -qE '^[0-9]+\.'; then
        is_hijacked=1
        returned_ip=$(echo "$result" | grep -E '^[0-9]+\.' | head -1)
    fi

    echo "${fake_domain}|${returned_ip}|${is_hijacked}"
}

# Test for transparent DNS interception by ISP
# Compares UDP vs TCP responses - if ISP intercepts UDP port 53, results will differ
test_dns_interception() {
    local dns_server=$1
    local test_domain="google.com"

    # Query via UDP (normal - may be intercepted by ISP)
    local udp_result
    udp_result=$(dig +short +time=2 +tries=1 @"$dns_server" "$test_domain" A 2>/dev/null | grep -E '^[0-9]+\.' | sort | tr '\n' ',' | sed 's/,$//')

    # Query via TCP (less commonly intercepted by transparent proxies)
    local tcp_result
    tcp_result=$(dig +tcp +short +time=2 +tries=1 @"$dns_server" "$test_domain" A 2>/dev/null | grep -E '^[0-9]+\.' | sort | tr '\n' ',' | sed 's/,$//')

    local is_intercepted=0
    if [ -n "$udp_result" ] && [ -n "$tcp_result" ] && [ "$udp_result" != "$tcp_result" ]; then
        is_intercepted=1
    fi

    echo "${is_intercepted}|${udp_result}|${tcp_result}"
}

# Test HTTP connectivity to distinguish DNS failures from general connectivity issues
test_http_connectivity() {
    local domain=$1
    local curl_result
    curl_result=$(curl -s -o /dev/null -w '%{http_code}|%{time_namelookup}|%{time_connect}|%{time_total}' \
        --max-time 10 "https://$domain/" 2>&1)

    local http_code dns_time connect_time total_time
    http_code=$(echo "$curl_result" | cut -d'|' -f1)
    dns_time=$(echo "$curl_result" | cut -d'|' -f2)
    connect_time=$(echo "$curl_result" | cut -d'|' -f3)
    total_time=$(echo "$curl_result" | cut -d'|' -f4)

    # Convert seconds to milliseconds
    local dns_time_ms connect_time_ms total_time_ms
    dns_time_ms=$(awk "BEGIN {printf \"%.0f\", ${dns_time:-0} * 1000}")
    connect_time_ms=$(awk "BEGIN {printf \"%.0f\", ${connect_time:-0} * 1000}")
    total_time_ms=$(awk "BEGIN {printf \"%.0f\", ${total_time:-0} * 1000}")

    echo "${http_code:-0}|${dns_time_ms}|${connect_time_ms}|${total_time_ms}"
}

# Test DNS consistency across servers
test_dns_consistency() {
    local run_id=$1
    local domain=$2
    local -a server_results=()
    local responses=""

    # Query all DNS servers and collect IPs
    for dns in "${DNS_SERVERS[@]}"; do
        if [[ "$dns" == "ISP_DNS_"* ]]; then
            continue
        fi

        result=$(dig +short +time=2 +tries=1 @"$dns" "$domain" A 2>/dev/null | grep -E '^[0-9]+\.' | sort | tr '\n' ',' | sed 's/,$//')
        if [ -n "$result" ]; then
            server_results+=("$dns:$result")
            responses="${responses}${dns}=${result};"
        fi
    done

    is_consistent=1

    if [ ${#server_results[@]} -gt 1 ]; then
        first_ip=$(echo "${server_results[0]}" | cut -d: -f2-)
        for entry in "${server_results[@]:1}"; do
            current_ip=$(echo "$entry" | cut -d: -f2-)
            if [ "$first_ip" != "$current_ip" ]; then
                is_consistent=0
                break
            fi
        done
    fi

    responses=$(echo "$responses" | sed "s/'/''/g")

    sqlite3 "$DB_FILE" << EOF
INSERT INTO consistency_checks (run_id, domain, is_consistent, server_responses)
VALUES ($run_id, '$domain', $is_consistent, '$responses');
EOF

    if [ $is_consistent -eq 1 ]; then
        echo "CONSISTENT"
    else
        echo "INCONSISTENT|$responses"
    fi
}

# Auto-detect ISP DNS servers
detect_isp_dns() {
    log "Attempting to auto-detect ISP DNS servers..."

    # Method 1: Check resolv.conf
    resolv_dns=$(grep "^nameserver" /etc/resolv.conf 2>/dev/null | awk '{print $2}' | grep -v "127.0.0")

    # Method 2: Check DHCP lease
    dhcp_dns=""
    if [ -f /var/lib/dhcp/dhclient.leases ]; then
        dhcp_dns=$(grep "domain-name-servers" /var/lib/dhcp/dhclient.leases | tail -1 | sed 's/.*domain-name-servers \(.*\);/\1/' | tr ',' '\n')
    fi

    # Method 3: Check NetworkManager
    nm_dns=""
    if command -v nmcli &> /dev/null; then
        nm_dns=$(nmcli dev show | grep "IP4.DNS" | awk '{print $2}')
    fi

    # Combine and deduplicate
    all_dns=$(echo -e "$resolv_dns\n$dhcp_dns\n$nm_dns" | grep -E '^[0-9]+\.' | sort -u)

    if [ -n "$all_dns" ]; then
        log "Detected potential ISP DNS servers:"
        echo "$all_dns" | while read dns; do
            log "  $dns"
        done

        isp_count=1
        while IFS= read -r dns; do
            if [ $isp_count -le 2 ]; then
                if [[ ! " ${DNS_SERVERS[@]} " =~ " ${dns} " ]]; then
                    for i in "${!DNS_SERVERS[@]}"; do
                        if [[ "${DNS_SERVERS[$i]}" == "ISP_DNS_$isp_count" ]]; then
                            DNS_SERVERS[$i]="$dns"
                            log "Set ISP_DNS_$isp_count to $dns"
                            ((isp_count++))
                            break
                        fi
                    done
                fi
            fi
        done <<< "$all_dns"
    else
        log "WARNING: Could not auto-detect ISP DNS servers. Please manually configure ISP_DNS_1 and ISP_DNS_2"
    fi
}

# Main monitoring loop
log "=== DNS Monitoring Started ==="
log "Duration: $((DURATION / 3600))h $((DURATION % 3600 / 60))m"
log "Interval: ${INTERVAL}s"
log "Log file: $LOG_FILE"
log "Database: $DB_FILE"
log ""

# Initialize database
init_database

# Detect ISP DNS servers
detect_isp_dns

log "Testing ${#TEST_DOMAINS[@]} domains against ${#DNS_SERVERS[@]} DNS servers"
log "DNS Servers: ${DNS_SERVERS[@]}"
log "Domains tracked for IP changes: ${STREAMING_DOMAINS[@]}"
log "HTTP connectivity test domains: ${HTTP_TEST_DOMAINS[@]}"
log ""

# Start test run
run_id=$(start_test_run)
log "Test run ID: $run_id"

start_time=$(date +%s)
test_count=0
failure_count=0

# Trap SIGTERM/SIGINT for graceful shutdown (e.g. when killed by timeout)
cleanup() {
    log "Received shutdown signal, saving results..."
    end_test_run "$run_id" "$test_count" "$failure_count"
    log "Results saved. Run ID: $run_id, Iterations: $test_count, Failures: $failure_count"
    rm -rf "$iter_tmp" 2>/dev/null
    exit 0
}
trap cleanup SIGTERM SIGINT

while [ $(($(date +%s) - start_time)) -lt $DURATION ]; do
    test_count=$((test_count + 1))
    log "--- Test Iteration #$test_count ---"

    # Create temp directory for parallel query results
    iter_tmp=$(mktemp -d)

    # ---- Phase 1: Launch all queries in parallel ----

    # Reachability tests
    for dns in "${DNS_SERVERS[@]}"; do
        [[ "$dns" == "ISP_DNS_"* ]] && continue
        dns_safe=$(echo "$dns" | tr '.' '_')
        ( test_dns_reachability "$dns" > "$iter_tmp/reach_${dns_safe}" ) &
    done

    # Hijacking tests every 10th iteration
    if [ $((test_count % 10)) -eq 0 ]; then
        for dns in "${DNS_SERVERS[@]}"; do
            [[ "$dns" == "ISP_DNS_"* ]] && continue
            dns_safe=$(echo "$dns" | tr '.' '_')
            ( test_dns_hijacking_check "$dns" > "$iter_tmp/hijack_${dns_safe}" ) &
        done
    fi

    # Interception tests every 10th iteration
    if [ $((test_count % 10)) -eq 0 ]; then
        for dns in "${DNS_SERVERS[@]}"; do
            [[ "$dns" == "ISP_DNS_"* ]] && continue
            dns_safe=$(echo "$dns" | tr '.' '_')
            ( test_dns_interception "$dns" > "$iter_tmp/intercept_${dns_safe}" ) &
        done
    fi

    # DNS resolution: all domains x all servers in parallel
    for domain in "${TEST_DOMAINS[@]}"; do
        domain_safe=$(echo "$domain" | tr '.' '_')

        # System DNS
        ( test_system_dns "$domain" > "$iter_tmp/sys_${domain_safe}" ) &

        # Each configured DNS server
        for dns in "${DNS_SERVERS[@]}"; do
            [[ "$dns" == "ISP_DNS_"* ]] && continue
            dns_safe=$(echo "$dns" | tr '.' '_')
            ( test_dns_server "$dns" "$domain" > "$iter_tmp/dns_${domain_safe}_${dns_safe}" ) &
        done
    done

    # HTTP connectivity tests every 5th iteration
    if [ $((test_count % 5)) -eq 0 ]; then
        for domain in "${HTTP_TEST_DOMAINS[@]}"; do
            domain_safe=$(echo "$domain" | tr '.' '_')
            ( test_http_connectivity "$domain" > "$iter_tmp/http_${domain_safe}" ) &
        done
    fi

    # Wait for ALL parallel queries to complete
    wait

    # ---- Phase 2: Process results and build batch SQL ----
    sql_batch="BEGIN TRANSACTION;"

    # Process reachability results
    for dns in "${DNS_SERVERS[@]}"; do
        [[ "$dns" == "ISP_DNS_"* ]] && continue
        dns_safe=$(echo "$dns" | tr '.' '_')
        result_file="$iter_tmp/reach_${dns_safe}"
        [ -f "$result_file" ] || continue

        reachability=$(<"$result_file")
        reach_status=$(echo "$reachability" | cut -d'|' -f1)
        reach_time=$(echo "$reachability" | cut -d'|' -f2)
        dns_name=$(get_dns_name "$dns")

        if [ "$reach_status" = "REACHABLE" ]; then
            sql_batch+=" INSERT INTO dns_reachability (run_id, dns_server, dns_server_name, reachable, ping_time_ms) VALUES ($run_id, '$dns', '$dns_name', 1, $reach_time);"
        else
            log "WARNING: DNS server $dns ($dns_name) is UNREACHABLE"
            sql_batch+=" INSERT INTO dns_reachability (run_id, dns_server, dns_server_name, reachable, ping_time_ms) VALUES ($run_id, '$dns', '$dns_name', 0, $reach_time);"
        fi
    done

    # Process hijacking results
    if [ $((test_count % 10)) -eq 0 ]; then
        for dns in "${DNS_SERVERS[@]}"; do
            [[ "$dns" == "ISP_DNS_"* ]] && continue
            dns_safe=$(echo "$dns" | tr '.' '_')
            result_file="$iter_tmp/hijack_${dns_safe}"
            [ -f "$result_file" ] || continue

            hijack_result=$(<"$result_file")
            hijack_domain=$(echo "$hijack_result" | cut -d'|' -f1)
            hijack_ip=$(echo "$hijack_result" | cut -d'|' -f2)
            hijack_flag=$(echo "$hijack_result" | cut -d'|' -f3)
            dns_name=$(get_dns_name "$dns")

            hijack_domain_esc=$(echo "$hijack_domain" | sed "s/'/''/g")
            sql_batch+=" INSERT INTO dns_hijacking (run_id, dns_server, dns_server_name, test_domain, returned_ip, is_hijacked) VALUES ($run_id, '$dns', '$dns_name', '$hijack_domain_esc', '$hijack_ip', $hijack_flag);"

            if [ "$hijack_flag" = "1" ]; then
                log "CRITICAL: DNS server $dns ($dns_name) appears HIJACKED - returns $hijack_ip for non-existent domains"
                failure_count=$((failure_count + 1))
            fi
        done
    fi

    # Process interception results
    if [ $((test_count % 10)) -eq 0 ]; then
        for dns in "${DNS_SERVERS[@]}"; do
            [[ "$dns" == "ISP_DNS_"* ]] && continue
            dns_safe=$(echo "$dns" | tr '.' '_')
            result_file="$iter_tmp/intercept_${dns_safe}"
            [ -f "$result_file" ] || continue

            intercept_result=$(<"$result_file")
            is_intercepted=$(echo "$intercept_result" | cut -d'|' -f1)
            udp_ips=$(echo "$intercept_result" | cut -d'|' -f2)
            tcp_ips=$(echo "$intercept_result" | cut -d'|' -f3)
            dns_name=$(get_dns_name "$dns")

            udp_esc=$(echo "$udp_ips" | sed "s/'/''/g")
            tcp_esc=$(echo "$tcp_ips" | sed "s/'/''/g")
            sql_batch+=" INSERT INTO interception_tests (run_id, dns_server, dns_server_name, domain, udp_result, tcp_result, is_intercepted) VALUES ($run_id, '$dns', '$dns_name', 'google.com', '$udp_esc', '$tcp_esc', $is_intercepted);"

            if [ "$is_intercepted" = "1" ]; then
                log "CRITICAL: Transparent DNS interception detected for $dns ($dns_name) - UDP: $udp_ips, TCP: $tcp_ips"
            fi
        done
    fi

    # Process DNS query results
    for domain in "${TEST_DOMAINS[@]}"; do
        domain_safe=$(echo "$domain" | tr '.' '_')

        # System DNS result
        result_file="$iter_tmp/sys_${domain_safe}"
        if [ -f "$result_file" ]; then
            sys_result=$(<"$result_file")
            sys_status=$(echo "$sys_result" | cut -d'|' -f1)
            sys_time=$(echo "$sys_result" | cut -d'|' -f2)
            sys_ip=$(echo "$sys_result" | cut -d'|' -f3)
            sys_failure=$(echo "$sys_result" | cut -d'|' -f4)

            sys_ip_esc=$(echo "$sys_ip" | sed "s/'/''/g")
            sys_fail_esc=$(echo "$sys_failure" | sed "s/'/''/g")
            sql_batch+=" INSERT INTO dns_queries (run_id, dns_server, dns_server_name, domain, status, response_time_ms, ip_addresses, failure_mode) VALUES ($run_id, 'system', 'System Resolver', '$domain', '$sys_status', $sys_time, '$sys_ip_esc', '$sys_fail_esc');"

            if [ "$sys_status" = "FAIL" ] || [ "$sys_status" = "TIMEOUT" ] || [ "$sys_status" = "NETUNREACH" ] || [ "$sys_status" = "NOSERVER" ] || [ "$sys_status" = "SERVFAIL" ] || [ "$sys_status" = "REFUSED" ]; then
                log "FAILURE [$sys_status]: System DNS: $domain (${sys_time}ms)"
                failure_count=$((failure_count + 1))
            elif [ "$sys_status" != "OK" ]; then
                log "INFO [$sys_status]: System DNS: $domain (${sys_time}ms)"
            elif [ "$sys_time" -gt 1000 ] 2>/dev/null; then
                log "SLOW: System DNS: $domain -> $sys_ip (${sys_time}ms)"
            fi
        fi

        # Per-server DNS results
        for dns in "${DNS_SERVERS[@]}"; do
            [[ "$dns" == "ISP_DNS_"* ]] && continue
            dns_safe=$(echo "$dns" | tr '.' '_')
            result_file="$iter_tmp/dns_${domain_safe}_${dns_safe}"
            [ -f "$result_file" ] || continue

            result=$(<"$result_file")
            status=$(echo "$result" | cut -d'|' -f1)
            rtime=$(echo "$result" | cut -d'|' -f2)
            ips=$(echo "$result" | cut -d'|' -f3)
            failure_mode=$(echo "$result" | cut -d'|' -f4)
            dns_name=$(get_dns_name "$dns")

            ips_esc=$(echo "$ips" | sed "s/'/''/g")
            fail_esc=$(echo "$failure_mode" | sed "s/'/''/g")
            sql_batch+=" INSERT INTO dns_queries (run_id, dns_server, dns_server_name, domain, status, response_time_ms, ip_addresses, failure_mode) VALUES ($run_id, '$dns', '$dns_name', '$domain', '$status', $rtime, '$ips_esc', '$fail_esc');"

            if [ "$status" = "OK" ]; then
                if [ "$rtime" -gt 1000 ] 2>/dev/null; then
                    log "SLOW: $dns ($dns_name): $domain (${rtime}ms)"
                fi
            elif [ "$status" = "FAIL" ] || [ "$status" = "TIMEOUT" ] || [ "$status" = "NETUNREACH" ] || [ "$status" = "NOSERVER" ] || [ "$status" = "SERVFAIL" ] || [ "$status" = "REFUSED" ]; then
                log "FAILURE [$status]: $dns ($dns_name): $domain (${rtime}ms) - $failure_mode"
                failure_count=$((failure_count + 1))
            fi
        done
    done

    # Process HTTP test results
    if [ $((test_count % 5)) -eq 0 ]; then
        for domain in "${HTTP_TEST_DOMAINS[@]}"; do
            domain_safe=$(echo "$domain" | tr '.' '_')
            result_file="$iter_tmp/http_${domain_safe}"
            [ -f "$result_file" ] || continue

            http_result=$(<"$result_file")
            http_code=$(echo "$http_result" | cut -d'|' -f1)
            dns_time=$(echo "$http_result" | cut -d'|' -f2)
            connect_time=$(echo "$http_result" | cut -d'|' -f3)
            total_time=$(echo "$http_result" | cut -d'|' -f4)

            sql_batch+=" INSERT INTO http_tests (run_id, domain, http_code, dns_time_ms, connect_time_ms, total_time_ms) VALUES ($run_id, '$domain', ${http_code:-0}, ${dns_time:-0}, ${connect_time:-0}, ${total_time:-0});"

            if [ "${http_code:-0}" = "000" ] || [ "${http_code:-0}" = "0" ]; then
                log "HTTP FAIL: $domain connection failed (dns: ${dns_time}ms, total: ${total_time}ms)"
            elif [ "${http_code:-0}" != "200" ] && [ "${http_code:-0}" != "301" ] && [ "${http_code:-0}" != "302" ] && [ "${http_code:-0}" != "303" ]; then
                log "HTTP ERROR: $domain returned HTTP $http_code (dns: ${dns_time}ms, total: ${total_time}ms)"
            elif [ "${total_time:-0}" -gt 5000 ] 2>/dev/null; then
                log "HTTP SLOW: $domain HTTP $http_code (dns: ${dns_time}ms, connect: ${connect_time}ms, total: ${total_time}ms)"
            fi
        done
    fi

    # Execute batch SQL
    sql_batch+=" COMMIT;"
    sqlite3 "$DB_FILE" <<< "$sql_batch"

    # ---- Phase 3: Post-insert checks (need current data in DB) ----

    # Check IP changes for streaming domains
    for domain in "${STREAMING_DOMAINS[@]}"; do
        domain_safe=$(echo "$domain" | tr '.' '_')
        for dns in "${DNS_SERVERS[@]}"; do
            [[ "$dns" == "ISP_DNS_"* ]] && continue
            dns_safe=$(echo "$dns" | tr '.' '_')
            result_file="$iter_tmp/dns_${domain_safe}_${dns_safe}"
            [ -f "$result_file" ] || continue

            result=$(<"$result_file")
            status=$(echo "$result" | cut -d'|' -f1)
            ips=$(echo "$result" | cut -d'|' -f3)

            if [ "$status" = "OK" ] && [ -n "$ips" ]; then
                check_ip_change "$domain" "$dns" "$ips"
            fi
        done
    done

    # Consistency checks every 5th iteration (skip CDN-heavy domains)
    if [ $((test_count % 5)) -eq 0 ]; then
        for domain in "${TEST_DOMAINS[@]}"; do
            if [[ " ${CDN_DOMAINS[*]} " =~ " ${domain} " ]]; then
                continue
            fi
            consistency=$(test_dns_consistency "$run_id" "$domain")
            if [[ "$consistency" == INCONSISTENT* ]]; then
                log "WARNING: Inconsistent DNS responses for $domain"
            fi
        done
    fi

    # Recursion tests every 20th iteration
    if [ $((test_count % 20)) -eq 0 ]; then
        for domain in "${TEST_DOMAINS[@]}"; do
            for dns in "${DNS_SERVERS[@]}"; do
                if [[ "$dns" != "ISP_DNS_"* ]]; then
                    recursion_result=$(test_full_recursion "$run_id" "$domain" "$dns")
                    rec_status=$(echo "$recursion_result" | cut -d'|' -f1)
                    rec_depth=$(echo "$recursion_result" | cut -d'|' -f2)
                    rec_failure=$(echo "$recursion_result" | cut -d'|' -f3)
                    rec_time=$(echo "$recursion_result" | cut -d'|' -f4)
                    dns_name=$(get_dns_name "$dns")

                    if [ "$rec_status" = "OK" ]; then
                        log "RECURSION: $domain via $dns ($dns_name) - $rec_depth hops (${rec_time}ms)"
                    else
                        log "RECURSION FAILURE: $domain via $dns ($dns_name) - $rec_failure (${rec_time}ms)"
                        failure_count=$((failure_count + 1))
                    fi
                    break
                fi
            done
        done
    fi

    # Cleanup temp directory
    rm -rf "$iter_tmp"

    # Check current DNS configuration
    current_dns=$(grep "^nameserver" /etc/resolv.conf 2>/dev/null | awk '{print $2}' | tr '\n' ' ')
    log "Current resolv.conf nameservers: ${current_dns:-NONE}"
    log ""

    # Sleep until next test
    sleep $INTERVAL
done

# End test run
end_test_run "$run_id" "$test_count" "$failure_count"

log "=== DNS Monitoring Completed ==="
log "Run ID: $run_id"
log "Total test iterations: $test_count"
log "Total failures: $failure_count"

# Generate summary from database
log ""
log "=== Generating Database Summary ==="

sqlite3 "$DB_FILE" << EOF
.mode column
.headers on
SELECT 'Failure Modes Summary' as report;
SELECT failure_mode, COUNT(*) as count,
       ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM dns_queries WHERE run_id = $run_id), 2) as percentage
FROM dns_queries
WHERE run_id = $run_id AND status != 'OK'
GROUP BY failure_mode
ORDER BY count DESC;

SELECT '';
SELECT 'DNS Server Performance' as report;
SELECT dns_server_name as server, dns_server as ip,
       COUNT(*) as total_queries,
       SUM(CASE WHEN status = 'OK' THEN 1 ELSE 0 END) as successful,
       SUM(CASE WHEN status != 'OK' THEN 1 ELSE 0 END) as failed,
       ROUND(AVG(CASE WHEN status = 'OK' THEN response_time_ms END), 2) as avg_ok_ms,
       ROUND(SUM(CASE WHEN status != 'OK' THEN 1 ELSE 0 END) * 100.0 / COUNT(*), 2) as failure_rate_pct
FROM dns_queries
WHERE run_id = $run_id
GROUP BY dns_server
ORDER BY failure_rate_pct DESC;

SELECT '';
SELECT 'Streaming/CDN Service IP Changes' as report;
SELECT domain, dns_server, COUNT(*) as change_count,
       MIN(time_since_last_change_seconds) as min_interval_sec,
       MAX(time_since_last_change_seconds) as max_interval_sec,
       ROUND(AVG(time_since_last_change_seconds), 0) as avg_interval_sec
FROM ip_changes
WHERE change_time >= (SELECT start_time FROM test_runs WHERE run_id = $run_id)
GROUP BY domain, dns_server
ORDER BY change_count DESC;

SELECT '';
SELECT 'Recursion Failures' as report;
SELECT failure_point, COUNT(*) as count
FROM recursion_tests
WHERE run_id = $run_id AND status = 'FAIL'
GROUP BY failure_point
ORDER BY count DESC;

SELECT '';
SELECT 'DNS Hijacking Detected' as report;
SELECT dns_server_name as server, dns_server as ip, COUNT(*) as hijack_detections
FROM dns_hijacking
WHERE run_id = $run_id AND is_hijacked = 1
GROUP BY dns_server;

SELECT '';
SELECT 'Transparent DNS Interception' as report;
SELECT dns_server_name as server, dns_server as ip,
       SUM(is_intercepted) as interceptions_detected,
       COUNT(*) as tests_run
FROM interception_tests
WHERE run_id = $run_id
GROUP BY dns_server;

SELECT '';
SELECT 'HTTP Connectivity Summary' as report;
SELECT domain,
       COUNT(*) as tests,
       ROUND(AVG(dns_time_ms), 0) as avg_dns_ms,
       ROUND(AVG(connect_time_ms), 0) as avg_connect_ms,
       ROUND(AVG(total_time_ms), 0) as avg_total_ms,
       SUM(CASE WHEN http_code = 0 THEN 1 ELSE 0 END) as connection_failures
FROM http_tests
WHERE run_id = $run_id
GROUP BY domain;
EOF

log ""
log "=== Analysis Complete ==="
log "Database: $DB_FILE"
log "Use the analysis script to query specific patterns"
