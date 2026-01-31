#!/bin/bash

# DNS Chain Monitor - 24 Hour Test with SQLite tracking and full recursion analysis
# Tests multiple DNS servers and resolution paths to identify intermittent issues

# Configuration
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DATA_DIR="$SCRIPT_DIR/data"
LOG_FILE="$DATA_DIR/dns_test_$(date +%Y%m%d_%H%M%S).log"
DB_FILE="$DATA_DIR/dns_monitoring.db"
INTERVAL=60  # Test every 60 seconds
DURATION=$((24 * 60 * 60))  # 24 hours in seconds

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

# Streaming service domains - we'll track IP changes for these
STREAMING_DOMAINS=(
    "netflix.com"
    "nflxvideo.net"
    "nflxext.com"
    "nflxso.net"
    "tv.apple.com"
    "play.itunes.apple.com"
    "hls.itunes.apple.com"
    "ocsp.apple.com"
)

# General test domains
TEST_DOMAINS=(
    "google.com"
    "cloudflare.com"
    "github.com"
    "stackoverflow.com"
    "${STREAMING_DOMAINS[@]}"
)

# Create data directory
mkdir -p "$DATA_DIR"

# macOS compatibility: use gdate if available for millisecond timestamps
if command -v gdate &> /dev/null; then
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
                log "WARNING: Streaming service $domain changing IPs frequently (instability indicator)"
            fi
        fi
    fi
}

# Record reachability test
record_reachability() {
    local run_id=$1
    local dns_server=$2
    local reachable=$3
    local ping_time=$4
    local dns_server_name
    dns_server_name=$(get_dns_name "$dns_server")

    sqlite3 "$DB_FILE" << EOF
INSERT INTO dns_reachability (run_id, dns_server, dns_server_name, reachable, ping_time_ms)
VALUES ($run_id, '$dns_server', '$dns_server_name', $reachable, $ping_time);
EOF
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

# Test DNS server reachability
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
            # Try to determine which level failed
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

# Test for DNS hijacking
test_dns_hijacking() {
    local run_id=$1
    local dns_server=$2
    local dns_server_name
    dns_server_name=$(get_dns_name "$dns_server")

    # Generate a definitely non-existent domain
    fake_domain="nonexistent$(date +%s%N).example.invalid"
    result=$(dig +short +time=2 +tries=1 @"$dns_server" "$fake_domain" A 2>&1)

    is_hijacked=0
    returned_ip=""

    # If we get an IP back for a non-existent domain, DNS might be hijacked
    if echo "$result" | grep -qE '^[0-9]+\.'; then
        is_hijacked=1
        returned_ip="$result"
    fi

    sqlite3 "$DB_FILE" << EOF
INSERT INTO dns_hijacking (run_id, dns_server, dns_server_name, test_domain, returned_ip, is_hijacked)
VALUES ($run_id, '$dns_server', '$dns_server_name', '$fake_domain', '$returned_ip', $is_hijacked);
EOF

    if [ $is_hijacked -eq 1 ]; then
        echo "HIJACKED|$returned_ip"
    else
        echo "OK|NXDOMAIN"
    fi
}

# Test DNS consistency across servers
test_dns_consistency() {
    local run_id=$1
    local domain=$2
    local -a server_results=()
    local responses=""
    
    # Query all DNS servers and collect IPs
    for dns in "${DNS_SERVERS[@]}"; do
        # Skip placeholder ISP DNS entries
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
    
    # Check if all servers return consistent results
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
        
        # Replace placeholder entries
        isp_count=1
        while IFS= read -r dns; do
            if [ $isp_count -le 2 ]; then
                # Check if it's not already in our list
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
log "Duration: 24 hours"
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
log "Streaming domains tracked for IP changes: ${STREAMING_DOMAINS[@]}"
log ""

# Start test run
run_id=$(start_test_run)
log "Test run ID: $run_id"

start_time=$(date +%s)
test_count=0
failure_count=0

while [ $(($(date +%s) - start_time)) -lt $DURATION ]; do
    test_count=$((test_count + 1))
    log "--- Test Iteration #$test_count ---"
    
    # Test each DNS server's reachability
    for dns in "${DNS_SERVERS[@]}"; do
        # Skip placeholder entries
        if [[ "$dns" == "ISP_DNS_"* ]]; then
            continue
        fi
        
        reachability=$(test_dns_reachability "$dns")
        reach_status=$(echo "$reachability" | cut -d'|' -f1)
        reach_time=$(echo "$reachability" | cut -d'|' -f2)

        if [ "$reach_status" = "REACHABLE" ]; then
            record_reachability "$run_id" "$dns" 1 "$reach_time"
        else
            log "WARNING: DNS server $dns is $reach_status"
            record_reachability "$run_id" "$dns" 0 "$reach_time"
            # Note: reachability failures are tracked separately, not counted in general failure_count
        fi
        
        # Test for DNS hijacking every 10th iteration
        if [ $((test_count % 10)) -eq 0 ]; then
            hijack_test=$(test_dns_hijacking "$run_id" "$dns")
            hijack_status=$(echo "$hijack_test" | cut -d'|' -f1)
            if [ "$hijack_status" = "HIJACKED" ]; then
                hijack_ip=$(echo "$hijack_test" | cut -d'|' -f2)
                log "CRITICAL: DNS server $dns appears HIJACKED - returns $hijack_ip for non-existent domains"
                failure_count=$((failure_count + 1))
            fi
        fi
    done
    
    # Test resolution for each domain
    for domain in "${TEST_DOMAINS[@]}"; do
        # Test system DNS first
        sys_result=$(test_system_dns "$domain")
        sys_status=$(echo "$sys_result" | cut -d'|' -f1)
        sys_time=$(echo "$sys_result" | cut -d'|' -f2)
        sys_ip=$(echo "$sys_result" | cut -d'|' -f3)
        sys_failure=$(echo "$sys_result" | cut -d'|' -f4)
        
        record_query "$run_id" "system" "$domain" "$sys_status" "$sys_time" "$sys_ip" "$sys_failure"

        # Only log as failure for actual errors, not valid DNS responses like NODATA/NXDOMAIN
        if [ "$sys_status" = "FAIL" ] || [ "$sys_status" = "TIMEOUT" ] || [ "$sys_status" = "NETUNREACH" ] || [ "$sys_status" = "NOSERVER" ] || [ "$sys_status" = "SERVFAIL" ] || [ "$sys_status" = "REFUSED" ]; then
            log "FAILURE [$sys_status]: System DNS: $domain (${sys_time}ms)"
            failure_count=$((failure_count + 1))
        elif [ "$sys_status" != "OK" ]; then
            # Valid non-error response (NODATA, NXDOMAIN)
            log "INFO [$sys_status]: System DNS: $domain (${sys_time}ms)"
        elif [ "$sys_time" -gt 1000 ]; then
            log "SLOW: System DNS: $domain -> $sys_ip (${sys_time}ms)"
        fi
        
        # Test each configured DNS server
        for dns in "${DNS_SERVERS[@]}"; do
            # Skip placeholder entries
            if [[ "$dns" == "ISP_DNS_"* ]]; then
                continue
            fi
            
            result=$(test_dns_server "$dns" "$domain")
            status=$(echo "$result" | cut -d'|' -f1)
            time=$(echo "$result" | cut -d'|' -f2)
            ips=$(echo "$result" | cut -d'|' -f3)
            failure_mode=$(echo "$result" | cut -d'|' -f4)
            
            record_query "$run_id" "$dns" "$domain" "$status" "$time" "$ips" "$failure_mode"

            if [ "$status" = "OK" ]; then
                # Check for IP changes on streaming domains
                if [[ " ${STREAMING_DOMAINS[@]} " =~ " ${domain} " ]]; then
                    check_ip_change "$domain" "$dns" "$ips"
                fi

                if [ "$time" -gt 1000 ]; then
                    log "SLOW: $dns: $domain (${time}ms)"
                fi
            elif [ "$status" = "FAIL" ] || [ "$status" = "TIMEOUT" ] || [ "$status" = "NETUNREACH" ] || [ "$status" = "NOSERVER" ] || [ "$status" = "SERVFAIL" ] || [ "$status" = "REFUSED" ]; then
                # Actual errors that indicate problems
                log "FAILURE [$status]: $dns: $domain (${time}ms) - $failure_mode"
                failure_count=$((failure_count + 1))
            else
                # Valid non-error responses (NODATA, NXDOMAIN) - don't log as failure
                : # No-op, these are expected for some domains
            fi
        done
        
        # Test consistency across servers every 5th iteration
        if [ $((test_count % 5)) -eq 0 ]; then
            consistency=$(test_dns_consistency "$run_id" "$domain")
            if [[ "$consistency" == INCONSISTENT* ]]; then
                log "WARNING: Inconsistent DNS responses for $domain"
            fi
        fi
        
        # Test full recursion to root for select domains every 20th iteration
        if [ $((test_count % 20)) -eq 0 ]; then
            # Test recursion with first available DNS server
            for dns in "${DNS_SERVERS[@]}"; do
                if [[ "$dns" != "ISP_DNS_"* ]]; then
                    recursion_result=$(test_full_recursion "$run_id" "$domain" "$dns")
                    rec_status=$(echo "$recursion_result" | cut -d'|' -f1)
                    rec_depth=$(echo "$recursion_result" | cut -d'|' -f2)
                    rec_failure=$(echo "$recursion_result" | cut -d'|' -f3)
                    rec_time=$(echo "$recursion_result" | cut -d'|' -f4)
                    
                    if [ "$rec_status" = "OK" ]; then
                        log "RECURSION: $domain via $dns - $rec_depth hops (${rec_time}ms)"
                    else
                        log "RECURSION FAILURE: $domain via $dns - $rec_failure (${rec_time}ms)"
                        failure_count=$((failure_count + 1))
                    fi
                    break
                fi
            done
        fi
    done
    
    # Check current DNS configuration
    current_dns=$(cat /etc/resolv.conf 2>/dev/null | grep "^nameserver" | awk '{print $2}' | tr '\n' ' ')
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
SELECT dns_server, 
       COUNT(*) as total_queries,
       SUM(CASE WHEN status = 'OK' THEN 1 ELSE 0 END) as successful,
       SUM(CASE WHEN status != 'OK' THEN 1 ELSE 0 END) as failed,
       ROUND(AVG(response_time_ms), 2) as avg_response_ms,
       ROUND(SUM(CASE WHEN status != 'OK' THEN 1 ELSE 0 END) * 100.0 / COUNT(*), 2) as failure_rate_pct
FROM dns_queries 
WHERE run_id = $run_id
GROUP BY dns_server
ORDER BY failure_rate_pct DESC;

SELECT '';
SELECT 'Streaming Service IP Changes' as report;
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
SELECT dns_server, COUNT(*) as hijack_detections
FROM dns_hijacking
WHERE run_id = $run_id AND is_hijacked = 1
GROUP BY dns_server;
EOF

log ""
log "=== Analysis Complete ==="
log "Database: $DB_FILE"
log "Use the analysis script to query specific patterns"
