#!/bin/bash

DOMAINS_FILE="domains.txt"
OUTPUT_FILE="dns_results.csv"
NUM_DOMAINS=100
NUM_RUNS=1
DELAY=0
DNS_SERVER=""
QUERY_TYPE="A"

while [[ $# -gt 0 ]]; do
    case "$1" in
        -f|--file)
            DOMAINS_FILE="$2"
            shift 2
            ;;
        -n|--domains)
            NUM_DOMAINS="$2"
            shift 2
            ;;
        -r|--runs)
            NUM_RUNS="$2"
            shift 2
            ;;
        -d|--delay)
            DELAY="$2"
            shift 2
            ;;
        -s|--server)
            DNS_SERVER="$2"
            shift 2
            ;;
        -t|--type)
            QUERY_TYPE="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  -f, --file FILE       Domain file"
            echo "  -n, --domains N       Number of domains to test"
            echo "  -r, --runs N          Number of runs per domain"
            echo "  -d, --delay SEC       Delay between queries"
            echo "  -s, --server IP       DNS server"
            echo "  -t, --type TYPE       Query type (A, AAAA, etc.)"
            echo "  -o, --output FILE     Output CSV"
            echo "  -h, --help            Show help"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

if [[ ! -f "$DOMAINS_FILE" ]]; then
    echo "Domain file not found: $DOMAINS_FILE"
    exit 1
fi

if ! command -v dig &> /dev/null; then
    echo "dig is not installed"
    exit 1
fi

echo "timestamp,domain,run,query_type,dns_server,status,query_time_ms" > "$OUTPUT_FILE"

mapfile -t DOMAINS < <(
    sed 's/#.*//' "$DOMAINS_FILE" |
    sed '/^[[:space:]]*$/d' |
    head -n "$NUM_DOMAINS"
)

TOTAL=${#DOMAINS[@]}

echo "Starting DNS measurements"
echo "Domains : $TOTAL"
echo "Runs    : $NUM_RUNS"
echo "Type    : $QUERY_TYPE"
echo "Server  : ${DNS_SERVER:-system default}"
echo "Output  : $OUTPUT_FILE"
echo ""

for ((i=0; i<TOTAL; i++)); do
    DOMAIN="${DOMAINS[$i]}"
    
    for ((run=1; run<=NUM_RUNS; run++)); do
        
        TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

        if [[ -n "$DNS_SERVER" ]]; then
            RESULT=$(dig @"$DNS_SERVER" "$DOMAIN" "$QUERY_TYPE" +stats +time=5 +tries=1 2>/dev/null)
        else
            RESULT=$(dig "$DOMAIN" "$QUERY_TYPE" +stats +time=5 +tries=1 2>/dev/null)
        fi

        STATUS=$(echo "$RESULT" | awk '/status:/{print $6; exit}')
        QUERY_TIME=$(echo "$RESULT" | awk '/Query time:/{print $4; exit}')
        
        [[ -z "$STATUS" ]] && STATUS="ERROR"
        [[ -z "$QUERY_TIME" ]] && QUERY_TIME="-1"

        if [[ -n "$DNS_SERVER" ]]; then
            SERVER="$DNS_SERVER"
        else
            SERVER=$(echo "$RESULT" | awk '/SERVER:/{print $3; exit}' | sed 's/#.*//')
        fi

        echo "$TIMESTAMP,$DOMAIN,$run,$QUERY_TYPE,$SERVER,$STATUS,$QUERY_TIME" >> "$OUTPUT_FILE"

        echo "[$((i+1))/$TOTAL] $DOMAIN | run=$run | ${QUERY_TIME}ms | $STATUS"

        if (( DELAY > 0 )); then
            sleep "$DELAY"
        fi
    done
done

echo ""
echo "Done."
echo "Results saved to: $OUTPUT_FILE"

# sample query : ./dns_test.sh -f domains.txt -n 100 -r 20 -d 1 -s 8.8.8.8 -t A -o results.csv