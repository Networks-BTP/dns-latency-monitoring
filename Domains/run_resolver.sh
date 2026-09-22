#!/bin/bash

RESOLVERS_FILE="resolvers.txt"
DOMAINS_FILE="domains.txt"
OUTPUT_FILE="dns_results.csv"
NUM_DOMAINS=100
DELAY=0.5

while [[ $# -gt 0 ]]; do
    case "$1" in
        -r|--resolvers)
            RESOLVERS_FILE="$2"
            shift 2
            ;;
        -f|--domains)
            DOMAINS_FILE="$2"
            shift 2
            ;;
        -n|--num)
            NUM_DOMAINS="$2"
            shift 2
            ;;
        -d|--delay)
            DELAY="$2"
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
            echo "  -r, --resolvers FILE   Resolver file"
            echo "  -f, --domains FILE     Domain file"
            echo "  -n, --num N            Number of domains"
            echo "  -d, --delay SEC        Delay between queries"
            echo "  -o, --output FILE      Output CSV"
            echo "  -h, --help             Show help"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

if [[ ! -f "$RESOLVERS_FILE" ]]; then
    echo "Error: resolver file not found: $RESOLVERS_FILE"
    exit 1
fi

if [[ ! -f "$DOMAINS_FILE" ]]; then
    echo "Error: domain file not found: $DOMAINS_FILE"
    exit 1
fi

if [[ ! -x "./dns_test.sh" ]]; then
    echo "Error: ./dns_test.sh not found or not executable"
    exit 1
fi

mapfile -t RESOLVERS < <(
    sed 's/#.*//' "$RESOLVERS_FILE" |
    sed '/^[[:space:]]*$/d'
)

TOTAL_RESOLVERS=${#RESOLVERS[@]}

if (( TOTAL_RESOLVERS == 0 )); then
    echo "Error: no resolvers found"
    exit 1
fi

rm -f "$OUTPUT_FILE"

echo "timestamp,domain,run,query_type,dns_server,status,query_time_ms" > "$OUTPUT_FILE"

echo "Starting DNS benchmark"
echo "Resolvers : $TOTAL_RESOLVERS"
echo "Domains   : $NUM_DOMAINS"
echo "Delay     : ${DELAY}s"
echo "Output    : $OUTPUT_FILE"
echo ""

for ((r=0; r<TOTAL_RESOLVERS; r++)); do
    RESOLVER="${RESOLVERS[$r]}"

    echo "[$((r + 1))/$TOTAL_RESOLVERS] Resolver: $RESOLVER"

    TEMP_FILE=$(mktemp)

    ./dns_test.sh \
        -s "$RESOLVER" \
        -f "$DOMAINS_FILE" \
        -n "$NUM_DOMAINS" \
        -d "$DELAY" \
        -o "$TEMP_FILE"

    tail -n +2 "$TEMP_FILE" >> "$OUTPUT_FILE"

    rm -f "$TEMP_FILE"

    echo ""
done

echo "Benchmark complete."
echo "Results saved to: $OUTPUT_FILE"