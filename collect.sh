#!/bin/bash
set -u

BASE="/home/j.toshit/dns-latency-monitoring"
IFACE="${IFACE:-enX0}"
OUT="$BASE/data"
CODE="$BASE/Code"
DOMAINS="$BASE/Domains"
TS=$(date -u +%Y%m%dT%H%M%SZ)
TRACER=""

mkdir -p "$OUT" "$CODE/json"

exec 9>"$OUT/collect.lock"
flock -n 9 || {
    echo "$TS skipped: another round is running" >> "$OUT/skipped.log"
    exit 0
}

stop_tracer() {
    if [[ -n "$TRACER" ]] && kill -0 "$TRACER" 2>/dev/null; then
        kill -INT "$TRACER"
        wait "$TRACER"
    fi
    TRACER=""
}

trap stop_tracer EXIT INT TERM

shopt -s nullglob
for f in "$CODE"/json/*.json; do
    mv "$f" "$OUT/preexisting_${TS}_$(basename "$f")"
done

cd "$CODE" || exit 1

./dns_tracer "$IFACE" > "$OUT/tracer_${TS}.log" 2>&1 &
TRACER=$!

sleep 3

if ! kill -0 "$TRACER" 2>/dev/null; then
    wait "$TRACER"
    RC=$?
    TRACER=""
    echo "$TS tracer failed to start (exit $RC)" >> "$OUT/skipped.log"
    exit 1
fi

cd "$DOMAINS" || exit 1

timeout 90m ./run_resolver.sh \
    -r "$DOMAINS/resolvers.txt" \
    -f "$DOMAINS/domains.txt" \
    -n 100 \
    -d 0.5 \
    -o "$OUT/dig_${TS}.csv" \
    > "$OUT/bench_${TS}.log" 2>&1

BENCH_RC=$?

sleep 10
stop_tracer

JSON_FILES=("$CODE"/json/*.json)

if (( ${#JSON_FILES[@]} == 0 )); then
    echo "$TS no JSON files produced" >> "$OUT/skipped.log"
    ROUND_RC=1
else
    ROUND_RC=0
    for f in "${JSON_FILES[@]}"; do
        DEST="$OUT/json_${TS}_$(basename "$f")"
        if mv "$f" "$DEST"; then
            if ! python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$DEST"; then
                echo "$TS invalid JSON: $DEST" >> "$OUT/skipped.log"
                ROUND_RC=1
            fi
        else
            echo "$TS failed to move JSON: $f" >> "$OUT/skipped.log"
            ROUND_RC=1
        fi
    done
fi

echo "$TS benchmark_exit=$BENCH_RC collection_exit=$ROUND_RC" \
    >> "$OUT/rounds.log"

chown -R "$(stat -c '%u:%g' "$BASE")" "$OUT"

if (( BENCH_RC != 0 || ROUND_RC != 0 )); then
    exit 1
fi
