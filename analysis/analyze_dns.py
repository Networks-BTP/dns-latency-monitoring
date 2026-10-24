
import csv
import glob
import json
import math
import os
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone

DATA_DIR = "data"
OUT_DIR = "analysis"

os.makedirs(OUT_DIR, exist_ok=True)


def percentile(values, p):
    """Calculate a percentile using linear interpolation."""
    if not values:
        return None

    values = sorted(values)
    if len(values) == 1:
        return values[0]

    position = (len(values) - 1) * p
    lower = math.floor(position)
    upper = math.ceil(position)

    if lower == upper:
        return values[lower]

    return values[lower] * (upper - position) + values[upper] * (
        position - lower
    )


def safe_float(value):
    try:
        if value is None:
            return None
        number = float(value)
        return number if math.isfinite(number) and number >= 0 else None
    except (TypeError, ValueError):
        return None


def write_csv(path, rows, columns):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)


files = sorted(glob.glob(os.path.join(DATA_DIR, "json_*.json")))

if not files:
    raise SystemExit(f"No JSON files found in {DATA_DIR}/")

measurements = []
validation = []
round_stats = Counter()
seen_observations = Counter()
all_resolvers = set()

for path in files:
    filename = os.path.basename(path)

    match = re.search(r"json_(\d{8}T\d{6})Z_", filename)
    if match:
        round_time = datetime.strptime(
            match.group(1), "%Y%m%dT%H%M%S"
        ).replace(tzinfo=timezone.utc).isoformat()
    else:
        round_time = ""

    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except Exception as exc:
        validation.append(
            {"file": filename, "issue": f"Invalid JSON: {exc}"}
        )
        round_stats["invalid_json_files"] += 1
        continue

    if not isinstance(data, dict) or not isinstance(
        data.get("queries"), list
    ):
        validation.append(
            {"file": filename, "issue": "Missing dictionary/queries list"}
        )
        round_stats["invalid_structure_files"] += 1
        continue

    queries = data["queries"]
    round_stats["valid_files"] += 1
    round_stats["total_records"] += len(queries)

    if len(queries) != 1000:
        validation.append(
            {
                "file": filename,
                "issue": f"Expected 1000 records; found {len(queries)}",
            }
        )

    for index, item in enumerate(queries):
        if not isinstance(item, dict):
            validation.append(
                {
                    "file": filename,
                    "issue": f"Record {index} is not an object",
                }
            )
            round_stats["malformed_records"] += 1
            continue

        client = item.get("client") or {}
        server = item.get("server") or {}
        query = item.get("query") or {}
        response = item.get("response") or {}
        latency = item.get("latency") or {}

        query_parsed = query.get("parsed") or {}
        response_parsed = response.get("parsed") or {}

        questions = query_parsed.get("questions") or []
        first_question = questions[0] if questions else {}

        domain = first_question.get("name", "")
        query_type = first_question.get("type_name", "")
        resolver = server.get("ip", "")
        query_id = item.get("query_id", "")

        latency_ms = safe_float(latency.get("latency_ms"))
        is_timeout = latency.get("is_timeout") is True

        response_present = bool(response)
        rcode = response_parsed.get("rcode_name", "")
        if not rcode:
            rcode = ""

        if is_timeout:
            status = "timeout"
        elif not response_present:
            status = "missing_response"
        elif not response_parsed:
            status = "unparsed_response"
        elif rcode == "NOERROR":
            status = "success"
        elif rcode:
            status = "dns_error"
        else:
            status = "unknown"

        row = {
            "file": filename,
            "round_time_utc": round_time,
            "query_id": query_id,
            "client_ip": client.get("ip", ""),
            "resolver_ip": resolver,
            "domain": domain,
            "query_type": query_type,
            "latency_ms": latency_ms,
            "is_timeout": is_timeout,
            "response_present": response_present,
            "rcode_name": rcode,
            "status": status,
        }
        measurements.append(row)

        if resolver:
            all_resolvers.add(resolver)

        if not resolver:
            round_stats["missing_resolver"] += 1
        if not domain:
            round_stats["missing_domain"] += 1
        if latency_ms is None:
            round_stats["missing_or_invalid_latency"] += 1

        # Potential duplicates are flagged for review, not removed.
        # The key includes round, resolver, domain, and query type.
        if round_time and resolver and domain:
            key = (round_time, resolver, domain, query_type)
            seen_observations[key] += 1

duplicate_count = sum(
    count - 1 for count in seen_observations.values() if count > 1
)

validation.append(
    {
        "file": "ALL",
        "issue": f"Potential duplicate observations: {duplicate_count}",
    }
)

columns = [
    "file", "round_time_utc", "query_id", "client_ip",
    "resolver_ip", "domain", "query_type", "latency_ms",
    "is_timeout", "response_present", "rcode_name", "status",
]

write_csv(
    os.path.join(OUT_DIR, "measurements.csv"),
    measurements,
    columns,
)

# Summarize measurements by a group of rows.
def summarize(group_rows, keys):
    groups = defaultdict(list)

    for row in group_rows:
        key = tuple(row[k] for k in keys)
        groups[key].append(row)

    output = []

    for key, rows in sorted(groups.items(), key=lambda pair: str(pair[0])):
        n = len(rows)
        timeouts = sum(r["status"] == "timeout" for r in rows)
        successes = sum(r["status"] == "success" for r in rows)
        dns_errors = sum(r["status"] == "dns_error" for r in rows)
        missing = sum(
            r["status"] in (
                "missing_response", "unparsed_response", "unknown"
            )
            for r in rows
        )

        # Latency statistics use successful DNS responses only.
        valid_latencies = [
            r["latency_ms"]
            for r in rows
            if r["status"] == "success"
            and r["latency_ms"] is not None
        ]

        result = dict(zip(keys, key))
        result.update({
            "queries": n,
            "successes": successes,
            "timeouts": timeouts,
            "dns_errors": dns_errors,
            "missing_or_unparsed": missing,
            "success_rate_pct": round(100 * successes / n, 3) if n else None,
            "timeout_rate_pct": round(100 * timeouts / n, 3) if n else None,
            "dns_error_rate_pct": round(100 * dns_errors / n, 3) if n else None,
            "latency_samples": len(valid_latencies),
            "median_latency_ms": (
                round(percentile(valid_latencies, 0.5), 3)
                if valid_latencies else None
            ),
            "p95_latency_ms": (
                round(percentile(valid_latencies, 0.95), 3)
                if valid_latencies else None
            ),
        })
        output.append(result)

    return output


summary_columns = [
    "queries", "successes", "timeouts", "dns_errors",
    "missing_or_unparsed", "success_rate_pct", "timeout_rate_pct",
    "dns_error_rate_pct", "latency_samples",
    "median_latency_ms", "p95_latency_ms",
]

write_csv(
    os.path.join(OUT_DIR, "resolver_summary.csv"),
    summarize(measurements, ["resolver_ip"]),
    ["resolver_ip"] + summary_columns,
)

write_csv(
    os.path.join(OUT_DIR, "domain_summary.csv"),
    summarize(measurements, ["domain", "resolver_ip"]),
    ["domain", "resolver_ip"] + summary_columns,
)

write_csv(
    os.path.join(OUT_DIR, "round_summary.csv"),
    summarize(measurements, ["round_time_utc", "resolver_ip"]),
    ["round_time_utc", "resolver_ip"] + summary_columns,
)

# Find the lowest-latency successful resolver for each domain and round.
# This is a descriptive comparison, not yet an online selection algorithm.
by_domain_round = defaultdict(list)

for row in measurements:
    if (
        row["status"] == "success"
        and row["latency_ms"] is not None
        and row["domain"]
        and row["resolver_ip"]
    ):
        by_domain_round[
            (row["round_time_utc"], row["domain"])
        ].append(row)

fastest_rows = []

for (round_time, domain), rows in sorted(by_domain_round.items()):
    # Aggregate in case a domain/resolver appears more than once in a round.
    by_resolver = defaultdict(list)
    for row in rows:
        by_resolver[row["resolver_ip"]].append(row["latency_ms"])

    resolver_medians = {
        resolver: percentile(values, 0.5)
        for resolver, values in by_resolver.items()
    }

    if not resolver_medians:
        continue

    fastest = min(resolver_medians, key=resolver_medians.get)

    fastest_rows.append({
        "round_time_utc": round_time,
        "domain": domain,
        "fastest_resolver_ip": fastest,
        "median_latency_ms": round(resolver_medians[fastest], 3),
        "resolvers_with_success": len(resolver_medians),
    })

write_csv(
    os.path.join(OUT_DIR, "fastest_resolver_by_round.csv"),
    fastest_rows,
    [
        "round_time_utc", "domain", "fastest_resolver_ip",
        "median_latency_ms", "resolvers_with_success",
    ],
)

with open(
    os.path.join(OUT_DIR, "validation_report.txt"),
    "w",
    encoding="utf-8",
) as f:
    f.write("DNS DATA VALIDATION REPORT\n")
    f.write("==========================\n")
    f.write(f"Input files discovered: {len(files)}\n")
    f.write(f"Valid JSON files: {round_stats['valid_files']}\n")
    f.write(f"Invalid JSON files: {round_stats['invalid_json_files']}\n")
    f.write(
        f"Files with invalid structure: "
        f"{round_stats['invalid_structure_files']}\n"
    )
    f.write(f"Records in valid files: {round_stats['total_records']}\n")
    f.write(f"Rows flattened: {len(measurements)}\n")
    f.write(f"Resolvers discovered: {len(all_resolvers)}\n")
    f.write(f"Malformed records skipped: {round_stats['malformed_records']}\n")
    f.write(f"Records missing resolver: {round_stats['missing_resolver']}\n")
    f.write(f"Records missing domain: {round_stats['missing_domain']}\n")
    f.write(
        f"Records missing/invalid latency: "
        f"{round_stats['missing_or_invalid_latency']}\n"
    )
    f.write(f"Potential duplicate observations: {duplicate_count}\n")

    f.write("\nIssues:\n")
    if not validation:
        f.write("No issues detected by the basic checks.\n")
    else:
        for issue in validation:
            f.write(f"- {issue['file']}: {issue['issue']}\n")

print("Analysis complete.")
print(f"Input JSON files: {len(files)}")
print(f"Valid files: {round_stats['valid_files']}")
print(f"Flattened query records: {len(measurements)}")
print(f"Resolvers found: {len(all_resolvers)}")
print(f"Potential duplicate observations: {duplicate_count}")
print(f"Output directory: {OUT_DIR}/")
print("Generated:")
for name in [
    "measurements.csv",
    "resolver_summary.csv",
    "domain_summary.csv",
    "round_summary.csv",
    "fastest_resolver_by_round.csv",
    "validation_report.txt",
]:
    print(f"  {OUT_DIR}/{name}")
