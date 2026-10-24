# DNS Latency Analyzer — JSON-based Phase 2

This version replaces the mock experiment dashboard with a browser-only JSON analysis workflow.

## Run

```bash
npm install
npm run dev
```

Upload one or multiple JSON run files produced by the DNS latency monitoring project.

The parser extracts:
- `run.pid`
- `run.interface`
- `run.started_at`
- `queries[].latency.latency_ms`
- `queries[].latency.timestamp_ns`
- `queries[].latency.server_ip`
- `queries[].latency.query_type_name`
- `queries[].latency.rcode_name`
- `queries[].latency.is_timeout`
- `queries[].latency.answer_count`
- `queries[].latency.parsed_query.questions[0].name`

Multiple JSON files are combined in-memory while retaining source filename, PID, interface and resolver metadata.

No backend is required.
