# TraceLens

Local observability proxy — capture HTTP latency, status and traces to SQLite/JSONL. Single-process, local-only.

> **Honest scope:** TraceLens is a tiny dev proxy for one machine. It is not distributed tracing. No sampling, no tail-sampling, no trace propagation (W3C/B3), no clustering, no retention policies beyond a capped ring buffer, no authentication, no TLS. If you need Jaeger/Tempo/OTel, use those.

## What it does

- Proxies any HTTP target (`TARGET=http://localhost:3000`) on `http://localhost:3888`
- Records per-request: method, path, status, latency (ms), timestamp, target, headers, error
- Stores to `data/traces.jsonl` (always) and `data/traces.db` via `node:sqlite` when available (Node ≥22.5)
- Serves a minimal viewer and JSON API at `/__tracelens`

## Quick start

```bash
npm install   # no dependencies — uses Node built-ins
TARGET=http://localhost:3000 npm start
# or
PORT=3888 TARGET=http://localhost:3000 node src/proxy.mjs
```

Send traffic through the proxy:

```bash
curl http://localhost:3888/api/hello
```

Open viewer: http://localhost:3888/__tracelens

## API

| Endpoint | Description |
|---|---|
| `GET /__tracelens` | Viewer HTML |
| `GET /__tracelens/traces?limit=100&method=GET&status=200` | JSON traces (newest first) |
| `GET /__tracelens/stats` | Count, avg/p95 latency, by-status |
| `GET /__tracelens/health` | Health check |

Query params: `limit` (max 1000), `method`, `status` (exact or prefix via viewer).

## Storage

- `data/traces.jsonl` — append-only JSON lines, survives restarts, capped in-memory to `MAX_TRACES` (default 5000, last 1000 reloaded on boot).
- `data/traces.db` — SQLite via `node:sqlite` (`DatabaseSync`). Falls back to JSONL-only on Node <22.5 or if `node:sqlite` unavailable.

No log rotation beyond ring-buffer pruning. Inspect raw: `cat data/traces.jsonl | jq`.

## Configuration

| Env | Default | Description |
|---|---|---|
| `PORT` / `PROXY_PORT` | `3888` | Proxy listen port |
| `TARGET` / `TARGET_URL` | `http://localhost:3000` | Upstream to proxy |
| `DATA_DIR` | `./data` | Storage directory |
| `MAX_TRACES` | `5000` | In-memory + SQLite cap |

## Limitations (read before using)

- **Local only** — single process, no auth, no TLS, binds to `0.0.0.0` naive.
- **No distributed tracing** — no context propagation, no span hierarchy, no correlation IDs.
- **Best-effort proxy** — hop-by-hop headers are not fully stripped; WebSocket/SSE not supported; large bodies stream but are not inspected.
- **No guarantees** — ring buffer drops oldest traces when full; JSONL grows until manually cleared.
- **Not production-hardened** — no rate limiting, no PII scrubbing. Use only for local dev.

## Viewer

Static HTML at `src/viewer/index.html` — no build step, no framework. Filter by path/method/status, live refresh (2s polling), avg/p95 stats.

## License

MIT — see [LICENSE](LICENSE).
