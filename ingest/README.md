# Ingest framework

How to add a new source

1. Create a new file in `ingest/adapters/` that extends `AdapterBase`.
2. Implement `fetch(self, **params)` which returns raw JSON.
3. Implement `normalize(self, raw_json, **params)` which returns a list of NormalizedRecord dicts.
4. Optionally override `store(self, records, conn)` to change storage behavior.

Running

- One-shot run inside container: `python -m ingest.runner --source nvd --max-items 10`
- Scheduler (default every minute): container runs `ingest.scheduler.start_scheduler()` via Dockerfile.

Notes

- The system uses Postgres advisory transaction-scoped locks to prevent concurrent runs across containers.
- Logs are structured and include a run correlation id.
