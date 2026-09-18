# api-orgs differential harness

Sends every case in `cases.py` to Node (`:3001`) and Rust (`:3102`) and compares the
status, the headers that matter, the body bytes and, for writes, the Postgres rows
each side left behind.

```
source ../env.sh                     # the parity stores
../run-node.sh &                     # Node on :3001, if it is not already up
./run-rust.sh &                      # Rust on :3102
PARITY_ORGS_OUT=/tmp/parity-orgs python3 fixtures.py setup > /tmp/parity-orgs/creds.json
PARITY_ORGS_OUT=/tmp/parity-orgs python3 run.py [route-substring ...]
python3 fixtures.py cleanup
```

`run.py` writes the mismatches to `$PARITY_ORGS_OUT/results.jsonl` and prints the
per-route counts. A write case resets the fixtures before each backend, so the two
sides start from the same rows.

Everything the harness writes is prefixed `parity-orgs-` (site ids 65300 and up), so
the other harnesses' rows in the same database stay untouched. It also adds a session
and an API key for three users of the production snapshot, read only: those
organizations are the only ones whose sites carry ClickHouse events, which is what
exercises the session-count query and the descending sort in
`GET /organizations/:id/sites`.

`last-run.txt` is the summary of the last full run.
