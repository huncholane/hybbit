#!/usr/bin/env python3
"""Dump everything startup init is allowed to touch, normalised so a Node-made store
and a Rust-made store can be compared byte for byte.

  dump.py <postgres-db> <clickhouse-db> <clickhouse-query-user> > snapshot.txt

Normalisation replaces the three names with @PGDB@, @CHDB@ and @CHUSER@ (the two sides
necessarily use different ones), strips pg_dump's header, its SET/SELECT preamble and
its psql \\restrict guards, and drops comment-only and blank lines. Nothing else is
touched: a difference in a type, a default, an engine, a key or a TTL survives.
"""
import json
import subprocess
import sys
import urllib.request

PG_CONTAINER = "hygo-parity-postgres-1"
PG_USER = "hygo"
CH_URL = "http://127.0.0.1:58123"
CH_AUTH = ("default", "hygo")

PG_DB, CH_DB, CH_QUERY_USER = sys.argv[1], sys.argv[2], sys.argv[3]


def placeholders(text):
    # Longest first: the query user's name usually has a database name as its prefix
    for name, token in sorted(
        ((PG_DB, "@PGDB@"), (CH_DB, "@CHDB@"), (CH_QUERY_USER, "@CHUSER@")), key=lambda pair: -len(pair[0])
    ):
        text = text.replace(name, token)
    return text


def pg(sql):
    out = subprocess.run(
        ["docker", "exec", "-i", PG_CONTAINER, "psql", "-U", PG_USER, "-d", PG_DB, "-At", "-F", "\t", "-c", sql],
        capture_output=True, text=True, check=True)
    return out.stdout.rstrip("\n")


def clickhouse(sql):
    request = urllib.request.Request(CH_URL, data=sql.encode(), headers={
        "X-ClickHouse-User": CH_AUTH[0], "X-ClickHouse-Key": CH_AUTH[1]})
    with urllib.request.urlopen(request) as response:
        return response.read().decode().rstrip("\n")


def pg_schema():
    """pg_dump --schema-only, minus everything that is about the dump rather than the schema."""
    dump = subprocess.run(
        ["docker", "exec", "-i", PG_CONTAINER, "pg_dump", "-U", PG_USER, "-d", PG_DB,
         "--schema-only", "--no-owner", "--no-privileges", "--no-comments"],
        capture_output=True, text=True, check=True).stdout
    kept = []
    for line in dump.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("--"):
            continue
        if stripped.startswith(("SET ", "SELECT pg_catalog.set_config", "\\restrict", "\\unrestrict")):
            continue
        kept.append(line)
    return "\n".join(kept)


def drizzle_bookkeeping():
    """The rows drizzle decides from. `id` is a SERIAL, so it is part of the contract."""
    return pg('select id, hash, created_at from drizzle.__drizzle_migrations order by id')


def users():
    """Not schema, but `initPostgres` writes here on every boot."""
    return pg('select "id", "role" from "user" order by "createdAt" asc, "id" asc')


def clickhouse_schema():
    tables = clickhouse(f"SHOW TABLES FROM {CH_DB} FORMAT TSVRaw").splitlines()
    parts = ["TABLES\n" + "\n".join(sorted(tables))]
    for table in sorted(tables):
        create = clickhouse(f"SHOW CREATE TABLE {CH_DB}.`{table}` FORMAT TSVRaw")
        parts.append(f"CREATE {table}\n{create}")
    return "\n\n".join(parts)


def query_user():
    """Server-global, so each side provisions its own name; the shapes must still match."""
    sections = []
    for label, sql in (
        ("USER", f"SHOW CREATE USER {CH_QUERY_USER} FORMAT TSVRaw"),
        ("GRANTS", f"SHOW GRANTS FOR {CH_QUERY_USER} FORMAT TSVRaw"),
        ("PROFILE", f"SHOW CREATE SETTINGS PROFILE {CH_QUERY_USER} FORMAT TSVRaw"),
    ):
        try:
            sections.append(f"{label}\n{clickhouse(sql)}")
        except Exception as error:  # a missing user is itself a difference worth showing
            sections.append(f"{label}\nERROR {error}")
    return "\n\n".join(sections)


sections = {
    "postgres-schema": pg_schema(),
    "drizzle-migrations": drizzle_bookkeeping(),
    "users": users(),
    "clickhouse-schema": clickhouse_schema(),
    "clickhouse-query-user": query_user(),
}
for name, body in sections.items():
    print(f"===== {name} =====")
    print(placeholders(body))
    print()

# A machine-readable copy on stderr keeps run.sh's diffs readable while still letting a
# caller see exactly which section moved.
print(json.dumps({name: len(body.splitlines()) for name, body in sections.items()}), file=sys.stderr)
