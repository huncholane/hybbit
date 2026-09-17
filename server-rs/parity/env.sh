# Shared environment for running the Node and Rust backends against the parity
# stores from docker-compose.yml. Mirrors production's settings where they change
# behaviour (NODE_ENV, BASE_URL, DISABLE_SIGNUP); secrets are local placeholders.
export NODE_ENV=production
export BASE_URL=https://a.hygo.ai
export BETTER_AUTH_SECRET=parity-local-secret-not-for-production
export DISABLE_SIGNUP=true
export DISABLE_TELEMETRY=true
export MAPBOX_TOKEN=pk.parity-local
export POSTGRES_HOST=127.0.0.1 POSTGRES_PORT=55432 POSTGRES_USER=hygo POSTGRES_PASSWORD=hygo POSTGRES_DB=analytics
export CLICKHOUSE_HOST=http://127.0.0.1:58123 CLICKHOUSE_DB=analytics CLICKHOUSE_PASSWORD=hygo
export REDIS_HOST=127.0.0.1 REDIS_PORT=56379 REDIS_PASSWORD=hygo
