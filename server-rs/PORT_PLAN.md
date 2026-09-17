# Rust backend port

The Fastify backend in `../server` is being rewritten in Rust (this crate), route by route, with full parity. This file is the source of truth for what is ported, how cutover works and what must match Node exactly. Update the status column in the same commit that switches a route.

## Decisions (2026-09-17)

- **Cutover:** route by route. The Rust container runs next to Node on the rybbit box; Caddy sends ported paths to Rust and everything else to Node until nothing is left, then Node is removed.
- **Scope:** everything, including features with no production data (Search Console, session replay, imports, feature flags, experiments, goals, segments, dashboards, annotations, identify, MCP, PDF export).
- **No billing** (user, 2026-09-17: "we don't really need stripe"): Stripe and AppSumo routes, the Stripe webhook, the usage cron and plan lookups are not ported. They were only registered with `CLOUD=true`, which production never set, so nothing live changes. Wherever Node consults a plan (import quotas, PDF export, replay entitlement, API key limits, over-limit checks), Rust implements the self-hosted answer Node gives without `CLOUD`.
- **Logins keep working:** `/api/auth/*` is reimplemented wire-compatible with the Better Auth 1.6.25 subset the client uses, reading and writing the same Postgres rows, so no user is logged out and no password changes.
- **PDF export:** drawn with the `pdf-writer` crate, no Chromium.
- **Client in the Rust server** (user, 2026-09-17: "have the client served in the rust server... no need to run a second container for that"): the Next.js client becomes a static export baked into the `backend-rs` image; the Rust server serves it (route matching for dynamic segments, the `proxy.ts` redirects, the `/widget/:siteId` renderer) and the `client` container goes away.
- **Sign-ups stay disabled** (`DISABLE_SIGNUP=true`): both password sign-up and email-code sign-in for unknown emails are refused, matching `emailAndPassword.disableSignUp` and `emailOTP({ disableSignUp })`.
- rybbit upstream backend changes can no longer be merged; they get hand-ported.

## How cutover works

- **Container:** `backend-rs` on the `hygo` compose network, listening on 3001, with the same environment block as `backend`. Healthcheck `GET /api/health` → `OK`.
- **Caddy:** inside the existing `handle /api*` block, a named matcher lists the ported paths and proxies them to `backend-rs:3001`; the rest still go to `backend:3001`. Script and static routes outside `/api` get their own matcher. Rolling a route back means removing it from the matcher and reloading Caddy; no data changes.
- **Shared state during the transition:** both backends run at once, so everything they share must be byte-compatible:
  - Redis keys and Lua scripts (`sessionGetOrCreate`, `sessionRefresh`, `stickyResolve`, `apiRateLimit`, `anomalyObserve`, `bot:*`, `feature-flags:definitions:*`, `rl:*`), so a visitor's session, sticky identity, bot counters and rate limits are the same whichever backend served the request.
  - ClickHouse rows (column formats, `timestamp`/`timestamp_ms` formatting, JSON props, `url_parameters`).
  - Postgres rows, including Better Auth's session, account, apikey and verification formats.
- **Background jobs:** each job runs in exactly one backend. Node keeps a job until the phase that ports it, and the Rust side only starts it behind an env switch flipped at the same deploy that stops it in Node.

## Verification for every area

1. **Port the TypeScript tests** that cover the area into Rust tests (they encode edge cases: SQL fragments, channel classification, bot rules, filter building, scope checks).
2. **Parity harness:** run Node (`npx tsx src/index.ts`, single process) and Rust side by side against `parity/` (a local copy of production loaded with `parity/restore-snapshot.sh backups/<timestamp>`). Replay the same requests to both and diff status codes, relevant headers and JSON bodies after masking volatile fields. For ingest, send the same events to both and diff the ClickHouse rows they write.
3. **Deploy**, move the area's paths in Caddy, and watch both backends' logs.

## Behaviour that must match Node (easy to miss)

From the inventory of `server/src/index.ts`, `cluster.ts`, `lib/cors.ts`, `lib/api-errors.ts`, `lib/logger/*`, `lib/auth-middleware.ts`, `lib/auth-utils.ts`, `lib/bearerAuth.ts`, `lib/scopes.ts`.

- **Error bodies:** for every `/api` response with status ≥ 400 (except `/api/mcp*` and the raw Better Auth routes), the body is rewritten to JSON `{...existing, error, code, message, resolution}` with per-status defaults (400 INVALID_REQUEST, 401 AUTHENTICATION_REQUIRED, 403 FORBIDDEN, 404 NOT_FOUND, 405, 409 CONFLICT, 413 PAYLOAD_TOO_LARGE, 415, 429 RATE_LIMITED, 500 INTERNAL_ERROR), plus `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, JSON content type. Text and HTML 4xx bodies get rewritten too.
- **404:** `/api*` → `{error, code:"API_ROUTE_NOT_FOUND", message:"No API route matches M P.", resolution, details:{method,path}}`; elsewhere `code:"NOT_FOUND"`. Unknown non-API GETs go through static file lookup first.
- **CORS:** methods GET, POST, PUT, DELETE, OPTIONS, PATCH; allowed headers Content-Type, Authorization, X-Requested-With, x-captcha-response, x-private-key, MCP-Protocol-Version, MCP-Session-Id, Last-Event-ID. No `Origin` → no CORS headers. Public paths (`/api/track`, `/api/identify`, `/api/version`, `/.well-known/oauth-*`, `/.well-known/openid-configuration*`, `/api/session-replay/record/*`, `/api/site/tracking-config/*`, exact `/api/sites/:x/sessions`, `/api/sites/:x/embed-stats`, `/api/site/:x/feature-flags/evaluate`) echo any origin, with credentials only for trusted origins; every other path allows trusted origins only, with credentials. Trusted = origin of `BASE_URL` (+ `http://localhost:3002`, `http://127.0.0.1:3002` outside production).
- **Write-origin check:** POST/PUT/PATCH/DELETE carrying an `Origin` on a non-public path whose origin is unparseable or untrusted → 403 `{error:"Origin not allowed"}`.
- **Plain-text successes:** `/api/health` → `OK`; `/api/track` and replay record → 200 text `Site over monthly limit, event not tracked` when over the limit.
- **JSON shaping (`processResults`):** numeric strings from ClickHouse become numbers only when the conversion is exact; `session_id`, `user_id`, `identified_user_id`, `effective_user_id` are never converted; `DateTime` stays `"YYYY-MM-DD HH:MM:SS"`.
- **Guards:** `requireAuth` checks the cookie session before an API key; every other guard checks the API key first. `requireAdmin` answers 401, not 403. API keys need an org or site target (`checkApiKey`), so bearer calls to `/api/user/organizations` are 401. `resolveSiteId` ignores identifiers of 4 characters or fewer. `validateTimeParams` is absent on `publicAnnotationsRead`, the `NoScopedKeys` chains and unguarded routes; `expandSegmentParam` runs only on the public and auth site chains.
- **Rate limiting:** `@fastify/rate-limit` on 3 routes (key `user.id ?? ip`, Redis prefix `fastify-rate-limit-`, 429 "Rate limit exceeded, retry in 1 minute" with `x-ratelimit-*` and `retry-after`). Bearer requests also get `X-RateLimit-Burst-*`, `X-RateLimit-Daily-*` and `RateLimit-*` headers; the daily quota is 0 (unlimited) when not cloud.
- **Per-route headers:** script aliases `public, max-age=3600` (`/api/script.js`) and `86400` (`/api/replay.js`, `/api/metrics.js`); root static files default `max-age=0` with ETag and Last-Modified; embed stats `public, max-age=60` gated on `embedEnabled`; `.well-known` `max-age=3600`; MCP `no-store`; PDF content type and disposition.
- **Every GET also answers HEAD.**
- **Client IP:** `resolveClientIp` (site `firstPartyProxy` → X-Real-IP, XFF, CF; CF-Connecting-IP from a datacenter ASN or the Worker IP `2a06:98c0:3600::103` → X-Real-IP, XFF, CF; otherwise CF, else `getIpAddress`: X-Real-IP → first XFF → CF → socket). Exclusions match every candidate IP.
- **Logging:** request log levels as in `requestLogging.ts` (errors ≥ 500, warnings ≥ 400, ingest and script successes at debug, others info), silent for health and live-user-count; redact credentials, cookies, tokens, emails, bodies, queries, SQL and prompts.
- **Ingest quirks to keep:** hard-coded drop of site 9133 events with an 800×600 screen; `ingest:write` bearer lets the payload override `ip_address`/`user_agent` and skips bot detection.
- **Startup side effects:** promote the oldest user to admin on every boot; migrations stay with drizzle-kit (the Rust service never runs migrations).
- **Known Node bugs to decide on, not copy blindly:** the pageview and bot queues are not flushed on shutdown (Rust should flush).

## Phases

| # | Phase | Contents | Status |
|---|---|---|---|
| 0 | Foundation | Skeleton, config, store connections, JSON logs, health. HTTP layer: error rewriting, 404, CORS, write-origin check, request logging, auto-HEAD, JSON shaping, static and script routes, `/api/config`, `/api/version`. Dockerfile, compose service, Caddy matcher. | live 2026-09-17: `backend-rs` container, Caddy `@rust` matcher; 21/21 parity cases, 8/8 live responses unchanged |
| 1 | Tracking | tracking-config, track, identify, session replay record, flag evaluate; payload validation, client IP, exclusions, usage gate, bot detection (header/UA heuristics, client score, datacenter ASN, anomaly scorer, site baseline, stats), user id (daily salt, identity IP bucket, sticky identity), sessions, pageview/bot/observation queues with GeoIP enrichment, identity backfill queue | not started |
| 2 | Auth | `/api/auth/*` (email+password, email OTP, sessions, organizations, teams, invitations, API keys, admin, MCP OAuth), guards, scopes, private links, public sites, rate limiting | not started |
| 3 | Analytics reads | overview, metric, page titles, time series, lite, retention, journeys, bots, errors, performance, sessions, events, users and traits, funnels, goals, annotations, dashboards and run-card, segments, custom SQL and generate, flags and experiments CRUD/results, replay reads | not started |
| 4 | Sites and orgs | sites, config, exclusions, private links, usage, imports, embed stats, check-install, organizations, members, teams, member access, org exclusions, API keys, API usage, account settings, unsubscribe | not started |
| 5 | The rest | admin, Search Console, PDF (pdf-writer), telemetry, weekly/lifecycle crons, MCP server and `.well-known` (no Stripe or AppSumo) | not started |
| 6 | Remove Node | Caddy default to Rust, drop the `backend` service and image | not started |

## Route inventory

Status: `node` (served by Node), `rust` (Caddy sends it to Rust). `…` = `/api/sites/:siteId`.

### Tracking and ingest

| Method | Path | Guard | Node handler | Status |
|---|---|---|---|---|
| POST | /api/track | none | services/tracker/trackEvent.ts | node |
| POST | /api/identify | none | services/tracker/identifyService.ts | node |
| POST | /api/session-replay/record/:siteId | none | api/sessionReplay/recordSessionReplay.ts | node |
| GET | /api/site/tracking-config/:siteId | none | api/sites/getTrackingConfig.ts | rust |
| POST | /api/site/:siteId/feature-flags/evaluate | none | api/featureFlags/index.ts | node |

### Static, scripts, misc

| Method | Path | Guard | Node handler | Status |
|---|---|---|---|---|
| GET | /api/health | none | index.ts (text `OK`) | node |
| GET | /api/config | none | api/getConfig.ts | rust |
| GET | /api/version | none | api/getConfig.ts | rust |
| GET | /api/script.js, /api/replay.js, /api/metrics.js | none | index.ts sendFile | rust |
| GET/HEAD | /* (public/: script.js, script-full.js, rrweb.min.js, web-vitals.iife.js) | none | @fastify/static | node |
| GET | /api/site/check-install | HMAC + 5/min per IP | api/sites/checkInstall.ts | node |
| GET | /api/user/unsubscribe-marketing-oneclick | HMAC | api/user/unsubscribeMarketing.ts | node |
| POST | /api/user/unsubscribe-marketing-oneclick | none | api/user/unsubscribeMarketing.ts | node |
| POST | /api/admin/telemetry | 403 unless CLOUD | api/admin/collectTelemetry.ts | node |

### Auth

| Method | Path | Guard | Node handler | Status |
|---|---|---|---|---|
| ALL | /api/auth/* | Better Auth | lib/auth.ts | node |
| ALL | /auth/* | Better Auth | lib/auth.ts | node |

### Analytics reads (`api/analytics/`, guard publicAnalyticsRead unless noted)

| Method | Path | Guard | Node handler | Status |
|---|---|---|---|---|
| GET | …/live-user-count | publicAnalyticsRead (silent) | getLiveUsercount.ts | node |
| GET | …/overview | | getOverview.ts | node |
| GET | …/overview/time-series | | getOverviewBucketed.ts | node |
| GET | …/overview-lite | | lite/getOverviewLite.ts | node |
| GET | …/overview-bucketed-lite | | lite/getOverviewBucketedLite.ts | node |
| GET | …/metric-lite | | lite/getMetricLite.ts | node |
| GET | …/metric | | getMetric.ts | node |
| GET | …/page-titles | | getPageTitles.ts | node |
| GET | …/retention | | getRetention.ts | node |
| GET | …/journeys | | getJourneys.ts | node |
| GET | …/bots/overview | | bots/getBotOverview.ts | node |
| GET | …/bots/time-series | | bots/getBotTimeSeries.ts | node |
| GET | …/bots/by-dimension | | bots/getBotDimension.ts | node |
| GET | …/bots/ai-summary | | bots/getBotAiSummary.ts | node |
| GET | …/export/pdf | authAnalyticsRead | generatePdfReport.ts | node |
| GET | /api/org-event-count/:organizationId | orgAnalyticsRead | getOrgEventCount.ts | node |
| GET | …/errors/names | | getErrorNames.ts | node |
| GET | …/errors/events | | getErrorEvents.ts | node |
| GET | …/errors/time-series | | getErrorBucketed.ts | node |
| GET | …/performance/overview | | performance/getPerformanceOverview.ts | node |
| GET | …/performance/time-series | | performance/getPerformanceTimeSeries.ts | node |
| GET | …/performance/by-dimension | | performance/getPerformanceByDimension.ts | node |

### Sessions and events (`api/analytics/`)

| Method | Path | Guard | Node handler | Status |
|---|---|---|---|---|
| GET | …/sessions | publicSessionsRead | sessions/getSessions.ts | node |
| GET | …/sessions/:sessionId | publicSessionsRead | sessions/getSession.ts | node |
| GET | …/sessions/locations | publicSessionsRead | sessions/getSessionLocations.ts | node |
| GET | …/events | publicEventsRead | events/getEvents.ts | node |
| GET | …/events/time-series | publicEventsRead | events/getEventBucketed.ts | node |
| GET | …/events/count | publicEventsRead | events/getSiteEventCount.ts | node |
| GET | …/events/names | publicEventsRead | events/getEventNames.ts | node |
| GET | …/events/properties | publicEventsRead | events/getEventProperties.ts | node |
| GET | …/events/autocapture | publicEventsRead | events/getAutocaptureEvents.ts | node |
| GET | …/events/autocapture-values | publicEventsRead | events/getAutocaptureValues.ts | node |
| GET | …/events/outbound | publicEventsRead | events/getOutboundLinks.ts | node |

### Users (`api/analytics/users/`)

| Method | Path | Guard | Node handler | Status |
|---|---|---|---|---|
| GET | …/users | publicUsersRead | getUsers.ts | node |
| GET | …/users/session-count | publicUsersRead | getUserSessionCount.ts | node |
| GET | …/users/:userId | publicUsersRead | getUserInfo.ts | node |
| POST | …/users/identify | authUsersWrite | identifyUser.ts | node |
| PUT | …/users/:userId/traits | authUsersWrite | updateUserTraits.ts | node |
| DELETE | …/users/:userId | adminUsersWrite | deleteUser.ts | node |
| GET | …/user-traits/keys | publicUsersRead | getUserTraits.ts | node |
| GET | …/user-traits/values | publicUsersRead | getUserTraits.ts | node |
| GET | …/user-traits/users | publicUsersRead | getUserTraits.ts | node |

### Funnels, goals, annotations (`api/analytics/`)

| Method | Path | Guard | Node handler | Status |
|---|---|---|---|---|
| GET | …/funnels | publicFunnelsRead | funnels/getFunnels.ts | node |
| POST | …/funnels/analyze | publicFunnelsRead | funnels/getFunnel.ts | node |
| POST | …/funnels/:stepNumber/sessions | publicFunnelsRead | funnels/getFunnelStepSessions.ts | node |
| POST | …/funnels | authFunnelsWrite | funnels/createFunnel.ts | node |
| DELETE | …/funnels/:funnelId | authFunnelsWrite | funnels/deleteFunnel.ts | node |
| GET | …/goals | publicGoalsRead | goals/getGoals.ts | node |
| GET | …/goals/time-series | publicGoalsRead | goals/getGoalTimeSeries.ts | node |
| GET | …/goals/:goalId/sessions | publicGoalsRead | goals/getGoalSessions.ts | node |
| POST | …/goals | authGoalsWrite | goals/createGoal.ts | node |
| DELETE | …/goals/:goalId | authGoalsWrite | goals/deleteGoal.ts | node |
| PUT | …/goals/:goalId | authGoalsWrite | goals/updateGoal.ts | node |
| GET | …/annotations | publicAnnotationsRead | annotations/getAnnotations.ts | node |
| POST | …/annotations | authAnnotationsWrite | annotations/createAnnotation.ts | node |
| PUT | …/annotations/:annotationId | authAnnotationsWrite | annotations/updateAnnotation.ts | node |
| DELETE | …/annotations/:annotationId | authAnnotationsWrite | annotations/deleteAnnotation.ts | node |

### Dashboards, segments, custom SQL (`api/analytics/`)

| Method | Path | Guard | Node handler | Status |
|---|---|---|---|---|
| GET | …/dashboards | authDashboardsRead | dashboards/getDashboards.ts | node |
| GET | …/dashboards/:dashboardId | authDashboardsRead | dashboards/getDashboard.ts | node |
| POST | …/dashboards | authDashboardsWrite | dashboards/createDashboard.ts | node |
| PUT | …/dashboards/:dashboardId | authDashboardsWrite | dashboards/updateDashboard.ts | node |
| DELETE | …/dashboards/:dashboardId | authDashboardsWrite | dashboards/deleteDashboard.ts | node |
| POST | …/dashboards/run-card | authDashboardsRead + 60/min | runDashboardCardQuery.ts | node |
| GET | …/segments | publicSegmentsRead | segments/getSegments.ts | node |
| GET | …/segments/:segmentId | publicSegmentsRead | segments/getSegment.ts | node |
| POST | …/segments | authSegmentsWrite | segments/createSegment.ts | node |
| PUT | …/segments/:segmentId | authSegmentsWrite | segments/updateSegment.ts | node |
| DELETE | …/segments/:segmentId | authSegmentsWrite | segments/deleteSegment.ts | node |
| POST | /api/organizations/:organizationId/analytics/query | orgSqlRead + 60/min | runCustomQuery.ts | node |
| POST | /api/organizations/:organizationId/analytics/query/generate | orgSqlRead + 20/min | generateCustomQuery.ts | node |

### Feature flags and experiments

| Method | Path | Guard | Node handler | Status |
|---|---|---|---|---|
| GET | …/feature-flags | authFlagsRead | api/featureFlags/index.ts | node |
| POST | …/feature-flags | adminFlagsWrite | api/featureFlags/index.ts | node |
| PUT | …/feature-flags/:flagId | adminFlagsWrite | api/featureFlags/index.ts | node |
| DELETE | …/feature-flags/:flagId | adminFlagsWrite | api/featureFlags/index.ts | node |
| POST | …/feature-flags/evaluate | authFlagsRead | api/featureFlags/index.ts | node |
| GET | …/experiments | authExperimentsRead | api/experiments/getExperiments.ts | node |
| POST | …/experiments | adminExperimentsWrite | api/experiments/createExperiment.ts | node |
| PUT | …/experiments/:experimentId | adminExperimentsWrite | api/experiments/updateExperiment.ts | node |
| DELETE | …/experiments/:experimentId | adminExperimentsWrite | api/experiments/deleteExperiment.ts | node |
| GET | …/experiments/:experimentId/results | authExperimentsRead | api/experiments/getExperimentResults.ts | node |

### Session replay reads (`api/sessionReplay/`)

| Method | Path | Guard | Node handler | Status |
|---|---|---|---|---|
| GET | …/session-replay/list | publicReplayRead | getSessionReplays.ts | node |
| GET | …/session-replay/:sessionId | publicReplayRead | getSessionReplayEvents.ts | node |
| DELETE | …/session-replay/:sessionId | authReplayWrite | deleteSessionReplay.ts | node |

### Sites (`api/sites/`)

| Method | Path | Guard | Node handler | Status |
|---|---|---|---|---|
| GET | /api/sites/:siteId | publicSitesRead | getSite.ts | node |
| PUT | …/config | adminSitesWrite | updateSiteConfig.ts | node |
| PUT | …/move | adminSitesWrite | moveSite.ts | node |
| DELETE | /api/sites/:siteId | adminSitesWrite | deleteSite.ts | node |
| GET | …/private-link-config | adminSitesWrite | getSitePrivateLinkConfig.ts | node |
| POST | …/private-link-config | adminSitesWrite | updateSitePrivateLinkConfig.ts | node |
| GET | …/has-data | publicSitesRead | getSiteHasData.ts | node |
| GET | …/is-public | publicSitesRead | getSiteIsPublic.ts | node |
| GET | …/excluded-ips | authSitesRead | getSiteExclusions.ts | node |
| GET | …/excluded-countries | authSitesRead | getSiteExclusions.ts | node |
| GET | …/excluded-paths | authSitesRead | getSiteExclusions.ts | node |
| GET | …/excluded-hostnames | authSitesRead | getSiteExclusions.ts | node |
| GET | …/excluded-user-agents | authSitesRead | getSiteExclusions.ts | node |
| GET | …/excluded-asns | authSitesRead | getSiteExclusions.ts | node |
| GET | …/excluded-query-params | authSitesRead | getSiteExclusions.ts | node |
| GET | …/organization-excluded-ips | authSitesRead | api/organizationExclusions/organizationExcludedIPs.ts | node |
| GET | …/usage | authSitesRead | getSiteUsage.ts | node |
| GET | …/embed-stats | resolveSiteId only | getEmbedStats.ts | node |
| GET | …/imports | adminSitesRead | getSiteImports.ts | node |
| POST | …/imports | adminSitesWrite | createSiteImport.ts | node |
| POST | …/imports/:importId/events | adminSitesWrite, 50 MB body | batchImportEvents.ts | node |
| DELETE | …/imports/:importId | adminSitesWrite | deleteSiteImport.ts | node |

### Organizations, teams, account, API keys

| Method | Path | Guard | Node handler | Status |
|---|---|---|---|---|
| GET | /api/organizations | none (resolves user itself) | api/user/getMyOrganizations.ts | node |
| GET | /api/organizations/:organizationId/sites | orgOrgRead | api/sites/getSitesFromOrg.ts | node |
| POST | /api/organizations/:organizationId/sites | orgAdminSitesWrite | api/sites/addSite.ts | node |
| GET | /api/organizations/:organizationId/members | orgOrgRead | api/user/listOrganizationMembers.ts | node |
| POST | /api/organizations/:organizationId/members | authOrgWrite | api/user/addUserToOrganization.ts | node |
| POST | /api/organizations/:organizationId/users | authOrgWrite | api/user/createUserInOrganization.ts | node |
| PUT | /api/organizations/:organizationId/members/:memberId/sites | orgAdminOrgWrite | api/memberAccess/updateMemberSiteAccess.ts | node |
| GET | /api/organizations/:organizationId/excluded-ips | orgOrgRead | api/organizationExclusions/organizationExcludedIPs.ts | node |
| PUT | /api/organizations/:organizationId/excluded-ips | orgAdminOrgWrite | api/organizationExclusions/organizationExcludedIPs.ts | node |
| GET | /api/organizations/:organizationId/teams | orgOrgRead | api/teams/listTeams.ts | node |
| POST | /api/organizations/:organizationId/teams | orgAdminOrgWrite | api/teams/createTeam.ts | node |
| PUT | /api/organizations/:organizationId/teams/:teamId | orgAdminOrgWrite | api/teams/updateTeam.ts | node |
| DELETE | /api/organizations/:organizationId/teams/:teamId | orgAdminOrgWrite | api/teams/deleteTeam.ts | node |
| GET | /api/user/organizations | authOrgRead | api/user/getUserOrganizations.ts | node |
| POST | /api/user/account-settings | authOnlyNoScopedKeys | api/user/updateAccountSettings.ts | node |
| POST | /api/user/unsubscribe-marketing | authOnlyNoScopedKeys | api/user/unsubscribeMarketing.ts | node |
| POST | /api/user/api-keys | authOnlyNoScopedKeys | api/user/createApiKey.ts | node |
| POST | /api/organizations/:organizationId/api-keys | orgAdminNoScopedKeys | api/user/createOrgApiKey.ts | node |
| GET | /api/organizations/:organizationId/api-usage | orgOrgRead | api/user/getOrgApiUsage.ts | node |

### Search Console (`api/gsc/`)

| Method | Path | Guard | Node handler | Status |
|---|---|---|---|---|
| GET | …/gsc/connect | adminGscWrite | connect.ts | node |
| GET | /api/gsc/callback | signed state | callback.ts | node |
| GET | …/gsc/status | publicGscRead | status.ts | node |
| DELETE | …/gsc/disconnect | adminGscWrite | disconnect.ts | node |
| POST | …/gsc/select-property | adminGscWrite | selectProperty.ts | node |
| GET | …/gsc/data | publicGscRead | getData.ts | node |

### Admin (`api/admin/`, guard adminOnly)

| Method | Path | Node handler | Status |
|---|---|---|---|
| GET | /api/admin/clickhouse-stats | getClickhouseStats.ts | node |
| GET | /api/admin/clickhouse-query-log | getClickhouseQueryLog.ts | node |
| GET | /api/admin/sites | getAdminSites.ts | node |
| PUT | /api/admin/sites/:siteId/move | adminMoveSite.ts | node |
| GET | /api/admin/organizations | getAdminOrganizations.ts | node |
| GET | /api/admin/organization-options | adminOrganizationManagement.ts | node |
| GET | /api/admin/subscription-plans | adminOrganizationManagement.ts | node |
| PUT | /api/admin/organizations/:organizationId/subscription-override | adminOrganizationManagement.ts | node |
| GET | /api/admin/organizations/:organizationId/members/:memberId | adminOrganizationManagement.ts | node |
| PATCH | /api/admin/organizations/:organizationId/members/:memberId | adminOrganizationManagement.ts | node |
| DELETE | /api/admin/organizations/:organizationId/members/:memberId | adminOrganizationManagement.ts | node |
| GET | /api/admin/service-event-count | getAdminServiceEventCount.ts | node |

### Stripe and AppSumo (registered only when `CLOUD=true`; not ported, see Decisions)

| Method | Path | Guard | Node handler | Status |
|---|---|---|---|---|
| POST | /api/stripe/create-checkout-session | authOnlyNoScopedKeys | api/stripe/createCheckoutSession.ts | dropped |
| POST | /api/stripe/create-portal-session | authOnlyNoScopedKeys | api/stripe/createPortalSession.ts | dropped |
| POST | /api/stripe/preview-subscription-update | authOnlyNoScopedKeys | api/stripe/previewSubscriptionUpdate.ts | dropped |
| POST | /api/stripe/update-subscription | authOnlyNoScopedKeys | api/stripe/updateSubscription.ts | dropped |
| GET | /api/stripe/subscription | authOnlyNoScopedKeys | api/stripe/getSubscription.ts | dropped |
| GET | /api/stripe/invoices | authOnlyNoScopedKeys | api/stripe/getInvoices.ts | dropped |
| POST | /api/stripe/cancellation-feedback | authOnlyNoScopedKeys | api/stripe/submitCancellationFeedback.ts | dropped |
| POST | /api/stripe/webhook | raw body | api/stripe/webhook.ts | dropped |
| POST | /api/as/activate | authOnlyNoScopedKeys | api/as/activate.ts | dropped |
| POST | /api/as/webhook | none | api/as/webhook.ts | dropped |

### MCP and OAuth discovery

| Method | Path | Guard | Node handler | Status |
|---|---|---|---|---|
| POST | /api/mcp | own bearer auth, 1 MB body | mcp/index.ts | node |
| GET, DELETE | /api/mcp | none (405) | mcp/index.ts | node |
| GET | /.well-known/oauth-authorization-server, …/oauth-authorization-server/api/mcp | none | mcp/wellKnown.ts | node |
| GET | /.well-known/openid-configuration, …/openid-configuration/api/mcp | none | mcp/wellKnown.ts | node |
| GET | /.well-known/oauth-protected-resource, …/oauth-protected-resource/api/mcp | none | mcp/wellKnown.ts | node |

## Background work

| Job | Node location | Schedule | Moves in phase |
|---|---|---|---|
| pageview queue (GeoIP enrich, insert `events`) | services/tracker/pageviewQueue.ts | every 1 s, batch 5000 | 1 (per backend, each flushes its own requests) |
| bot event and observation queues | services/tracker/botBlocking/botEventQueue.ts | every 1 s, batch 5000 | 1 (per backend) |
| identity backfill queue | services/tracker/identityBackfillQueue.ts | 5 min or 5000 identities, drained at shutdown | 1 (per backend) |
| site baseline refresh | services/tracker/botBlocking/siteBaseline.ts | refresh 15 min (Redis lock), mirror 5 min | 1 (lock-coordinated, safe in both) |
| bot detection stats | services/tracker/botBlocking/botDetectionStats.ts | every 60 s | 1 (per backend) |
| telemetry | services/telemetryService.ts | boot + daily, unless CLOUD or DISABLE_TELEMETRY | 5 |
| usage (Stripe + CH counts, over-limit sets) | services/usageService.ts | every 30 min, CLOUD only | dropped (no billing) |
| weekly reports | services/weekyReports/weeklyReportService.ts | Mondays, CLOUD only | 5 |
| lifecycle emails | services/lifecycleEmails/lifecycleEmailService.ts | every 10 min, CLOUD only | 5 |
