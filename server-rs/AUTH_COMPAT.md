# Better Auth compatibility

The Rust service replaces Better Auth 1.6.25 (`server/src/lib/auth.ts`) for the subset this app uses. Existing rows in Postgres must keep working unchanged: nobody is logged out, no password changes, API keys and MCP tokens stay valid. Everything below was read from the installed sources in `server/node_modules` (better-auth 1.6.25, @better-auth/api-key 1.6.25, @better-auth/utils 0.4.2, better-call 1.3.7). `NM` = `server/node_modules`.

## Configuration in use

- `basePath` `/api/auth`; base URL `${BASE_URL}/api/auth`. The Fastify `/auth/*` mount never matches Better Auth's router, so it is not ported.
- Secret: `BETTER_AUTH_SECRET` used as a raw UTF-8 string (not hex-decoded). No `BETTER_AUTH_SECRETS` rotation.
- Database: Kysely/postgres with default table names and camelCase columns, separate `SELECT *` queries (no joins), arrays `JSON.stringify`'d, timestamps without time zone holding naive UTC.
- Email and password: enabled, `requireEmailVerification: false`, `disableSignUp = (DISABLE_SIGNUP === "true")`, password length 8 to 128, `autoSignIn` true. No `sendResetPassword`: resets only go through email OTP.
- Email verification: sending uses `sendEmailVerificationLink`; nothing is sent on sign-up. Token lifetime 3600 s.
- Social: google and github from `GOOGLE_*` / `GITHUB_*`, redirect `${BASE_URL}/api/auth/callback/{id}`, scopes github `read:user user:email`, google `email profile openid`, tokens stored in plaintext, default account linking (`requireLocalEmailVerified`). Production has no client ids, so both are effectively off.
- User: `deleteUser` enabled (after delete, remove `apikey` rows whose `referenceId` is the user); `changeEmail` enabled with a confirmation mail; extra field `sendAutoEmailReports` (boolean, required, default true, settable).
- Sessions: defaults (`expiresIn` 604800 s, `updateAge` 86400 s, `freshAge` 86400 s), no cookie cache, no deferred refresh.
- Cookies: `useSecureCookies` when `NODE_ENV=production`; `sameSite` `none` in production and `lax` otherwise; `path` `/`; prefix `better-auth`; no domain, no cross-subdomain cookies.
- Trusted origins: the `BASE_URL` origin (+ `http://localhost:3002`, `http://127.0.0.1:3002` outside production). CSRF and origin checks on.
- Rate limiting (only when `NODE_ENV=production`, in memory per process): 100 per 10 s per `${ip}|${path}`; 3 per 10 s for `/sign-in*`, `/sign-up*`, `/change-password*`, `/change-email*`; 3 per 60 s for `/request-password-reset`, `/send-verification-email`, `/forget-password*` and every `/email-otp/*` endpoint. Rejection: 429 `{"message":"Too many requests. Please try again later."}` with `X-Retry-After`.
- Captcha (Turnstile) only when `CLOUD=true`, `TURNSTILE_SECRET_KEY` set and production; guards `/sign-up/email`, `/sign-in/email`, `/request-password-reset` via the `x-captcha-response` header (400 missing, 403 failed).
- `dash()` (@better-auth/infra telemetry) is not ported.

## Tables Better Auth reads and writes (`server/src/db/postgres/schema.ts`)

| Model | Columns |
|---|---|
| `user` | id, name, email, emailVerified, image, createdAt, updatedAt, role, banned, banReason, banExpires, sendAutoEmailReports |
| `session` | id, expiresAt, token (unique), createdAt, updatedAt, ipAddress, userAgent, userId, impersonatedBy, activeOrganizationId, activeTeamId |
| `account` | id, accountId, providerId, userId, accessToken, refreshToken, idToken, accessTokenExpiresAt, refreshTokenExpiresAt, scope, password, createdAt, updatedAt |
| `verification` | id, identifier, value, expiresAt, createdAt, updatedAt |
| `organization` | id, name, slug, logo, createdAt, metadata (text), stripeCustomerId, monthlyEventCount, overMonthlyLimit, planOverride, customPlan (see quirks) |
| `member` | id, organizationId, userId, role, createdAt |
| `invitation` | id, email, inviterId, organizationId, role, status, createdAt, expiresAt, teamId, `has_restricted_site_access`, `site_ids` (number[] JSON in jsonb) |
| `team` / `teamMember` | id, name, organizationId, createdAt, updatedAt / id, teamId, userId, createdAt |
| `apikey` | id, configId, name, start, prefix, key, referenceId, refillInterval, refillAmount, lastRefillAt, enabled, rateLimitEnabled, rateLimitTimeWindow, rateLimitMax, requestCount, remaining, lastRequest, expiresAt, createdAt, updatedAt, permissions (text), metadata (jsonb) |
| `oauthApplication` / `oauthAccessToken` / `oauthConsent` | as in `NM/better-auth/dist/plugins/oidc-provider/schema.mjs:59-163` |

## Random strings (`NM/@better-auth/utils/dist/random.mjs`)

Read `2*len` random bytes, keep byte `b` only if `b < floor(256/n)*n`, emit `charset[b % n]`; charset is the alphabets concatenated in the order given.

- Primary keys: 32 chars of `a-z A-Z 0-9`.
- Session token: 32 chars of `a-z A-Z 0-9`.
- API key body: 64 chars of `a-z A-Z`.
- Email OTP: 6 chars of `0-9`.
- MCP authorization code: 32 of `a-z A-Z 0-9`; access token, refresh token, client_id, client_secret: 32 of `a-z A-Z`.

## Passwords (`NM/@better-auth/utils/dist/password.node.mjs`)

- `saltHex = hex(randomBytes(16))` (32 lowercase hex chars).
- `key = scrypt(password.normalize("NFKC"), saltHex, dkLen 64, N 16384, r 16, p 1, maxmem 64 MiB)`. **The salt passed to scrypt is the UTF-8 bytes of the 32-char hex string**, not the 16 raw bytes.
- `account.password = saltHex + ":" + hex(key)` (161 chars). Verify by splitting on `:`, recomputing, comparing hex strings.
- Credential account: `providerId "credential"`, `accountId = userId`.
- Sign-in always hashes even when the user, account or password is missing, then 401 `{"message":"Invalid email or password","code":"INVALID_EMAIL_OR_PASSWORD"}`.

## Sessions and cookies

- **Create:** token `generateId(32)` stored as-is (not hashed); `expiresAt = now + 604800 s` (86400 s when `rememberMe === false`); `ipAddress` = the `x-forwarded-for` value only if it is exactly one valid IP (IPv6 reduced to its /64), else `""` in production; `userAgent` header or `""`.
- **Banned users** at session creation: if `banExpires` passed, unban (banned false, reason/expires null); else 403 `{"code":"BANNED_USER","message":"You have been banned from this application. Please contact support if you believe this is an error."}`.
- **Cookie name:** `__Secure-better-auth.session_token` in production, `better-auth.session_token` otherwise.
- **Signing (better-call):** `sig = base64std(HMAC-SHA256(key = UTF8(secret), msg = UTF8(token)))` (44 chars, one `=`). Cookie value `encodeURIComponent(token + "." + sig)`.
- **Set-Cookie layout:** `name=value; Max-Age=604800; Path=/; HttpOnly; Secure; SameSite=None` (dev: no `Secure`, `SameSite=Lax`).
- **Reading:** split the Cookie header on `;`, trim, first occurrence of a name wins, strip surrounding `"`, `decodeURIComponent` when it contains `%`; exact name match; split at the last `.` (index ≥ 1); signature must be 44 chars ending in `=`; verify HMAC. Any failure means no session.
- **`GET /get-session`** (POST is 405): headers `cache-control: no-store`, `pragma: no-cache`. No valid cookie → 200 `null`. Expired → delete the row, expire `session_token`, `session_data`, `dont_remember` (Max-Age=0, same attributes), return `null`. `dont_remember` cookie or `?disableRefresh` → no refresh. Refresh when `expiresAt - 604800000 + 86400000 <= now`: `UPDATE session SET expiresAt = now+7d, updatedAt = now WHERE token = …` and reissue the cookie. Body `{"session":{id,expiresAt,token,createdAt,updatedAt,ipAddress,userAgent,userId,impersonatedBy,activeOrganizationId,activeTeamId},"user":{id,name,email,emailVerified,image,createdAt,updatedAt,sendAutoEmailReports,role,banned,banReason,banExpires}}`, dates as ISO strings with milliseconds and `Z`.
- **`POST /sign-out`:** delete the row by token, expire the cookies, `{"success":true}`.
- **Other signed cookies (same prefix rule):** `better-auth.dont_remember` = `"true"` without Max-Age; `better-auth.admin_session` = `"${adminToken}:${dontRememberValue||""}"`; `better-auth.state` (OAuth, Max-Age 300). `oidc_login_prompt` has **no prefix**, value = JSON of the authorize query, Max-Age 600, `Path=/`, `SameSite=Lax`, not HttpOnly or Secure.
- The session cookie is (re)issued on sign-in, sign-up, update-user, organization set-active, email verification and impersonation.
- Server-side guard lookups (`auth.api.getSession`) perform the same refresh write but never reissue the browser cookie.

## Email verification and change of email

- Token: JWT HS256 (jose), key UTF-8 secret, payload `{email (lowercased), updateTo?, requestType?, iat, exp: now+3600}`.
- URL: `${BASE_URL}/api/auth/verify-email?token=<jwt>&callbackURL=<encodeURIComponent(cb || "/")>`.
- `change-email`: verified user → `requestType "change-email-confirmation"` mailed to the current address; clicking it mails a `"change-email-verification"` token to the new address; clicking that sets `email = new, emailVerified = true` and reissues the cookie (creating a session if none). Unverified user → the verification token goes straight to the new address. New email already taken → `{status:true}`, nothing sent.

## API keys (`NM/@better-auth/api-key/dist/index.mjs`)

- Configs: `default` (user keys, no prefix, rate limit off) and `org` (`references: organization`, prefix `rb_org_`, metadata enabled, rate limit off). Key length 64, name 1-32, prefix 1-32, `start` = first 6 chars, expiry 1-365 days given in seconds.
- Key = `prefix + random(64, a-z A-Z)`. Stored `apikey.key = base64url_nopad(SHA-256(UTF8(fullKey)))` (43 chars).
- Row on create: configId, name, prefix (`rb_org_` or null), start (`rb_org` for org keys), referenceId (user id or org id), enabled true, expiresAt or null, rateLimitEnabled **false**, rateLimitMax 10, rateLimitTimeWindow 86400000, requestCount 0, remaining/refill*/lastRefillAt/lastRequest null, permissions `JSON.stringify(Record<string,string[]>)` or SQL NULL, metadata jsonb (user keys: JSON `null`; org keys `{"createdBy":"<userId>"}`). Response: row + plain `key`, parsed metadata and permissions.
- Creation goes through Fastify `POST /api/user/api-keys` (`{name, expiresIn, userId, permissions?}`) and `POST /api/organizations/:id/api-keys` (`{name, expiresIn, configId:"org", organizationId, userId, metadata:{createdBy}, permissions?}`), both inside `createApiKeyWithinLimit` (advisory lock on `hashtextextended(referenceId,0)`, count of enabled unexpired keys).
- `verifyApiKey`: `SELECT … WHERE key = hash` (configId null treated as `default`). Not found → `INVALID_API_KEY` "Invalid API key.". Checks in order: `enabled === false` → `KEY_DISABLED`; `expiresAt < now` → delete row, `KEY_EXPIRED`; `remaining === 0 && refillAmount === null` → delete row, `USAGE_EXCEEDED`. Then `UPDATE lastRequest = now`, then `UPDATE updatedAt = now`. Valid → `{valid:true, error:null, key:{row minus key, permissions parsed|null, metadata}}`.
- Hygo reads keys from `Authorization: Bearer <key>`, then `?api_key=`. The plugin's own `x-api-key` path is unused.
- `GET /api-key/list[?organizationId=]`: with an org, caller needs `apiKey:read` there (owners always pass); returns keys whose config `references` matches and whose `referenceId` matches. Body `{apiKeys:[row minus key, permissions and metadata parsed], total, limit, offset}`.
- `POST /api-key/delete {keyId, configId?}`: banned users 401; the key's config must match (default when omitted); org keys need `apiKey:delete`; user keys must belong to the caller else `NOT_FOUND`. `{success:true}`.
- Expired-key sweep at most every 10 s per process on create, list and delete.

## Email OTP (`NM/better-auth/dist/plugins/email-otp/`)

- Stored in `verification`: `identifier = "${type}-otp-${emailLower}"`, `value = "${otp}:${attempts}"` (starts `:0`), `expiresAt = now + 300 s`. 6 digits, 3 attempts, plain text, no resend reuse.
- `POST /email-otp/send-verification-otp {email, type}`: always creates a row (on insert error delete by identifier and retry); unknown email → delete the row and still `{success:true}`; `type: "sign-in"` for an unknown email sends nothing when sign-ups are disabled; `change-email` type rejected.
- `POST /email-otp/reset-password {email, otp, password}`: expired row → delete, 400 `OTP_EXPIRED`; take the newest row, delete all rows for the identifier, split value at the last `:`; attempts ≥ 3 → 403 `TOO_MANY_ATTEMPTS`; mismatch (constant-time) → re-insert with attempts+1 and the same expiry, 400 `INVALID_OTP`; success → validate length, hash, update or create the credential account, set `emailVerified` true, keep sessions, `{success:true}`.
- `POST /sign-in/email-otp`: with sign-ups disabled, an unknown email → 400 `INVALID_OTP`.
- Reading verification values also deletes every expired `verification` row.

## Organizations, members, teams, invitations

- Active organization/team: `session.activeOrganizationId` / `activeTeamId` via `UPDATE session … WHERE token`.
- Create (`{name, slug}`): slug unique; creates the owner member, a default team named after the org and its teamMember row; sets both active ids on the session; returns `{...org, metadata parsed, members:[member]}`. `allowUserToCreateOrganization` true.
- Delete: members, invitations, then the org (teams by FK cascade); other sessions keep a stale active id. Hook: purge org API keys first.
- Invitations: statuses `pending | accepted | rejected | canceled`; `expiresAt = now + 172800 s`; `teamId` holds comma-joined team ids; accepting needs no email verification. Limits 100 invitations, 100 members. Email link `${BASE_URL}/invitation?invitationId=${id}&organization=${org.name}&inviterEmail=${email}` (not URL-encoded). Hooks: `beforeCreateInvitation` validates site restrictions; after `accept-invitation`, copy `has_restricted_site_access`/`site_ids` onto the member and insert `member_site_access` rows; after `leave`, delete invitations and clear the access cache; `afterRemoveMember`.
- Roles (`role` may be comma-separated; any listed role granting every action passes):

| Resource | owner | admin | member |
|---|---|---|---|
| organization | update, delete | update | none |
| member | create, update, delete | create, update, delete | none |
| invitation | create, cancel | create, cancel | none |
| team | create, update, delete | create, update, delete | none |
| ac | create, read, update, delete | create, read, update, delete | read |
| apiKey | create, read, update, delete | create, read, update, delete | none |

## Admin plugin

- Role `admin` (from `user.role`, comma-split): `user[create,list,set-role,ban,impersonate,delete,set-password,set-email,get,update]`, `session[list,revoke,delete]`; not `impersonate-admins`. Role `user`: nothing.
- Impersonate: admins can't be impersonated (403); create a session `{impersonatedBy: adminId, expiresAt: now+3600 s}` with don't-remember; expire current cookies; set `admin_session`; set the new session cookie without Max-Age plus `dont_remember`.
- Stop impersonating: requires `session.impersonatedBy`; read `admin_session`, which must name an existing session of that admin; delete the impersonation session, restore the admin cookie, expire `admin_session`.
- Ban: banned true, `banReason` (default "No reason"), `banExpires = now + banExpiresIn s` (untouched if omitted); delete all the user's sessions.
- Hooks: `user.create.after` makes the only user an admin, then sends the welcome email and adds a Resend contact. `user.update.before` tries to strip `role` but has no effect.

## MCP OAuth (`NM/better-auth/dist/plugins/mcp/`)

- Endpoints under `/api/auth`: `GET /.well-known/oauth-authorization-server`, `GET /.well-known/oauth-protected-resource`, `GET /mcp/authorize`, `POST /mcp/token` (JSON or form), `POST /mcp/register`, `GET /mcp/get-session`, `POST /oauth2/consent`. `jwks_uri` and `userinfo` are advertised without handlers.
- Metadata: issuer = `BASE_URL` origin, endpoints `${BASE_URL}/api/auth/mcp/...`, S256 only, auth methods `client_secret_basic`, `client_secret_post`, `none`; `server/src/mcp/wellKnown.ts` replaces `scopes_supported` with OIDC scopes + `ALL_SCOPE_STRINGS`. Resource `${BASE_URL}/api/mcp`, login page `/login`.
- Authorize: not logged in → set `oidc_login_prompt`, redirect to `/login?<same query>`; any later response that sets `session_token` while that cookie exists resumes authorization. `redirect_uri` must equal one of the comma-separated `redirectUrls`; scopes within `openid profile email offline_access` + custom. Code stored as a verification row `identifier = code`, `value = JSON{clientId, redirectURI, scope:[..], userId, authTime, requireConsent, state, codeChallenge, codeChallengeMethod:"s256", nonce}`, 600 s; redirect `redirect_uri?code=&state=`.
- Token (`authorization_code`): consume the code, match `client_id` and `redirect_uri`; PKCE `base64url_nopad(SHA-256(verifier)) == codeChallenge` (required for public clients), confidential clients checked with constant-time secret compare (Basic or body). Insert `oauthAccessToken{accessToken, refreshToken, accessTokenExpiresAt +3600 s, refreshTokenExpiresAt +604800 s, clientId, userId, scopes space-joined}`. Response `{access_token, token_type:"Bearer", expires_in:3600, refresh_token (offline_access only), scope, id_token (openid only)}`.
- Token (`refresh_token`): needs `offline_access`; inserts a new row without revoking the old one; `token_type` `"bearer"`.
- Register: `client_id`/`client_secret` 32 letters (public clients `""`), `redirectUrls` comma-joined, `type` `web` or `public`, metadata JSON text; 201 with RFC 7591 JSON.
- `getMcpSession`: strip `Bearer `, find `oauthAccessToken` by `accessToken`, null if missing or expired.

## Endpoints the client calls (`client/src`, base `${NEXT_PUBLIC_BACKEND_URL}/api/auth`, credentials included)

| Endpoint | Body / query | Fields the UI uses |
|---|---|---|
| GET /get-session | – | user.id, email, name, role, emailVerified; session.impersonatedBy |
| GET /organization/get-full-organization | – | id, name, members[].userId, members[].role |
| POST /sign-in/email | {email, password} | data.user; returns {redirect, token, url, user} |
| POST /sign-up/email | {email, name, password} | data.user; 422 USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL (disabled in production) |
| POST /sign-in/social | {provider, callbackURL?, newUserCallbackURL?} | {url, redirect:true} |
| POST /sign-out | {} | – |
| POST /email-otp/send-verification-otp | {email, type:"forget-password"} | error |
| POST /email-otp/reset-password | {email, otp, password} | error |
| POST /change-password | {currentPassword, newPassword} | error |
| POST /update-user | {name} | error; {status:true} |
| POST /change-email | {newEmail} | error |
| POST /delete-user | {} (session must be < 24 h old, else 400 SESSION_EXPIRED) | error |
| POST /organization/create | {name, slug} | data.id |
| POST /organization/set-active | {organizationId} or {organizationId:null} | – |
| POST /organization/update | {organizationId, data:{name}} | error |
| POST /organization/delete | {organizationId} | – |
| POST /organization/invite-member | {email, role, organizationId, teamId?, hasRestrictedSiteAccess, siteIds} | error |
| POST /organization/accept-invitation | {invitationId} | error; {invitation, member} |
| POST /organization/cancel-invitation | {invitationId} | – |
| GET /organization/list-invitations?organizationId= | – | [].id, email, role, status, expiresAt |
| POST /organization/remove-member | {memberIdOrEmail, organizationId} | – |
| POST /organization/update-member-role | {memberId, organizationId, role} | – |
| GET /api-key/list[?organizationId=] | – | apiKeys[].id, name, start, permissions, createdAt, lastRequest |
| POST /api-key/delete | {keyId} or {keyId, configId:"org"} | error |
| POST /admin/has-permission | {permissions:{user:["impersonate"]}} | success |
| GET /admin/list-users | limit, offset, sortBy, sortDirection, searchField=email, searchOperator=contains, searchValue, filterField=role, filterOperator=eq, filterValue | users[].id, name, email, role, createdAt; total |
| POST /admin/impersonate-user | {userId} | – |
| POST /admin/stop-impersonating | {} | – |
| POST /admin/update-user | {userId, data:{name[, email]}} | error |
| POST /admin/set-role, /admin/ban-user, /admin/unban-user | {userId, role} / {userId, banReason?, banExpiresIn?} / {userId} | error |

Errors reach the UI as `{message, code}`. `useSession` refetches on window focus and after sign-in/up/out, update-user, change-email, change-password, delete-user, set-active, org create/delete/remove-member/accept-invitation, impersonate/stop. `useActiveOrganization` refetches after any `/organization*` call or sign-out. Not called by the client: reject-invitation, team endpoints, api-key create, organization list and leave.

## Server-side uses (`server/src`)

- `getSession({headers})` in guards (`lib/auth-utils.ts:104`), `verifyApiKey({body:{key}})` (no configId), `getMcpSession({headers:{authorization}})`, `createApiKey` (the two Fastify routes), `getMcpOAuthConfig`/`getMCPProtectedResource` (`mcp/wellKnown.ts`).
- `createUserInOrganization` uses `internalAdapter.findUserByEmail`, `createUser`, `password.hash`, `linkAccount`, then inserts the member through drizzle with its own 62-char-alphabet id.
- Bearer resolution (`lib/bearerAuth.ts:113`): API key first (org config → organization identity, else user; scopes from `permissions`, null = unrestricted), `RATE_LIMITED` passthrough, then MCP token (scopes from the space-separated list minus OIDC scopes, none left = unrestricted), else invalid, or `verify_error` if verification threw.

## Quirks and decisions

1. Organization plan fields (`stripeCustomerId`, `monthlyEventCount`, `overMonthlyLimit`, `planOverride`, `customPlan`) are accepted from the browser by `/organization/create` and `/organization/update` in Better Auth. **Not ported:** Rust accepts only `name`, `slug`, `logo`, `metadata`.
2. `customPlan` maps to a nonexistent `"customPlan"` column (the real one is `custom_plan`), so Better Auth reads return undefined and writes fail. Rust reads `custom_plan`.
3. Guard lookups refresh `expiresAt` in the database without reissuing the cookie. Keep (harmless, and the browser's own `/get-session` call reissues).
4. The `user.update.before` role strip does nothing, so admin `set-role` works. Keep the working behaviour.
5. Refreshing an MCP token doesn't revoke the old refresh token. Keep for compatibility with issued tokens.
6. `/auth/*` never reached Better Auth. Not ported.
