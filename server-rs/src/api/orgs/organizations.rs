//! The two organization listings, ported from server/src/api/user/getMyOrganizations.ts
//! and server/src/api/user/getUserOrganizations.ts.

use axum::{
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri},
    response::Response,
};
use sqlx::{PgPool, Row};
use tracing::{debug, error};

use super::{
    access,
    chain::{self},
    request::{self, object, text},
};
use crate::{
    analytics::{
        chain::{account_scoped, route_scope},
        js::JsValue,
    },
    auth::access::{get_org_membership, member_can_access_site, resolve_member_site_grants},
    state::AppState,
};

/// One row of the caller's organizations (`db.select(...).from(member).innerJoin(organization)`).
struct OrgRow {
    id: String,
    name: String,
    slug: String,
    logo: Option<String>,
    created_at: Option<String>,
    role: String,
}

async fn caller_organizations(pg: &PgPool, user_id: &str) -> Result<Vec<OrgRow>, sqlx::Error> {
    let rows = sqlx::query(
        r#"select "organization"."id", "organization"."name", "organization"."slug", "organization"."logo",
                  "organization"."createdAt"::text as "createdAt", "member"."role"
           from "member" inner join "organization" on "member"."organizationId" = "organization"."id"
           where "member"."userId" = $1"#,
    )
    .bind(user_id)
    .fetch_all(pg)
    .await?;
    rows.iter()
        .map(|row| {
            Ok(OrgRow {
                id: row.try_get("id")?,
                name: row.try_get("name")?,
                slug: row.try_get("slug")?,
                logo: row.try_get("logo")?,
                created_at: row.try_get("createdAt")?,
                role: row.try_get("role")?,
            })
        })
        .collect()
}

/// GET /api/organizations (`getMyOrganizations`). No preHandler: the handler
/// resolves the caller itself, so a credential that is not a cookie session still
/// gets its organizations, but without the member roster (names and emails).
pub async fn get_my_organizations(State(state): State<AppState>, uri: Uri, headers: HeaderMap) -> Response {
    let query = chain::unguarded(&uri);
    let context = chain::context(&state, &headers, &query);
    let user_id = match access::user_id_from_request(&state, &headers, &query, &context).await {
        Ok(user_id) => user_id,
        Err(response) => return response,
    };
    let Some(user_id) = user_id else {
        // Rate limiting is cloud-only, so `wasRateLimited` is always undefined here
        return request::error(StatusCode::UNAUTHORIZED, "Unauthorized");
    };
    let include_members = match access::session(&context).await {
        Ok(session) => session.is_some(),
        Err(response) => return response,
    };

    match build_organizations(&state, &user_id, include_members).await {
        Ok(value) => request::send(StatusCode::OK, &value),
        Err(err) => {
            error!(error = %err, "Error fetching organizations with members");
            request::error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to fetch organizations")
        }
    }
}

async fn build_organizations(state: &AppState, user_id: &str, include_members: bool) -> Result<JsValue, sqlx::Error> {
    let pg = &state.pg;
    let organizations = caller_organizations(pg, user_id).await?;
    let mut result = Vec::with_capacity(organizations.len());
    for org in &organizations {
        let members = organization_members(pg, &org.id, include_members).await?;
        let sites = organization_sites(pg, &org.id).await?;
        let membership = get_org_membership(pg, Some(user_id), Some(&org.id)).await?;

        // Admins and owners see every site; a member-role caller sees the union of
        // explicit grants, team sites and (when unrestricted) ungated sites
        let sites = match &membership {
            Some(membership) if membership.role == "member" => {
                let granted_member_ids =
                    if membership.has_restricted_site_access { vec![membership.id.clone()] } else { Vec::new() };
                let grants =
                    resolve_member_site_grants(pg, user_id, std::slice::from_ref(&org.id), &granted_member_ids).await?;
                sites
                    .into_iter()
                    .filter(|site| {
                        member_can_access_site(&grants, site.site_id, membership.has_restricted_site_access)
                    })
                    .collect()
            }
            _ => sites,
        };

        result.push(object(vec![
            ("id", org.id.clone().into()),
            ("name", org.name.clone().into()),
            ("slug", org.slug.clone().into()),
            ("logo", text(org.logo.clone())),
            ("createdAt", text(org.created_at.clone())),
            ("role", org.role.clone().into()),
            ("members", JsValue::Array(members)),
            ("sites", JsValue::Array(sites.iter().map(SiteRow::to_json).collect())),
        ]));
    }
    debug!(user_id, organizations = result.len(), "Fetched organizations with members");
    Ok(JsValue::Array(result))
}

/// `organizationMembers.map(...)`, or `[]` when the caller is not a cookie session.
async fn organization_members(
    pg: &PgPool,
    organization_id: &str,
    include_members: bool,
) -> Result<Vec<JsValue>, sqlx::Error> {
    let rows = sqlx::query(
        r#"select "member"."id", "member"."role", "member"."userId", "member"."createdAt"::text as "createdAt",
                  "user"."name" as "userName", "user"."email" as "userEmail", "user"."id" as "userActualId"
           from "member" left join "user" on "member"."userId" = "user"."id"
           where "member"."organizationId" = $1"#,
    )
    .bind(organization_id)
    .fetch_all(pg)
    .await?;
    if !include_members {
        // Node still runs the query and only drops the result
        return Ok(Vec::new());
    }
    rows.iter()
        .map(|row| {
            Ok(object(vec![
                ("id", JsValue::String(row.try_get("id")?)),
                ("role", JsValue::String(row.try_get("role")?)),
                ("userId", JsValue::String(row.try_get("userId")?)),
                ("createdAt", text(row.try_get("createdAt")?)),
                (
                    "user",
                    object(vec![
                        ("id", text(row.try_get("userActualId")?)),
                        ("name", text(row.try_get("userName")?)),
                        ("email", text(row.try_get("userEmail")?)),
                    ]),
                ),
            ]))
        })
        .collect()
}

/// The site columns `getMyOrganizations` selects.
struct SiteRow {
    site_id: i32,
    domain: String,
    name: String,
    organization_id: Option<String>,
    created_by: Option<String>,
    public: Option<bool>,
    salt_user_ids: Option<bool>,
    block_bots: bool,
    created_at: Option<String>,
}

impl SiteRow {
    /// `String(site.siteId ?? site.siteUuid)` and the rest of the projection.
    fn to_json(&self) -> JsValue {
        object(vec![
            ("id", JsValue::String(self.site_id.to_string())),
            ("domain", self.domain.clone().into()),
            ("name", self.name.clone().into()),
            ("organizationId", text(self.organization_id.clone())),
            ("createdBy", text(self.created_by.clone())),
            ("public", super::request::boolean(self.public)),
            ("saltUserIds", super::request::boolean(self.salt_user_ids)),
            ("blockBots", JsValue::Bool(self.block_bots)),
            ("createdAt", text(self.created_at.clone())),
        ])
    }
}

async fn organization_sites(pg: &PgPool, organization_id: &str) -> Result<Vec<SiteRow>, sqlx::Error> {
    let rows = sqlx::query(
        r#"select "sites"."site_id", "sites"."domain", "sites"."name", "sites"."organization_id",
                  "sites"."created_by", "sites"."public", "sites"."saltUserIds", "sites"."blockBots",
                  "sites"."created_at"::text as "created_at"
           from "sites" where "sites"."organization_id" = $1"#,
    )
    .bind(organization_id)
    .fetch_all(pg)
    .await?;
    rows.iter()
        .map(|row| {
            Ok(SiteRow {
                site_id: row.try_get("site_id")?,
                domain: row.try_get("domain")?,
                name: row.try_get("name")?,
                organization_id: row.try_get("organization_id")?,
                created_by: row.try_get("created_by")?,
                public: row.try_get("public")?,
                salt_user_ids: row.try_get("saltUserIds")?,
                block_bots: row.try_get("blockBots")?,
                created_at: row.try_get("created_at")?,
            })
        })
        .collect()
}

/// GET /api/user/organizations (`getUserOrganizations`), chain `authOrgRead`.
///
/// `request.user` is only set for cookie sessions and user-owned API keys, and an
/// API key needs an organization or site target to pass `checkApiKey` at all, so
/// every bearer call lands on the guard's 401 before reaching this handler.
pub async fn get_user_organizations(
    State(state): State<AppState>,
    _method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let scoped = match account_scoped(&state, &headers, &uri, false, route_scope("org", "read")).await {
        Ok(scoped) => scoped,
        Err(response) => return response,
    };
    let Some(user_id) = scoped.auth.user_id else {
        return request::error(StatusCode::UNAUTHORIZED, "Unauthorized");
    };

    let rows = sqlx::query(
        r#"select "organization"."id", "organization"."name", "organization"."slug", "organization"."logo",
                  "organization"."createdAt"::text as "createdAt", "organization"."metadata", "member"."role"
           from "member" inner join "organization" on "member"."organizationId" = "organization"."id"
           where "member"."userId" = $1"#,
    )
    .bind(&user_id)
    .fetch_all(&state.pg)
    .await;
    let rows = match rows {
        Ok(rows) => rows,
        Err(err) => {
            error!(error = %err, "Error fetching user organizations");
            // `reply.status(500).send(string)` is a text/plain payload in Fastify
            return request::send_text(StatusCode::INTERNAL_SERVER_ERROR, "Failed to fetch user organizations");
        }
    };
    let mut listed = Vec::with_capacity(rows.len());
    for row in &rows {
        let read = || -> Result<JsValue, sqlx::Error> {
            Ok(object(vec![
                ("id", JsValue::String(row.try_get("id")?)),
                ("name", JsValue::String(row.try_get("name")?)),
                ("slug", JsValue::String(row.try_get("slug")?)),
                ("logo", text(row.try_get("logo")?)),
                ("createdAt", text(row.try_get("createdAt")?)),
                ("metadata", text(row.try_get("metadata")?)),
                ("role", JsValue::String(row.try_get("role")?)),
            ]))
        };
        match read() {
            Ok(value) => listed.push(value),
            Err(err) => {
                error!(error = %err, "Error fetching user organizations");
                return request::send_text(StatusCode::INTERNAL_SERVER_ERROR, "Failed to fetch user organizations");
            }
        }
    }
    debug!(user_id, organizations = listed.len(), "Fetched user organizations");
    request::send(StatusCode::OK, &JsValue::Array(listed))
}
