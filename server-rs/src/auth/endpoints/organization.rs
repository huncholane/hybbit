//! The organization plugin (better-auth/dist/plugins/organization) as auth.ts
//! configures it: teams enabled, the `apiKey` resource added to the owner and admin
//! roles, invitation site restrictions (`beforeCreateInvitation`), API key purge
//! before deletion, invitation cleanup after removals, and the app's after hook
//! that copies an accepted invitation's site restrictions onto the new member.

use axum::http::StatusCode;
use chrono::NaiveDateTime;
use serde_json::{Map, Value, json};
use sqlx::{PgPool, Row, postgres::PgRow};
use tracing::{debug, error, info, warn};

use crate::email;

use super::{
    Endpoint, better_json,
    context::{ApiError, Ctx, EndpointResult, Reply, truthy},
    crypto,
    db::{self, SessionField, SessionWithUser, iso, iso_opt, opt_str},
    require_session, session_from_ctx,
    validate::{self, Ty, nullish, optional, required},
};

const CREATOR_ROLE: &str = "owner";
const MEMBERSHIP_LIMIT: i64 = 100;
const INVITATION_LIMIT: usize = 100;
const INVITATION_EXPIRES_IN: i64 = 172_800;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
    Create,
    Update,
    Delete,
    SetActive,
    GetFull,
    List,
    InviteMember,
    CancelInvitation,
    AcceptInvitation,
    GetInvitation,
    RejectInvitation,
    ListInvitations,
    GetActiveMember,
    CheckSlug,
    RemoveMember,
    UpdateMemberRole,
    Leave,
    ListUserInvitations,
    HasPermission,
}

pub async fn run(ctx: &mut Ctx<'_>, route: Route) -> EndpointResult {
    match route {
        Route::Create => create(ctx).await,
        Route::Update => update(ctx).await,
        Route::Delete => delete(ctx).await,
        Route::SetActive => set_active(ctx).await,
        Route::GetFull => get_full(ctx).await,
        Route::List => list(ctx).await,
        Route::InviteMember => invite_member(ctx).await,
        Route::CancelInvitation => cancel_invitation(ctx).await,
        Route::AcceptInvitation => accept_invitation(ctx).await,
        Route::GetInvitation => get_invitation(ctx).await,
        Route::RejectInvitation => reject_invitation(ctx).await,
        Route::ListInvitations => list_invitations(ctx).await,
        Route::GetActiveMember => get_active_member(ctx).await,
        Route::CheckSlug => check_slug(ctx).await,
        Route::RemoveMember => remove_member(ctx).await,
        Route::UpdateMemberRole => update_member_role(ctx).await,
        Route::Leave => leave(ctx).await,
        Route::ListUserInvitations => list_user_invitations(ctx).await,
        Route::HasPermission => has_permission_endpoint(ctx).await,
    }
}

fn org_error(status: StatusCode, code: &str, message: &str) -> ApiError {
    ApiError::code(status, code, message)
}

fn not_member() -> ApiError {
    org_error(StatusCode::BAD_REQUEST, "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION", "User is not a member of the organization")
}

fn member_not_found() -> ApiError {
    org_error(StatusCode::BAD_REQUEST, "MEMBER_NOT_FOUND", "Member not found")
}

fn organization_not_found() -> ApiError {
    org_error(StatusCode::BAD_REQUEST, "ORGANIZATION_NOT_FOUND", "Organization not found")
}

// ---------------------------------------------------------------------------
// access control

/// auth.ts `orgRoles`: the default statements plus `apiKey`
fn role_statements(role: &str) -> Option<&'static [(&'static str, &'static [&'static str])]> {
    const CRUD: &[&str] = &["create", "read", "update", "delete"];
    const MEMBER_ACTIONS: &[&str] = &["create", "update", "delete"];
    match role {
        "owner" => Some(&[
            ("organization", &["update", "delete"]),
            ("member", MEMBER_ACTIONS),
            ("invitation", &["create", "cancel"]),
            ("team", MEMBER_ACTIONS),
            ("ac", CRUD),
            ("apiKey", CRUD),
        ]),
        "admin" => Some(&[
            ("organization", &["update"]),
            ("invitation", &["create", "cancel"]),
            ("member", MEMBER_ACTIONS),
            ("team", MEMBER_ACTIONS),
            ("ac", CRUD),
            ("apiKey", CRUD),
        ]),
        "member" => Some(&[("organization", &[]), ("member", &[]), ("invitation", &[]), ("team", &[]), ("ac", &["read"])]),
        _ => None,
    }
}

/// `role(statements).authorize(request)` with the AND connector
pub fn authorize(statements: &[(&str, &[&str])], request: &Map<String, Value>) -> bool {
    let mut authorized_any = false;
    for (resource, requested) in request {
        let Some((_, allowed)) = statements.iter().find(|(name, _)| name == resource) else { return false };
        let actions: Vec<&Value> = match requested {
            Value::Array(items) => items.iter().collect(),
            Value::Object(object) => match object.get("actions") {
                Some(Value::Array(items)) => items.iter().collect(),
                _ => Vec::new(),
            },
            _ => return false,
        };
        let ok = !actions.is_empty() && actions.iter().all(|action| action.as_str().is_some_and(|a| allowed.contains(&a)));
        if !ok {
            return false;
        }
        authorized_any = true;
    }
    authorized_any
}

/// `hasPermission({ role, permissions, allowCreatorAllPermissions })` for organization roles
pub fn has_permission(role: &str, permissions: Option<&Map<String, Value>>, allow_creator_all: bool) -> bool {
    let Some(permissions) = permissions else { return false };
    let roles: Vec<&str> = role.split(',').collect();
    if allow_creator_all && roles.contains(&CREATOR_ROLE) {
        return true;
    }
    roles.iter().any(|role| role_statements(role).is_some_and(|statements| authorize(statements, permissions)))
}

fn permission(resource: &str, action: &str) -> Map<String, Value> {
    let mut map = Map::new();
    map.insert(resource.into(), json!([action]));
    map
}

// ---------------------------------------------------------------------------
// rows

#[derive(Clone, Debug)]
pub struct Organization {
    pub id: String,
    pub name: String,
    pub slug: String,
    pub logo: Option<String>,
    pub created_at: NaiveDateTime,
    pub metadata: Option<String>,
    pub stripe_customer_id: Option<String>,
    pub monthly_event_count: Option<i32>,
    pub over_monthly_limit: Option<bool>,
    pub plan_override: Option<String>,
}

const ORG_COLUMNS: &str =
    r#"id, name, slug, logo, "createdAt", metadata, "stripeCustomerId", "monthlyEventCount", "overMonthlyLimit", "planOverride""#;

/// How the organization's `metadata` appears in a response
enum MetadataOutput {
    /// The stored text as is (reads)
    Raw,
    /// `JSON.parse` when truthy, dropped otherwise (create)
    Parsed,
    /// `parseJSON` (better-json) when truthy, dropped otherwise (update)
    BetterJson,
}

impl Organization {
    fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            name: row.try_get("name")?,
            slug: row.try_get("slug")?,
            logo: row.try_get("logo")?,
            created_at: row.try_get("createdAt")?,
            metadata: row.try_get("metadata")?,
            stripe_customer_id: row.try_get("stripeCustomerId")?,
            monthly_event_count: row.try_get("monthlyEventCount")?,
            over_monthly_limit: row.try_get("overMonthlyLimit")?,
            plan_override: row.try_get("planOverride")?,
        })
    }

    /// Schema order; `customPlan` maps to a column that does not exist, so it is
    /// always undefined and never serialised.
    fn to_json_with(&self, metadata: MetadataOutput) -> Map<String, Value> {
        let mut map = Map::new();
        map.insert("name".into(), Value::from(self.name.clone()));
        map.insert("slug".into(), Value::from(self.slug.clone()));
        map.insert("logo".into(), opt_str(self.logo.clone()));
        map.insert("createdAt".into(), Value::from(iso(self.created_at)));
        let metadata_value = match metadata {
            MetadataOutput::Raw => Some(opt_str(self.metadata.clone())),
            // the text was just written from JSON.stringify, so JSON.parse cannot throw here
            MetadataOutput::Parsed => {
                self.metadata.as_deref().filter(|text| !text.is_empty()).map(|text| better_json::js_json_parse(text).unwrap_or(Value::Null))
            }
            // callers check `better_json_metadata_error` first; undefined drops the key
            MetadataOutput::BetterJson => self
                .metadata
                .as_deref()
                .filter(|text| !text.is_empty())
                .and_then(|text| better_json::parse_json_strict(text).ok().flatten()),
        };
        if let Some(value) = metadata_value {
            map.insert("metadata".into(), value);
        }
        map.insert("stripeCustomerId".into(), opt_str(self.stripe_customer_id.clone()));
        map.insert("monthlyEventCount".into(), self.monthly_event_count.map_or(Value::Null, Value::from));
        map.insert("overMonthlyLimit".into(), self.over_monthly_limit.map_or(Value::Null, Value::from));
        map.insert("planOverride".into(), opt_str(self.plan_override.clone()));
        map.insert("id".into(), Value::from(self.id.clone()));
        map
    }

    pub fn to_json(&self) -> Value {
        Value::Object(self.to_json_with(MetadataOutput::Raw))
    }
}

impl Organization {
    /// `parseJSON(organization.metadata)` (strict) throws for stored text that is not
    /// JSON, which fails the request with a 500 after the update was written.
    fn better_json_metadata_error(&self) -> Option<better_json::StrictParseError> {
        self.metadata.as_deref().filter(|text| !text.is_empty()).and_then(|text| better_json::parse_json_strict(text).err())
    }
}

pub async fn find_organization(pg: &PgPool, id: &str) -> Result<Option<Organization>, sqlx::Error> {
    let row = sqlx::query(&format!("SELECT {ORG_COLUMNS} FROM organization WHERE id = $1")).bind(id).fetch_optional(pg).await?;
    row.as_ref().map(Organization::from_row).transpose()
}

async fn find_organization_by_slug(pg: &PgPool, slug: &str) -> Result<Option<Organization>, sqlx::Error> {
    let row = sqlx::query(&format!("SELECT {ORG_COLUMNS} FROM organization WHERE slug = $1")).bind(slug).fetch_optional(pg).await?;
    row.as_ref().map(Organization::from_row).transpose()
}

#[derive(Clone, Debug)]
pub struct Member {
    pub id: String,
    pub organization_id: String,
    pub user_id: String,
    pub role: String,
    pub created_at: NaiveDateTime,
}

const MEMBER_COLUMNS: &str = r#"id, "organizationId", "userId", role, "createdAt""#;

impl Member {
    fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            organization_id: row.try_get("organizationId")?,
            user_id: row.try_get("userId")?,
            role: row.try_get("role")?,
            created_at: row.try_get("createdAt")?,
        })
    }

    pub fn to_json(&self) -> Map<String, Value> {
        let mut map = Map::new();
        map.insert("organizationId".into(), Value::from(self.organization_id.clone()));
        map.insert("userId".into(), Value::from(self.user_id.clone()));
        map.insert("role".into(), Value::from(self.role.clone()));
        map.insert("createdAt".into(), Value::from(iso(self.created_at)));
        map.insert("id".into(), Value::from(self.id.clone()));
        map
    }

    /// `{ ...member, user: { id, name, email, image } }`
    fn with_user(&self, user: &db::User) -> Value {
        let mut map = self.to_json();
        map.insert("user".into(), json!({"id": user.id, "name": user.name, "email": user.email, "image": user.image}));
        Value::Object(map)
    }
}

/// `findMemberByOrgId`: None when the member or its user is missing
async fn find_member_by_org(pg: &PgPool, user_id: &str, organization_id: &str) -> Result<Option<(Member, db::User)>, sqlx::Error> {
    let row = sqlx::query(&format!(r#"SELECT {MEMBER_COLUMNS} FROM member WHERE "userId" = $1 AND "organizationId" = $2"#))
        .bind(user_id)
        .bind(organization_id)
        .fetch_optional(pg)
        .await?;
    let Some(member) = row.as_ref().map(Member::from_row).transpose()? else { return Ok(None) };
    Ok(db::find_user_by_id(pg, &member.user_id).await?.map(|user| (member, user)))
}

async fn find_member_by_id(pg: &PgPool, member_id: &str) -> Result<Option<(Member, Option<db::User>)>, sqlx::Error> {
    let row = sqlx::query(&format!("SELECT {MEMBER_COLUMNS} FROM member WHERE id = $1")).bind(member_id).fetch_optional(pg).await?;
    let Some(member) = row.as_ref().map(Member::from_row).transpose()? else { return Ok(None) };
    let user = db::find_user_by_id(pg, &member.user_id).await?;
    Ok(Some((member, user)))
}

/// `findMemberByEmail`
async fn find_member_by_email(pg: &PgPool, email: &str, organization_id: &str) -> Result<Option<(Member, db::User)>, sqlx::Error> {
    let Some(user) = db::find_user_by_email(pg, email).await? else { return Ok(None) };
    let row = sqlx::query(&format!(r#"SELECT {MEMBER_COLUMNS} FROM member WHERE "organizationId" = $1 AND "userId" = $2"#))
        .bind(organization_id)
        .bind(&user.id)
        .fetch_optional(pg)
        .await?;
    Ok(row.as_ref().map(Member::from_row).transpose()?.map(|member| (member, user)))
}

async fn list_org_members(pg: &PgPool, organization_id: &str) -> Result<Vec<Member>, sqlx::Error> {
    let rows = sqlx::query(&format!(r#"SELECT {MEMBER_COLUMNS} FROM member WHERE "organizationId" = $1 LIMIT 100"#))
        .bind(organization_id)
        .fetch_all(pg)
        .await?;
    rows.iter().map(Member::from_row).collect()
}

#[derive(Clone, Debug)]
pub struct Invitation {
    pub id: String,
    pub organization_id: String,
    pub email: String,
    pub role: String,
    pub team_id: Option<String>,
    pub status: String,
    pub expires_at: NaiveDateTime,
    pub created_at: Option<NaiveDateTime>,
    pub inviter_id: Option<String>,
    pub has_restricted_site_access: bool,
    pub site_ids: Option<Value>,
}

const INVITATION_COLUMNS: &str = r#"id, "organizationId", email, role, "teamId", status, "expiresAt", "createdAt", "inviterId", has_restricted_site_access, site_ids"#;

impl Invitation {
    fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            organization_id: row.try_get("organizationId")?,
            email: row.try_get("email")?,
            role: row.try_get("role")?,
            team_id: row.try_get("teamId")?,
            status: row.try_get("status")?,
            expires_at: row.try_get("expiresAt")?,
            created_at: row.try_get("createdAt")?,
            inviter_id: row.try_get("inviterId")?,
            has_restricted_site_access: row.try_get("has_restricted_site_access")?,
            site_ids: row.try_get("site_ids")?,
        })
    }

    pub fn to_json(&self) -> Map<String, Value> {
        let mut map = Map::new();
        map.insert("organizationId".into(), Value::from(self.organization_id.clone()));
        map.insert("email".into(), Value::from(self.email.clone()));
        map.insert("role".into(), Value::from(self.role.clone()));
        map.insert("teamId".into(), opt_str(self.team_id.clone()));
        map.insert("status".into(), Value::from(self.status.clone()));
        map.insert("expiresAt".into(), Value::from(iso(self.expires_at)));
        map.insert("createdAt".into(), iso_opt(self.created_at));
        map.insert("inviterId".into(), opt_str(self.inviter_id.clone()));
        map.insert("hasRestrictedSiteAccess".into(), Value::from(self.has_restricted_site_access));
        map.insert("siteIds".into(), self.site_ids.clone().unwrap_or(Value::Null));
        map.insert("id".into(), Value::from(self.id.clone()));
        map
    }
}

async fn find_invitation(pg: &PgPool, id: &str) -> Result<Option<Invitation>, sqlx::Error> {
    let row = sqlx::query(&format!("SELECT {INVITATION_COLUMNS} FROM invitation WHERE id = $1")).bind(id).fetch_optional(pg).await?;
    row.as_ref().map(Invitation::from_row).transpose()
}

/// `updateInvitation`: `incrementOne` setting the status (optionally only from a status)
async fn set_invitation_status(pg: &PgPool, id: &str, status: &str, from: Option<&str>) -> Result<Option<Invitation>, sqlx::Error> {
    let row = match from {
        Some(from) => {
            sqlx::query(&format!(
                "UPDATE invitation SET status = $1 WHERE id IN (SELECT id FROM invitation WHERE id = $2 AND status = $3 LIMIT 1) RETURNING {INVITATION_COLUMNS}"
            ))
            .bind(status)
            .bind(id)
            .bind(from)
            .fetch_optional(pg)
            .await?
        }
        None => {
            sqlx::query(&format!(
                "UPDATE invitation SET status = $1 WHERE id IN (SELECT id FROM invitation WHERE id = $2 LIMIT 1) RETURNING {INVITATION_COLUMNS}"
            ))
            .bind(status)
            .bind(id)
            .fetch_optional(pg)
            .await?
        }
    };
    row.as_ref().map(Invitation::from_row).transpose()
}

#[derive(Clone, Debug)]
struct Team {
    id: String,
    name: String,
    organization_id: String,
    created_at: NaiveDateTime,
    updated_at: Option<NaiveDateTime>,
}

impl Team {
    fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            name: row.try_get("name")?,
            organization_id: row.try_get("organizationId")?,
            created_at: row.try_get("createdAt")?,
            updated_at: row.try_get("updatedAt")?,
        })
    }

    fn to_json(&self) -> Value {
        json!({
            "name": self.name,
            "organizationId": self.organization_id,
            "createdAt": iso(self.created_at),
            "updatedAt": iso_opt(self.updated_at),
            "id": self.id,
        })
    }
}

async fn find_team(pg: &PgPool, team_id: &str, organization_id: &str) -> Result<Option<Team>, sqlx::Error> {
    let row = sqlx::query(r#"SELECT id, name, "organizationId", "createdAt", "updatedAt" FROM team WHERE id = $1 AND "organizationId" = $2"#)
        .bind(team_id)
        .bind(organization_id)
        .fetch_optional(pg)
        .await?;
    row.as_ref().map(Team::from_row).transpose()
}

/// `findOrCreateTeamMember`
async fn find_or_create_team_member(pg: &PgPool, team_id: &str, user_id: &str) -> Result<(), sqlx::Error> {
    let exists: Option<String> = sqlx::query_scalar(r#"SELECT id FROM "teamMember" WHERE "teamId" = $1 AND "userId" = $2"#)
        .bind(team_id)
        .bind(user_id)
        .fetch_optional(pg)
        .await?;
    if exists.is_none() {
        sqlx::query(r#"INSERT INTO "teamMember" (id, "teamId", "userId", "createdAt") VALUES ($1, $2, $3, $4)"#)
            .bind(crypto::generate_id())
            .bind(team_id)
            .bind(user_id)
            .bind(db::now_ms())
            .execute(pg)
            .await?;
    }
    Ok(())
}

/// `createMember`
async fn create_member(pg: &PgPool, organization_id: &str, user_id: &str, role: &str) -> Result<Member, sqlx::Error> {
    let row = sqlx::query(&format!(
        r#"INSERT INTO member (id, "organizationId", "userId", role, "createdAt") VALUES ($1, $2, $3, $4, $5) RETURNING {MEMBER_COLUMNS}"#
    ))
    .bind(crypto::generate_id())
    .bind(organization_id)
    .bind(user_id)
    .bind(role)
    .bind(db::now_ms())
    .fetch_one(pg)
    .await?;
    Member::from_row(&row)
}

/// `deleteMember`: the member row, then its team memberships in the organization
async fn delete_member(pg: &PgPool, member_id: &str, organization_id: &str, user_id: &str) -> Result<(), sqlx::Error> {
    let mut tx = pg.begin().await?;
    sqlx::query("DELETE FROM member WHERE id = $1").bind(member_id).execute(&mut *tx).await?;
    let teams: Vec<String> = sqlx::query_scalar(r#"SELECT id FROM team WHERE "organizationId" = $1 LIMIT 100"#)
        .bind(organization_id)
        .fetch_all(&mut *tx)
        .await?;
    if !teams.is_empty() {
        sqlx::query(r#"DELETE FROM "teamMember" WHERE "userId" = $1 AND "teamId" = ANY($2)"#)
            .bind(user_id)
            .bind(&teams)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(())
}

async fn set_active_organization(pg: &PgPool, token: &str, organization_id: Option<&str>) -> Result<Option<db::Session>, sqlx::Error> {
    db::update_session(pg, token, SessionField::ActiveOrganizationId(organization_id.map(str::to_string))).await
}

/// `siteIdsInOrganization` (server/src/lib/access.ts)
pub async fn site_ids_in_organization(pg: &PgPool, site_ids: &[i64], organization_id: &str) -> Result<Vec<i64>, sqlx::Error> {
    if site_ids.is_empty() {
        return Ok(Vec::new());
    }
    sqlx::query_scalar::<_, i32>("SELECT site_id FROM sites WHERE organization_id = $1 AND site_id = ANY($2)")
        .bind(organization_id)
        .bind(site_ids)
        .fetch_all(pg)
        .await
        .map(|ids| ids.into_iter().map(i64::from).collect())
}

// ---------------------------------------------------------------------------
// endpoints

const CREATE_FIELDS: &[validate::Field] = &[
    required("name", Ty::NonEmptyString),
    required("slug", Ty::NonEmptyString),
    optional("userId", Ty::CoerceString),
    nullish("logo", Ty::String),
    optional("metadata", Ty::Record),
    optional("keepCurrentActiveOrganization", Ty::Boolean),
];

/// `POST /organization/create`: owner member, default team with its member, and
/// the new organization and team made active. Plan fields from the browser are
/// ignored (AUTH_COMPAT quirk 1).
async fn create(ctx: &mut Ctx<'_>) -> EndpointResult {
    validate::object(ctx.body.as_ref(), CREATE_FIELDS, "body", false)?;
    let Some(session) = session_from_ctx(ctx).await else { return Err(ApiError::status(StatusCode::UNAUTHORIZED)) };
    let body = ctx.body_object().cloned().unwrap_or_default();
    let name = body.get("name").and_then(Value::as_str).unwrap_or_default().to_string();
    let slug = body.get("slug").and_then(Value::as_str).unwrap_or_default().to_string();
    if find_organization_by_slug(&ctx.state.pg, &slug).await?.is_some() {
        return Err(org_error(StatusCode::BAD_REQUEST, "ORGANIZATION_ALREADY_EXISTS", "Organization already exists"));
    }
    let logo = match body.get("logo") {
        Some(Value::String(logo)) => Some(Some(logo.clone())),
        Some(Value::Null) => Some(None),
        _ => None,
    };
    let metadata = body.get("metadata").filter(|m| truthy(Some(m))).map(crate::js_json::stringify);
    let id = crypto::generate_id();
    let row = sqlx::query(&format!(
        r#"INSERT INTO organization (id, name, slug, logo, "createdAt", metadata, "monthlyEventCount", "overMonthlyLimit")
           VALUES ($1, $2, $3, $4, $5, $6, 0, false) RETURNING {ORG_COLUMNS}"#
    ))
    .bind(&id)
    .bind(&name)
    .bind(&slug)
    .bind(logo.flatten())
    .bind(db::now_ms())
    .bind(metadata)
    .fetch_one(&ctx.state.pg)
    .await?;
    let organization = Organization::from_row(&row)?;
    let member = create_member(&ctx.state.pg, &organization.id, &session.user.id, CREATOR_ROLE).await?;
    let team_id = crypto::generate_id();
    sqlx::query(r#"INSERT INTO team (id, name, "organizationId", "createdAt") VALUES ($1, $2, $3, $4)"#)
        .bind(&team_id)
        .bind(&organization.name)
        .bind(&organization.id)
        .bind(db::now_ms())
        .execute(&ctx.state.pg)
        .await?;
    find_or_create_team_member(&ctx.state.pg, &team_id, &session.user.id).await?;
    if body.get("keepCurrentActiveOrganization") != Some(&Value::Bool(true)) {
        set_active_organization(&ctx.state.pg, &session.session.token, Some(&organization.id)).await?;
        db::update_session(&ctx.state.pg, &session.session.token, SessionField::ActiveTeamId(Some(team_id))).await?;
    }
    info!(organization_id = %organization.id, user_id = %session.user.id, "Organization created");
    let mut response = organization.to_json_with(MetadataOutput::Parsed);
    response.insert("members".into(), Value::Array(vec![Value::Object(member.to_json())]));
    Ok(Reply::Json(Value::Object(response)))
}

/// `POST /organization/update`: name, slug, logo and metadata only
async fn update(ctx: &mut Ctx<'_>) -> EndpointResult {
    validate::object(ctx.body.as_ref(), &[required("data", Ty::Record), optional("organizationId", Ty::String)], "body", false)?;
    let data = ctx.body_object().and_then(|b| b.get("data")).and_then(Value::as_object).cloned().unwrap_or_default();
    validate::object(
        Some(&Value::Object(data.clone())),
        &[optional("name", Ty::NonEmptyString), optional("slug", Ty::NonEmptyString), nullish("logo", Ty::String), optional("metadata", Ty::Record)],
        "body.data",
        false,
    )?;
    let Some(session) = session_from_ctx(ctx).await else {
        return Err(ApiError::message(StatusCode::UNAUTHORIZED, "User not found"));
    };
    let organization_id = ctx
        .body_str("organizationId")
        .filter(|id| !id.is_empty())
        .map(str::to_string)
        .or_else(|| session.session.active_organization_id.clone());
    let Some(organization_id) = organization_id else { return Err(organization_not_found()) };
    let Some((member, _)) = find_member_by_org(&ctx.state.pg, &session.user.id, &organization_id).await? else {
        return Err(not_member());
    };
    if !has_permission(&member.role, Some(&permission("organization", "update")), false) {
        return Err(org_error(StatusCode::FORBIDDEN, "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_ORGANIZATION", "You are not allowed to update this organization"));
    }
    if let Some(slug) = data.get("slug").and_then(Value::as_str)
        && find_organization_by_slug(&ctx.state.pg, slug).await?.is_some_and(|existing| existing.id != organization_id)
    {
        return Err(org_error(StatusCode::BAD_REQUEST, "ORGANIZATION_SLUG_ALREADY_TAKEN", "Organization slug already taken"));
    }
    let mut assignments: Vec<(&str, Option<String>)> = Vec::new();
    if let Some(Value::String(name)) = data.get("name") {
        assignments.push(("name", Some(name.clone())));
    }
    if let Some(Value::String(slug)) = data.get("slug") {
        assignments.push(("slug", Some(slug.clone())));
    }
    match data.get("logo") {
        Some(Value::String(logo)) => assignments.push(("logo", Some(logo.clone()))),
        Some(Value::Null) => assignments.push(("logo", None)),
        _ => {}
    }
    if let Some(metadata) = data.get("metadata") {
        assignments.push(("metadata", Some(crate::js_json::stringify(metadata))));
    }
    if assignments.is_empty() {
        // Kysely refuses an UPDATE with nothing to set
        error!(organization_id = %organization_id, "Organization update with no fields");
        return Err(ApiError::internal());
    }
    let set: Vec<String> = assignments.iter().enumerate().map(|(i, (column, _))| format!("{column} = ${}", i + 1)).collect();
    let sql = format!("UPDATE organization SET {} WHERE id = ${} RETURNING {ORG_COLUMNS}", set.join(", "), assignments.len() + 1);
    let mut query = sqlx::query(&sql);
    for (_, value) in assignments {
        query = query.bind(value);
    }
    let row = query.bind(&organization_id).fetch_optional(&ctx.state.pg).await?;
    let updated = row.as_ref().map(Organization::from_row).transpose()?;
    info!(organization_id = %organization_id, "Organization updated");
    if let Some(err) = updated.as_ref().and_then(Organization::better_json_metadata_error) {
        error!(organization_id = %organization_id, error = ?err, "Stored organization metadata is not JSON; parseJSON throws");
        return Err(ApiError::internal());
    }
    Ok(Reply::Json(updated.map_or(Value::Null, |org| Value::Object(org.to_json_with(MetadataOutput::BetterJson)))))
}

/// `POST /organization/delete`, with auth.ts's org API key purge first
async fn delete(ctx: &mut Ctx<'_>) -> EndpointResult {
    validate::object(ctx.body.as_ref(), &[required("organizationId", Ty::String)], "body", false)?;
    let Some(session) = session_from_ctx(ctx).await else { return Err(ApiError::status(StatusCode::UNAUTHORIZED)) };
    let organization_id = ctx.body_str("organizationId").unwrap_or_default().to_string();
    if organization_id.is_empty() {
        return Err(organization_not_found());
    }
    let Some((member, _)) = find_member_by_org(&ctx.state.pg, &session.user.id, &organization_id).await? else {
        return Err(not_member());
    };
    if !has_permission(&member.role, Some(&permission("organization", "delete")), false) {
        return Err(org_error(StatusCode::FORBIDDEN, "YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_ORGANIZATION", "You are not allowed to delete this organization"));
    }
    if session.session.active_organization_id.as_deref() == Some(organization_id.as_str()) {
        set_active_organization(&ctx.state.pg, &session.session.token, None).await?;
    }
    let Some(organization) = find_organization(&ctx.state.pg, &organization_id).await? else {
        return Err(ApiError::status(StatusCode::BAD_REQUEST));
    };
    sqlx::query(r#"DELETE FROM apikey WHERE "referenceId" = $1 AND "configId" = 'org'"#).bind(&organization_id).execute(&ctx.state.pg).await?;
    let mut tx = ctx.state.pg.begin().await?;
    sqlx::query(r#"DELETE FROM member WHERE "organizationId" = $1"#).bind(&organization_id).execute(&mut *tx).await?;
    sqlx::query(r#"DELETE FROM invitation WHERE "organizationId" = $1"#).bind(&organization_id).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM organization WHERE id = $1").bind(&organization_id).execute(&mut *tx).await?;
    tx.commit().await?;
    info!(organization_id = %organization_id, user_id = %session.user.id, "Organization deleted");
    Ok(Reply::Json(organization.to_json()))
}

/// `POST /organization/set-active`
async fn set_active(ctx: &mut Ctx<'_>) -> EndpointResult {
    validate::object(ctx.body.as_ref(), &[nullish("organizationId", Ty::String), optional("organizationSlug", Ty::String)], "body", false)?;
    let session = require_session(ctx).await?;
    let body = ctx.body_object().cloned().unwrap_or_default();
    let slug = body.get("organizationSlug").and_then(Value::as_str).map(str::to_string);
    let mut organization_id = match body.get("organizationId") {
        Some(Value::Null) => {
            if session.session.active_organization_id.is_none() {
                return Ok(Reply::Json(Value::Null));
            }
            let updated = set_active_organization(&ctx.state.pg, &session.session.token, None).await?.ok_or_else(ApiError::internal)?;
            ctx.set_session_cookie(&SessionWithUser { session: updated, user: session.user.clone() }, None, None);
            info!(user_id = %session.user.id, "Active organization cleared");
            return Ok(Reply::Json(Value::Null));
        }
        Some(Value::String(id)) if !id.is_empty() => Some(id.clone()),
        _ => None,
    };
    if organization_id.is_none() && slug.as_deref().is_none_or(str::is_empty) {
        match &session.session.active_organization_id {
            None => return Ok(Reply::Json(Value::Null)),
            Some(active) => organization_id = Some(active.clone()),
        }
    }
    if organization_id.is_none()
        && let Some(slug) = slug.filter(|slug| !slug.is_empty())
    {
        let Some(organization) = find_organization_by_slug(&ctx.state.pg, &slug).await? else { return Err(organization_not_found()) };
        organization_id = Some(organization.id);
    }
    let Some(organization_id) = organization_id else { return Err(organization_not_found()) };
    if find_member_row(&ctx.state.pg, &session.user.id, &organization_id).await?.is_none() {
        set_active_organization(&ctx.state.pg, &session.session.token, None).await?;
        return Err(org_error(StatusCode::FORBIDDEN, "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION", "User is not a member of the organization"));
    }
    let Some(organization) = find_organization(&ctx.state.pg, &organization_id).await? else { return Err(organization_not_found()) };
    let updated = set_active_organization(&ctx.state.pg, &session.session.token, Some(&organization.id)).await?.ok_or_else(ApiError::internal)?;
    ctx.set_session_cookie(&SessionWithUser { session: updated, user: session.user.clone() }, None, None);
    info!(organization_id = %organization.id, user_id = %session.user.id, "Active organization set");
    Ok(Reply::Json(organization.to_json()))
}

/// `checkMembership`: the member row without its user
async fn find_member_row(pg: &PgPool, user_id: &str, organization_id: &str) -> Result<Option<Member>, sqlx::Error> {
    let row = sqlx::query(&format!(r#"SELECT {MEMBER_COLUMNS} FROM member WHERE "userId" = $1 AND "organizationId" = $2"#))
        .bind(user_id)
        .bind(organization_id)
        .fetch_optional(pg)
        .await?;
    row.as_ref().map(Member::from_row).transpose()
}

/// JavaScript `parseInt` for the members limit (NaN when no leading digits)
fn js_parse_int(text: &str) -> Option<i64> {
    let trimmed = text.trim_start();
    let (negative, rest) = match trimmed.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, trimmed.strip_prefix('+').unwrap_or(trimmed)),
    };
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    digits.parse::<i64>().ok().map(|value| if negative { -value } else { value })
}

/// `GET /organization/get-full-organization`
async fn get_full(ctx: &mut Ctx<'_>) -> EndpointResult {
    validate::object(
        Some(&Value::Object(ctx.query.clone())),
        &[optional("organizationId", Ty::String), optional("organizationSlug", Ty::String)],
        "query",
        false,
    )?;
    let members_limit = match ctx.query.get("membersLimit") {
        None => None,
        Some(Value::String(text)) => js_parse_int(text),
        Some(_) => {
            return Err(ApiError::code(StatusCode::BAD_REQUEST, "VALIDATION_ERROR", "[query.membersLimit] Invalid input"));
        }
    };
    let session = require_session(ctx).await?;
    let slug = ctx.query_str("organizationSlug").filter(|s| !s.is_empty()).map(str::to_string);
    let lookup = slug
        .clone()
        .or_else(|| ctx.query_str("organizationId").filter(|s| !s.is_empty()).map(str::to_string))
        .or_else(|| session.session.active_organization_id.clone());
    let Some(lookup) = lookup else { return Ok(Reply::Json(Value::Null)) };
    let pg = &ctx.state.pg;
    let organization = if slug.is_some() { find_organization_by_slug(pg, &lookup).await? } else { find_organization(pg, &lookup).await? };
    let Some(organization) = organization else { return Err(organization_not_found()) };

    let invitations = sqlx::query(&format!(r#"SELECT {INVITATION_COLUMNS} FROM invitation WHERE "organizationId" = $1 LIMIT 100"#))
        .bind(&organization.id)
        .fetch_all(pg)
        .await?;
    let limit = members_limit.filter(|limit| *limit != 0).unwrap_or(100);
    let members = sqlx::query(&format!(r#"SELECT {MEMBER_COLUMNS} FROM member WHERE "organizationId" = $1 LIMIT $2"#))
        .bind(&organization.id)
        .bind(limit)
        .fetch_all(pg)
        .await?;
    let teams = sqlx::query(r#"SELECT id, name, "organizationId", "createdAt", "updatedAt" FROM team WHERE "organizationId" = $1 LIMIT 100"#)
        .bind(&organization.id)
        .fetch_all(pg)
        .await?;
    let members: Vec<Member> = members.iter().map(Member::from_row).collect::<Result<_, _>>()?;
    let user_ids: Vec<String> = members.iter().map(|member| member.user_id.clone()).collect();
    let mut users = Vec::new();
    if !user_ids.is_empty() {
        let rows = sqlx::query(r#"SELECT id, name, email, image FROM "user" WHERE id = ANY($1) LIMIT 100"#).bind(&user_ids).fetch_all(pg).await?;
        for row in rows {
            let id: String = row.try_get("id")?;
            let name: String = row.try_get("name")?;
            let email: String = row.try_get("email")?;
            let image: Option<String> = row.try_get("image")?;
            users.push((id, name, email, image));
        }
    }
    let mut members_json = Vec::new();
    for member in &members {
        let Some((id, name, email, image)) = users.iter().find(|(id, ..)| *id == member.user_id) else {
            error!(member_id = %member.id, "Unexpected error: User not found for member");
            return Err(ApiError::internal());
        };
        let mut map = member.to_json();
        map.insert("user".into(), json!({"id": id, "name": name, "email": email, "image": image}));
        members_json.push(Value::Object(map));
    }
    if find_member_row(pg, &session.user.id, &organization.id).await?.is_none() {
        set_active_organization(pg, &session.session.token, None).await?;
        return Err(org_error(StatusCode::FORBIDDEN, "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION", "User is not a member of the organization"));
    }
    let mut response = organization.to_json_with(MetadataOutput::Raw);
    let invitations: Vec<Value> =
        invitations.iter().map(Invitation::from_row).collect::<Result<Vec<_>, _>>()?.into_iter().map(|i| Value::Object(i.to_json())).collect();
    response.insert("invitations".into(), Value::Array(invitations));
    response.insert("members".into(), Value::Array(members_json));
    let teams: Vec<Value> = teams.iter().map(Team::from_row).collect::<Result<Vec<_>, _>>()?.into_iter().map(|t| t.to_json()).collect();
    response.insert("teams".into(), Value::Array(teams));
    Ok(Reply::Json(Value::Object(response)))
}

/// `GET /organization/list`
async fn list(ctx: &mut Ctx<'_>) -> EndpointResult {
    let session = require_session(ctx).await?;
    let organization_ids: Vec<String> = sqlx::query_scalar(r#"SELECT "organizationId" FROM member WHERE "userId" = $1 LIMIT 100"#)
        .bind(&session.user.id)
        .fetch_all(&ctx.state.pg)
        .await?;
    let mut organizations = Vec::new();
    for id in organization_ids {
        organizations.push(find_organization(&ctx.state.pg, &id).await?.map_or(Value::Null, |org| org.to_json()));
    }
    Ok(Reply::Json(Value::Array(organizations)))
}

/// `sendInvitationEmail` from auth.ts (the link is not URL-encoded)
async fn send_invitation(ctx: &Ctx<'_>, invitation: &Invitation, organization: &Organization, inviter_email: &str) {
    let base = ctx.state.config.base_url.clone().unwrap_or_else(|| "undefined".to_string());
    let link = format!(
        "{base}/invitation?invitationId={}&organization={}&inviterEmail={inviter_email}",
        invitation.id, organization.name
    );
    if let Err(err) = email::send_invitation_email(&ctx.state.config, &invitation.email, inviter_email, &organization.name, &link).await {
        error!(error = %err, "Failed to run background task");
    }
}

/// auth.ts `beforeCreateInvitation`: the site restriction fields to store
async fn invitation_site_restrictions(
    pg: &PgPool,
    restricted: Option<&Value>,
    role: &str,
    site_ids: Option<&Value>,
    organization_id: &str,
) -> Result<(bool, Vec<i64>), ApiError> {
    if restricted != Some(&Value::Bool(true)) {
        return Ok((false, Vec::new()));
    }
    if role != "member" {
        return Err(ApiError::message(StatusCode::BAD_REQUEST, "Site access restrictions can only be applied to member invitations"));
    }
    let mut unique: Vec<Value> = Vec::new();
    if let Some(Value::Array(ids)) = site_ids {
        for id in ids {
            if !unique.iter().any(|existing| same_value_zero(existing, id)) {
                unique.push(id.clone());
            }
        }
    }
    if unique.is_empty() {
        return Err(ApiError::message(StatusCode::BAD_REQUEST, "At least one site is required when restricting invitation access"));
    }
    let integers: Vec<i64> = unique.iter().filter_map(Value::as_f64).filter(|n| n.fract() == 0.0).map(|n| n as i64).collect();
    if integers.len() != unique.len() {
        // A fractional id reaches Postgres' integer comparison and fails there
        error!("Invitation site ids are not all integers");
        return Err(ApiError::internal());
    }
    let valid = site_ids_in_organization(pg, &integers, organization_id).await?;
    let invalid: Vec<String> = integers.iter().filter(|id| !valid.contains(id)).map(|id| id.to_string()).collect();
    if !invalid.is_empty() {
        return Err(ApiError::message(StatusCode::BAD_REQUEST, &format!("Sites do not belong to organization: {}", invalid.join(", "))));
    }
    Ok((true, integers))
}

/// `Set` membership for JSON numbers (SameValueZero)
fn same_value_zero(a: &Value, b: &Value) -> bool {
    match (a.as_f64(), b.as_f64()) {
        (Some(x), Some(y)) => x == y,
        _ => a == b,
    }
}

const INVITE_FIELDS: &[validate::Field] = &[
    required("email", Ty::String),
    required("role", Ty::StringOrStringArray),
    optional("organizationId", Ty::String),
    optional("resend", Ty::Boolean),
    optional("teamId", Ty::StringOrStringArray),
    nullish("hasRestrictedSiteAccess", Ty::Boolean),
    nullish("siteIds", Ty::ArrayOfNumbers),
];

/// `POST /organization/invite-member`
async fn invite_member(ctx: &mut Ctx<'_>) -> EndpointResult {
    validate::object(ctx.body.as_ref(), INVITE_FIELDS, "body", false)?;
    let body = ctx.body_object().cloned().unwrap_or_default();
    let session = require_session(ctx).await?;
    let pg = &ctx.state.pg;
    let organization_id = body
        .get("organizationId")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .map(str::to_string)
        .or_else(|| session.session.active_organization_id.clone());
    let Some(organization_id) = organization_id else { return Err(organization_not_found()) };
    let email = db::js_lowercase(body.get("email").and_then(Value::as_str).unwrap_or_default());
    if !validate::is_email(&email) {
        return Err(ApiError::code(StatusCode::BAD_REQUEST, "INVALID_EMAIL", "Invalid email"));
    }
    let Some((member, _)) = find_member_by_org(pg, &session.user.id, &organization_id).await? else {
        return Err(member_not_found());
    };
    if !has_permission(&member.role, Some(&permission("invitation", "create")), false) {
        return Err(org_error(
            StatusCode::FORBIDDEN,
            "YOU_ARE_NOT_ALLOWED_TO_INVITE_USERS_TO_THIS_ORGANIZATION",
            "You are not allowed to invite users to this organization",
        ));
    }
    let roles = match body.get("role") {
        Some(Value::Array(items)) => items.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(","),
        Some(Value::String(role)) => role.clone(),
        _ => String::new(),
    };
    let unknown: Vec<&str> =
        roles.split(',').map(str::trim).filter(|role| !role.is_empty()).filter(|role| !["admin", "owner", "member"].contains(role)).collect();
    if !unknown.is_empty() {
        return Err(ApiError::message(StatusCode::BAD_REQUEST, &format!("ROLE_NOT_FOUND: {}", unknown.join(", "))));
    }
    if !member.role.split(',').map(str::trim).any(|role| role == CREATOR_ROLE) && roles.split(',').any(|role| role == CREATOR_ROLE) {
        return Err(org_error(
            StatusCode::FORBIDDEN,
            "YOU_ARE_NOT_ALLOWED_TO_INVITE_USER_WITH_THIS_ROLE",
            "You are not allowed to invite a user with this role",
        ));
    }
    if find_member_by_email(pg, &email, &organization_id).await?.is_some() {
        return Err(org_error(StatusCode::BAD_REQUEST, "USER_IS_ALREADY_A_MEMBER_OF_THIS_ORGANIZATION", "User is already a member of this organization"));
    }
    let pending = pending_invitations(pg, &organization_id, Some(&email)).await?;
    let resend = body.get("resend") == Some(&Value::Bool(true));
    if !pending.is_empty() && !resend {
        return Err(org_error(StatusCode::BAD_REQUEST, "USER_IS_ALREADY_INVITED_TO_THIS_ORGANIZATION", "User is already invited to this organization"));
    }
    let Some(organization) = find_organization(pg, &organization_id).await? else { return Err(organization_not_found()) };
    if let Some(existing) = pending.first().filter(|_| resend) {
        let expires_at = db::in_seconds(INVITATION_EXPIRES_IN);
        sqlx::query(r#"UPDATE invitation SET "expiresAt" = $1 WHERE id = $2"#).bind(expires_at).bind(&existing.id).execute(pg).await?;
        let mut updated = existing.clone();
        updated.expires_at = expires_at;
        send_invitation(ctx, &updated, &organization, &session.user.email).await;
        info!(organization_id = %organization_id, "Invitation resent");
        return Ok(Reply::Json(Value::Object(updated.to_json())));
    }
    if pending_invitations(pg, &organization_id, None).await?.len() >= INVITATION_LIMIT {
        return Err(org_error(StatusCode::FORBIDDEN, "INVITATION_LIMIT_REACHED", "Invitation limit reached"));
    }
    let team_ids: Vec<String> = match body.get("teamId") {
        Some(Value::String(id)) => vec![id.clone()],
        Some(Value::Array(items)) => items.iter().filter_map(Value::as_str).map(str::to_string).collect(),
        _ => Vec::new(),
    };
    if truthy(body.get("teamId")) {
        if team_ids.iter().any(|id| id.contains(',')) {
            return Err(org_error(StatusCode::BAD_REQUEST, "INVALID_TEAM_ID", "Team id contains a reserved character"));
        }
        for team_id in &team_ids {
            if find_team(pg, team_id, &organization_id).await?.is_none() {
                return Err(org_error(StatusCode::BAD_REQUEST, "TEAM_NOT_FOUND", "Team not found"));
            }
        }
    }
    let (restricted, site_ids) =
        invitation_site_restrictions(pg, body.get("hasRestrictedSiteAccess"), &roles, body.get("siteIds"), &organization_id).await?;
    let now = db::now_ms();
    let row = sqlx::query(&format!(
        r#"INSERT INTO invitation (id, "organizationId", email, role, "teamId", status, "expiresAt", "createdAt", "inviterId", has_restricted_site_access, site_ids)
           VALUES ($1, $2, $3, $4, $5, 'pending', $6, $7, $8, $9, $10::jsonb) RETURNING {INVITATION_COLUMNS}"#
    ))
    .bind(crypto::generate_id())
    .bind(&organization_id)
    .bind(&email)
    .bind(&roles)
    .bind((!team_ids.is_empty()).then(|| team_ids.join(",")))
    .bind(db::in_seconds(INVITATION_EXPIRES_IN))
    .bind(now)
    .bind(&session.user.id)
    .bind(restricted)
    .bind(crate::js_json::stringify(&json!(site_ids)))
    .fetch_one(pg)
    .await?;
    let invitation = Invitation::from_row(&row)?;
    send_invitation(ctx, &invitation, &organization, &session.user.email).await;
    info!(organization_id = %organization_id, restricted, "Invitation created");
    Ok(Reply::Json(Value::Object(invitation.to_json())))
}

/// `findPendingInvitation(s)`: pending and not yet expired
async fn pending_invitations(pg: &PgPool, organization_id: &str, email: Option<&str>) -> Result<Vec<Invitation>, sqlx::Error> {
    let rows = match email {
        Some(email) => {
            sqlx::query(&format!(
                r#"SELECT {INVITATION_COLUMNS} FROM invitation WHERE email = $1 AND "organizationId" = $2 AND status = 'pending' LIMIT 100"#
            ))
            .bind(email)
            .bind(organization_id)
            .fetch_all(pg)
            .await?
        }
        None => {
            sqlx::query(&format!(
                r#"SELECT {INVITATION_COLUMNS} FROM invitation WHERE "organizationId" = $1 AND status = 'pending' LIMIT 100"#
            ))
            .bind(organization_id)
            .fetch_all(pg)
            .await?
        }
    };
    let invitations: Vec<Invitation> = rows.iter().map(Invitation::from_row).collect::<Result<_, _>>()?;
    Ok(invitations.into_iter().filter(|invitation| !db::is_past(invitation.expires_at) && db::ms(invitation.expires_at) != db::now_ms()).collect())
}

/// `POST /organization/cancel-invitation`
async fn cancel_invitation(ctx: &mut Ctx<'_>) -> EndpointResult {
    validate::object(ctx.body.as_ref(), &[required("invitationId", Ty::String)], "body", false)?;
    let session = require_session(ctx).await?;
    let pg = &ctx.state.pg;
    let id = ctx.body_str("invitationId").unwrap_or_default().to_string();
    let Some(invitation) = find_invitation(pg, &id).await? else {
        return Err(org_error(StatusCode::BAD_REQUEST, "INVITATION_NOT_FOUND", "Invitation not found"));
    };
    let Some((member, _)) = find_member_by_org(pg, &session.user.id, &invitation.organization_id).await? else {
        return Err(member_not_found());
    };
    if !has_permission(&member.role, Some(&permission("invitation", "cancel")), false) {
        return Err(org_error(StatusCode::FORBIDDEN, "YOU_ARE_NOT_ALLOWED_TO_CANCEL_THIS_INVITATION", "You are not allowed to cancel this invitation"));
    }
    if find_organization(pg, &invitation.organization_id).await?.is_none() {
        return Err(organization_not_found());
    }
    let canceled = set_invitation_status(pg, &id, "canceled", None).await?;
    info!(invitation_id = %id, "Invitation canceled");
    Ok(Reply::Json(canceled.map_or(Value::Null, |i| Value::Object(i.to_json()))))
}

/// `POST /organization/accept-invitation`
async fn accept_invitation(ctx: &mut Ctx<'_>) -> EndpointResult {
    validate::object(ctx.body.as_ref(), &[required("invitationId", Ty::String)], "body", false)?;
    let session = require_session(ctx).await?;
    let pg = &ctx.state.pg;
    let id = ctx.body_str("invitationId").unwrap_or_default().to_string();
    let not_found = || org_error(StatusCode::BAD_REQUEST, "INVITATION_NOT_FOUND", "Invitation not found");
    let Some(invitation) = find_invitation(pg, &id).await? else { return Err(not_found()) };
    if db::is_past(invitation.expires_at) || invitation.status != "pending" {
        return Err(not_found());
    }
    if db::js_lowercase(&invitation.email) != db::js_lowercase(&session.user.email) {
        return Err(org_error(StatusCode::FORBIDDEN, "YOU_ARE_NOT_THE_RECIPIENT_OF_THE_INVITATION", "You are not the recipient of the invitation"));
    }
    let members: i64 = sqlx::query_scalar(r#"SELECT count(id) FROM member WHERE "organizationId" = $1"#)
        .bind(&invitation.organization_id)
        .fetch_one(pg)
        .await?;
    if find_organization(pg, &invitation.organization_id).await?.is_none() {
        return Err(organization_not_found());
    }
    if members >= MEMBERSHIP_LIMIT {
        return Err(org_error(StatusCode::FORBIDDEN, "ORGANIZATION_MEMBERSHIP_LIMIT_REACHED", "Organization membership limit reached"));
    }
    let Some(accepted) = set_invitation_status(pg, &id, "accepted", Some("pending")).await? else {
        return Err(not_found());
    };

    let outcome: Result<Member, ApiError> = async {
        if let Some(team_field) = accepted.team_id.as_deref().filter(|t| !t.is_empty()) {
            let team_ids: Vec<&str> = team_field.split(',').collect();
            for team_id in &team_ids {
                if find_team(pg, team_id, &accepted.organization_id).await?.is_none() {
                    return Err(org_error(StatusCode::BAD_REQUEST, "TEAM_NOT_FOUND", "Team not found"));
                }
                find_or_create_team_member(pg, team_id, &session.user.id).await?;
            }
            if team_ids.len() == 1 {
                let updated = db::update_session(pg, &session.session.token, SessionField::ActiveTeamId(Some(team_ids[0].to_string())))
                    .await?
                    .ok_or_else(ApiError::internal)?;
                ctx.set_session_cookie(&SessionWithUser { session: updated, user: session.user.clone() }, None, None);
            }
        }
        let member = create_member(pg, &accepted.organization_id, &session.user.id, &accepted.role).await?;
        set_active_organization(pg, &session.session.token, Some(&accepted.organization_id)).await?;
        Ok(member)
    }
    .await;
    let member = match outcome {
        Ok(member) => member,
        Err(err) => {
            set_invitation_status(pg, &id, "pending", None).await?;
            warn!(invitation_id = %id, "Invitation acceptance failed; status restored");
            return Err(err);
        }
    };
    info!(invitation_id = %id, user_id = %session.user.id, "Invitation accepted");
    Ok(Reply::Json(json!({"invitation": Value::Object(accepted.to_json()), "member": Value::Object(member.to_json())})))
}

/// `GET /organization/get-invitation?id=`
async fn get_invitation(ctx: &mut Ctx<'_>) -> EndpointResult {
    validate::object(Some(&Value::Object(ctx.query.clone())), &[required("id", Ty::String)], "query", false)?;
    let Some(session) = session_from_ctx(ctx).await else {
        return Err(ApiError::message(StatusCode::UNAUTHORIZED, "Not authenticated"));
    };
    let pg = &ctx.state.pg;
    let id = ctx.query_str("id").unwrap_or_default().to_string();
    let invitation = find_invitation(pg, &id).await?;
    let Some(invitation) = invitation.filter(|i| i.status == "pending" && !db::is_past(i.expires_at)) else {
        return Err(ApiError::message(StatusCode::BAD_REQUEST, "Invitation not found!"));
    };
    if db::js_lowercase(&invitation.email) != db::js_lowercase(&session.user.email) {
        return Err(org_error(StatusCode::FORBIDDEN, "YOU_ARE_NOT_THE_RECIPIENT_OF_THE_INVITATION", "You are not the recipient of the invitation"));
    }
    let Some(organization) = find_organization(pg, &invitation.organization_id).await? else { return Err(organization_not_found()) };
    let inviter = match &invitation.inviter_id {
        Some(inviter) => find_member_by_org(pg, inviter, &invitation.organization_id).await?,
        None => None,
    };
    let Some((_, inviter_user)) = inviter else {
        return Err(org_error(
            StatusCode::BAD_REQUEST,
            "INVITER_IS_NO_LONGER_A_MEMBER_OF_THE_ORGANIZATION",
            "Inviter is no longer a member of the organization",
        ));
    };
    let mut response = invitation.to_json();
    response.insert("organizationName".into(), Value::from(organization.name));
    response.insert("organizationSlug".into(), Value::from(organization.slug));
    response.insert("inviterEmail".into(), Value::from(inviter_user.email));
    Ok(Reply::Json(Value::Object(response)))
}

/// `POST /organization/reject-invitation`
async fn reject_invitation(ctx: &mut Ctx<'_>) -> EndpointResult {
    validate::object(ctx.body.as_ref(), &[required("invitationId", Ty::String)], "body", false)?;
    let session = require_session(ctx).await?;
    let pg = &ctx.state.pg;
    let id = ctx.body_str("invitationId").unwrap_or_default().to_string();
    let invitation = find_invitation(pg, &id).await?;
    let Some(invitation) = invitation.filter(|i| i.status == "pending") else {
        return Err(org_error(StatusCode::BAD_REQUEST, "INVITATION_NOT_FOUND", "Invitation not found!"));
    };
    if db::js_lowercase(&invitation.email) != db::js_lowercase(&session.user.email) {
        return Err(org_error(StatusCode::FORBIDDEN, "YOU_ARE_NOT_THE_RECIPIENT_OF_THE_INVITATION", "You are not the recipient of the invitation"));
    }
    if find_organization(pg, &invitation.organization_id).await?.is_none() {
        return Err(organization_not_found());
    }
    let rejected = set_invitation_status(pg, &id, "rejected", None).await?;
    info!(invitation_id = %id, "Invitation rejected");
    Ok(Reply::Json(json!({"invitation": rejected.map_or(Value::Null, |i| Value::Object(i.to_json())), "member": null})))
}

/// `GET /organization/list-invitations[?organizationId=]`
async fn list_invitations(ctx: &mut Ctx<'_>) -> EndpointResult {
    validate::object(Some(&Value::Object(ctx.query.clone())), &[optional("organizationId", Ty::String)], "query", false)?;
    let session = require_session(ctx).await?;
    let organization_id = ctx
        .query_str("organizationId")
        .filter(|id| !id.is_empty())
        .map(str::to_string)
        .or_else(|| session.session.active_organization_id.clone());
    let Some(organization_id) = organization_id else {
        return Err(ApiError::message(StatusCode::BAD_REQUEST, "Organization ID is required"));
    };
    if find_member_by_org(&ctx.state.pg, &session.user.id, &organization_id).await?.is_none() {
        return Err(ApiError::message(StatusCode::FORBIDDEN, "You are not a member of this organization"));
    }
    let rows = sqlx::query(&format!(r#"SELECT {INVITATION_COLUMNS} FROM invitation WHERE "organizationId" = $1 LIMIT 100"#))
        .bind(&organization_id)
        .fetch_all(&ctx.state.pg)
        .await?;
    let invitations: Vec<Value> =
        rows.iter().map(Invitation::from_row).collect::<Result<Vec<_>, _>>()?.into_iter().map(|i| Value::Object(i.to_json())).collect();
    Ok(Reply::Json(Value::Array(invitations)))
}

/// `GET /organization/get-active-member`
async fn get_active_member(ctx: &mut Ctx<'_>) -> EndpointResult {
    let session = require_session(ctx).await?;
    let Some(organization_id) = session.session.active_organization_id.clone() else {
        return Err(org_error(StatusCode::BAD_REQUEST, "NO_ACTIVE_ORGANIZATION", "No active organization"));
    };
    let Some((member, user)) = find_member_by_org(&ctx.state.pg, &session.user.id, &organization_id).await? else {
        return Err(member_not_found());
    };
    Ok(Reply::Json(member.with_user(&user)))
}

/// `POST /organization/check-slug`
async fn check_slug(ctx: &mut Ctx<'_>) -> EndpointResult {
    validate::object(ctx.body.as_ref(), &[required("slug", Ty::String)], "body", false)?;
    require_session(ctx).await?;
    let slug = ctx.body_str("slug").unwrap_or_default().to_string();
    if find_organization_by_slug(&ctx.state.pg, &slug).await?.is_none() {
        return Ok(Reply::Json(json!({"status": true})));
    }
    Err(org_error(StatusCode::BAD_REQUEST, "ORGANIZATION_SLUG_ALREADY_TAKEN", "Organization slug already taken"))
}

/// `POST /organization/remove-member`, then auth.ts's `afterRemoveMember`
async fn remove_member(ctx: &mut Ctx<'_>) -> EndpointResult {
    validate::object(ctx.body.as_ref(), &[required("memberIdOrEmail", Ty::String), optional("organizationId", Ty::String)], "body", false)?;
    let session = require_session(ctx).await?;
    let state = ctx.state;
    let pg = &state.pg;
    let organization_id = ctx
        .body_str("organizationId")
        .filter(|id| !id.is_empty())
        .map(str::to_string)
        .or_else(|| session.session.active_organization_id.clone());
    let Some(organization_id) = organization_id else {
        return Err(org_error(StatusCode::BAD_REQUEST, "NO_ACTIVE_ORGANIZATION", "No active organization"));
    };
    let Some((member, _)) = find_member_by_org(pg, &session.user.id, &organization_id).await? else {
        return Err(member_not_found());
    };
    let target = ctx.body_str("memberIdOrEmail").unwrap_or_default().to_string();
    let (removed, removed_json) = if target.contains('@') {
        match find_member_by_email(pg, &target, &organization_id).await? {
            Some((found, user)) => {
                let json = found.with_user(&user);
                (found, json)
            }
            None => return Err(member_not_found()),
        }
    } else {
        match find_member_by_id(pg, &target).await? {
            Some((found, _)) => {
                let json = Value::Object(found.to_json());
                (found, json)
            }
            None => return Err(member_not_found()),
        }
    };
    if removed.role.split(',').any(|role| role == CREATOR_ROLE) {
        let removing_owner_allowed = member.role.split(',').map(str::trim).any(|role| role == CREATOR_ROLE);
        let owners = list_org_members(pg, &organization_id).await?.iter().filter(|m| m.role.split(',').any(|r| r == CREATOR_ROLE)).count();
        if !removing_owner_allowed || owners <= 1 {
            return Err(org_error(StatusCode::BAD_REQUEST, "YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER", "You cannot leave the organization as the only owner"));
        }
    }
    if !has_permission(&member.role, Some(&permission("member", "delete")), false) {
        return Err(org_error(StatusCode::UNAUTHORIZED, "YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_MEMBER", "You are not allowed to delete this member"));
    }
    if removed.organization_id != organization_id {
        return Err(member_not_found());
    }
    if find_organization(pg, &organization_id).await?.is_none() {
        return Err(organization_not_found());
    }
    let Some(removed_user) = db::find_user_by_id(pg, &removed.user_id).await? else {
        return Err(ApiError::message(StatusCode::BAD_REQUEST, "User not found"));
    };
    delete_member(pg, &removed.id, &organization_id, &removed.user_id).await?;
    if session.user.id == removed.user_id && session.session.active_organization_id.as_deref() == Some(removed.organization_id.as_str()) {
        set_active_organization(pg, &session.session.token, None).await?;
    }
    // afterRemoveMember (auth.ts): stale invitations can't recreate access
    if let Err(err) = sqlx::query(r#"DELETE FROM invitation WHERE email = $1 AND "organizationId" = $2"#)
        .bind(&removed_user.email)
        .bind(&organization_id)
        .execute(pg)
        .await
    {
        error!(error = %err, organization_id = %organization_id, "Error deleting invitations for removed member");
    }
    state.sites_access.invalidate_user(&removed.user_id);
    info!(organization_id = %organization_id, removed_user_id = %removed.user_id, "Member removed");
    Ok(Reply::Json(json!({"member": removed_json})))
}

/// `POST /organization/update-member-role`
async fn update_member_role(ctx: &mut Ctx<'_>) -> EndpointResult {
    validate::object(
        ctx.body.as_ref(),
        &[required("role", Ty::StringOrStringArray), required("memberId", Ty::String), optional("organizationId", Ty::String)],
        "body",
        false,
    )?;
    let session = require_session(ctx).await?;
    let pg = &ctx.state.pg;
    let body = ctx.body_object().cloned().unwrap_or_default();
    if !truthy(body.get("role")) {
        return Err(ApiError::status(StatusCode::BAD_REQUEST));
    }
    let organization_id = body
        .get("organizationId")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .map(str::to_string)
        .or_else(|| session.session.active_organization_id.clone());
    let Some(organization_id) = organization_id else {
        return Err(org_error(StatusCode::BAD_REQUEST, "NO_ACTIVE_ORGANIZATION", "No active organization"));
    };
    let requested: Vec<String> = match body.get("role") {
        Some(Value::Array(items)) => items.iter().filter_map(Value::as_str).map(str::to_string).collect(),
        Some(Value::String(role)) => vec![role.clone()],
        _ => Vec::new(),
    };
    let role_to_set: Vec<String> =
        requested.iter().flat_map(|role| role.split(',')).map(|role| role.trim().to_string()).filter(|role| !role.is_empty()).collect();
    if role_to_set.is_empty() {
        return Err(ApiError::status(StatusCode::BAD_REQUEST));
    }
    let unknown: Vec<&str> = role_to_set.iter().map(String::as_str).filter(|role| !["admin", "owner", "member"].contains(role)).collect();
    if !unknown.is_empty() {
        return Err(ApiError::body(
            StatusCode::BAD_REQUEST,
            json!({"code": "ROLE_NOT_FOUND", "message": format!("ROLE_NOT_FOUND: {}", unknown.join(", "))}),
        ));
    }
    let member_id = body.get("memberId").and_then(Value::as_str).unwrap_or_default().to_string();
    let Some((member, _)) = find_member_by_org(pg, &session.user.id, &organization_id).await? else {
        return Err(member_not_found());
    };
    let target = if member.id != member_id {
        match find_member_by_id(pg, &member_id).await? {
            Some((found, _)) => found,
            None => return Err(member_not_found()),
        }
    } else {
        member.clone()
    };
    let forbidden = || org_error(StatusCode::FORBIDDEN, "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_MEMBER", "You are not allowed to update this member");
    if target.organization_id != organization_id {
        return Err(forbidden());
    }
    let updater_is_creator = member.role.split(',').any(|role| role == CREATOR_ROLE);
    let updating_creator = target.role.split(',').any(|role| role == CREATOR_ROLE);
    let setting_creator = role_to_set.iter().any(|role| role == CREATOR_ROLE);
    if (updating_creator || setting_creator) && !updater_is_creator {
        return Err(forbidden());
    }
    if updater_is_creator && member.id == target.id {
        let owners = sqlx::query_scalar::<_, String>(r#"SELECT role FROM member WHERE "organizationId" = $1 LIMIT 100"#)
            .bind(&organization_id)
            .fetch_all(pg)
            .await?
            .iter()
            .filter(|role| role.split(',').any(|r| r == CREATOR_ROLE))
            .count();
        if owners <= 1 && !setting_creator {
            return Err(org_error(
                StatusCode::BAD_REQUEST,
                "YOU_CANNOT_LEAVE_THE_ORGANIZATION_WITHOUT_AN_OWNER",
                "You cannot leave the organization without an owner",
            ));
        }
    }
    if !has_permission(&member.role, Some(&permission("member", "update")), true) {
        return Err(forbidden());
    }
    if find_organization(pg, &organization_id).await?.is_none() {
        return Err(organization_not_found());
    }
    if db::find_user_by_id(pg, &target.user_id).await?.is_none() {
        return Err(ApiError::message(StatusCode::BAD_REQUEST, "User not found"));
    }
    let row = sqlx::query(&format!("UPDATE member SET role = $1 WHERE id = $2 RETURNING {MEMBER_COLUMNS}"))
        .bind(role_to_set.join(","))
        .bind(&member_id)
        .fetch_optional(pg)
        .await?;
    let Some(updated) = row.as_ref().map(Member::from_row).transpose()? else { return Err(member_not_found()) };
    info!(organization_id = %organization_id, member_id = %member_id, "Member role updated");
    Ok(Reply::Json(Value::Object(updated.to_json())))
}

/// `POST /organization/leave` (cleanup in `app_after_hook`)
async fn leave(ctx: &mut Ctx<'_>) -> EndpointResult {
    validate::object(ctx.body.as_ref(), &[required("organizationId", Ty::String)], "body", false)?;
    let session = require_session(ctx).await?;
    let pg = &ctx.state.pg;
    let organization_id = ctx.body_str("organizationId").unwrap_or_default().to_string();
    let Some((member, user)) = find_member_by_org(pg, &session.user.id, &organization_id).await? else {
        return Err(member_not_found());
    };
    if member.role.split(',').any(|role| role == CREATOR_ROLE) {
        let owners = list_org_members(pg, &organization_id).await?.iter().filter(|m| m.role.split(',').any(|r| r == CREATOR_ROLE)).count();
        if owners <= 1 {
            return Err(org_error(StatusCode::BAD_REQUEST, "YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER", "You cannot leave the organization as the only owner"));
        }
    }
    delete_member(pg, &member.id, &organization_id, &session.user.id).await?;
    if session.session.active_organization_id.as_deref() == Some(organization_id.as_str()) {
        set_active_organization(pg, &session.session.token, None).await?;
    }
    info!(organization_id = %organization_id, user_id = %session.user.id, "Left organization");
    Ok(Reply::Json(member.with_user(&user)))
}

/// `GET /organization/list-user-invitations`
async fn list_user_invitations(ctx: &mut Ctx<'_>) -> EndpointResult {
    validate::object(Some(&Value::Object(ctx.query.clone())), &[optional("email", Ty::String)], "query", false)?;
    let session = session_from_ctx(ctx).await;
    if truthy(ctx.query.get("email")) {
        return Err(ApiError::message(StatusCode::BAD_REQUEST, "User email cannot be passed for client side API calls."));
    }
    if let Some(session) = &session
        && !session.user.email_verified
    {
        return Err(org_error(
            StatusCode::FORBIDDEN,
            "EMAIL_VERIFICATION_REQUIRED_FOR_INVITATION",
            "Email verification required to view or list invitations for the session email",
        ));
    }
    let Some(session) = session else {
        return Err(ApiError::message(StatusCode::BAD_REQUEST, "Missing session headers, or email query parameter."));
    };
    let pg = &ctx.state.pg;
    let rows = sqlx::query(&format!("SELECT {INVITATION_COLUMNS} FROM invitation WHERE email = $1 LIMIT 100"))
        .bind(db::js_lowercase(&session.user.email))
        .fetch_all(pg)
        .await?;
    let mut listed = Vec::new();
    for invitation in rows.iter().map(Invitation::from_row).collect::<Result<Vec<_>, _>>()? {
        if invitation.status != "pending" {
            continue;
        }
        let name = find_organization(pg, &invitation.organization_id).await?.map(|org| org.name);
        let mut map = invitation.to_json();
        if let Some(name) = name {
            map.insert("organizationName".into(), Value::from(name));
        }
        listed.push(Value::Object(map));
    }
    Ok(Reply::Json(Value::Array(listed)))
}

/// `POST /organization/has-permission`
async fn has_permission_endpoint(ctx: &mut Ctx<'_>) -> EndpointResult {
    validate::object_and_permission_xor(ctx.body.as_ref(), &[optional("organizationId", Ty::String)])?;
    let session = require_session(ctx).await?;
    let organization_id = ctx
        .body_str("organizationId")
        .filter(|id| !id.is_empty())
        .map(str::to_string)
        .or_else(|| session.session.active_organization_id.clone());
    let Some(organization_id) = organization_id else {
        return Err(org_error(StatusCode::BAD_REQUEST, "NO_ACTIVE_ORGANIZATION", "No active organization"));
    };
    let Some((member, _)) = find_member_by_org(&ctx.state.pg, &session.user.id, &organization_id).await? else {
        return Err(org_error(StatusCode::UNAUTHORIZED, "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION", "User is not a member of the organization"));
    };
    let permissions = ctx.body_object().and_then(|b| b.get("permissions")).and_then(Value::as_object).cloned();
    let success = has_permission(&member.role, permissions.as_ref(), false);
    Ok(Reply::Json(json!({"error": null, "success": success})))
}

/// server/src/lib/auth.ts `hooks.after`: after `/organization/accept-invitation`,
/// restrict the new member to the invitation's sites (flag first, fail safe).
/// Errors are logged, never surfaced.
///
/// The same hook's `/organization/leave` branch never fires in Node: the
/// organization plugin wraps its endpoints in `shimContext`, which copies
/// `ctx.context`, so the session the endpoint resolves is not visible to after
/// hooks and `ctx.context.session` is always null there. Leaving therefore keeps
/// the user's invitations; this port does the same (see AUTH_COMPAT.md).
pub async fn app_after_hook(ctx: &mut Ctx<'_>, endpoint: Endpoint, result: EndpointResult) -> EndpointResult {
    if endpoint == Endpoint::Organization(Route::AcceptInvitation)
        && let Some(invitation_id) = ctx.body_str("invitationId").filter(|id| !id.is_empty()).map(str::to_string)
        && let Err(err) = copy_invitation_site_access(ctx, &invitation_id).await
    {
        error!(error = %err, "Error applying invitation Site restrictions");
    }
    if endpoint == Endpoint::Organization(Route::Leave) {
        debug!("Leave cleanup hook skipped: Node's never sees the session");
    }
    result
}

async fn copy_invitation_site_access(ctx: &Ctx<'_>, invitation_id: &str) -> Result<(), sqlx::Error> {
    let pg = &ctx.state.pg;
    let Some(row) = sqlx::query(r#"SELECT "organizationId", email, has_restricted_site_access, site_ids FROM invitation WHERE id = $1 LIMIT 1"#)
        .bind(invitation_id)
        .fetch_optional(pg)
        .await?
    else {
        return Ok(());
    };
    let organization_id: String = row.try_get("organizationId")?;
    let email: String = row.try_get("email")?;
    let restricted: bool = row.try_get("has_restricted_site_access")?;
    let site_ids: Option<Value> = row.try_get("site_ids")?;
    if !restricted {
        return Ok(());
    }
    let Some(user_id) = sqlx::query_scalar::<_, String>(r#"SELECT id FROM "user" WHERE email = $1 LIMIT 1"#).bind(&email).fetch_optional(pg).await?
    else {
        return Ok(());
    };
    let Some(member_id) =
        sqlx::query_scalar::<_, String>(r#"SELECT id FROM member WHERE "organizationId" = $1 AND "userId" = $2 LIMIT 1"#)
            .bind(&organization_id)
            .bind(&user_id)
            .fetch_optional(pg)
            .await?
    else {
        return Ok(());
    };
    sqlx::query("UPDATE member SET has_restricted_site_access = true WHERE id = $1").bind(&member_id).execute(pg).await?;
    let invited: Vec<i64> = match site_ids {
        Some(Value::Array(ids)) => ids.iter().filter_map(Value::as_i64).collect(),
        _ => Vec::new(),
    };
    let grantable = site_ids_in_organization(pg, &invited, &organization_id).await?;
    if grantable.len() != invited.len() {
        let dropped: Vec<i64> = invited.iter().filter(|id| !grantable.contains(id)).copied().collect();
        warn!(organization_id = %organization_id, member_id = %member_id, dropped_site_ids = ?dropped,
            "Invitation named sites the organization no longer owns; those grants were dropped");
    }
    if !grantable.is_empty() {
        let mut query = String::from("INSERT INTO member_site_access (member_id, site_id) VALUES ");
        let values: Vec<String> = (0..grantable.len()).map(|i| format!("($1, ${})", i + 2)).collect();
        query.push_str(&values.join(", "));
        let mut insert = sqlx::query(&query).bind(&member_id);
        for id in &grantable {
            insert = insert.bind(*id as i32);
        }
        insert.execute(pg).await?;
    }
    ctx.state.sites_access.invalidate_user(&user_id);
    info!(member_id = %member_id, sites = grantable.len(), "Invitation site restrictions applied");
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn request(value: Value) -> Map<String, Value> {
        value.as_object().unwrap().clone()
    }

    #[test]
    fn organization_roles_follow_auth_ts() {
        assert!(has_permission("owner", Some(&request(json!({"organization": ["delete"]}))), false));
        assert!(!has_permission("admin", Some(&request(json!({"organization": ["delete"]}))), false));
        assert!(has_permission("admin", Some(&request(json!({"apiKey": ["read", "delete"]}))), false));
        assert!(!has_permission("member", Some(&request(json!({"apiKey": ["read"]}))), false));
        assert!(has_permission("member", Some(&request(json!({"ac": ["read"]}))), false));
        assert!(!has_permission("member", Some(&request(json!({"organization": ["update"]}))), false));
        assert!(has_permission("member,admin", Some(&request(json!({"invitation": ["create"]}))), false));
        assert!(!has_permission("owner", Some(&request(json!({}))), false));
        assert!(!has_permission("owner", Some(&request(json!({"nope": ["read"]}))), false));
        assert!(!has_permission("owner", None, false));
        assert!(has_permission("owner", Some(&request(json!({"nope": ["read"]}))), true));
    }

    #[test]
    fn js_parse_int_matches_javascript() {
        assert_eq!(js_parse_int("10abc"), Some(10));
        assert_eq!(js_parse_int(" -3"), Some(-3));
        assert_eq!(js_parse_int("abc"), None);
    }

    #[test]
    fn metadata_parsing() {
        let org = |metadata: Option<&str>| Organization {
            id: "o".into(),
            name: "n".into(),
            slug: "s".into(),
            logo: None,
            created_at: db::now_ms(),
            metadata: metadata.map(str::to_string),
            stripe_customer_id: None,
            monthly_event_count: None,
            over_monthly_limit: None,
            plan_override: None,
        };
        let better = |metadata: Option<&str>| org(metadata).to_json_with(MetadataOutput::BetterJson).get("metadata").cloned();
        assert_eq!(better(Some("null")), Some(Value::Null));
        assert_eq!(better(Some("undefined")), None);
        assert_eq!(better(None), None);
        assert_eq!(better(Some("{\"a\":\"2024-01-01T00:00:00Z\"}")), Some(json!({"a": "2024-01-01T00:00:00.000Z"})));
        assert!(org(Some("not json")).better_json_metadata_error().is_some());
        assert!(org(Some("{\"a\":1}")).better_json_metadata_error().is_none());
    }
}
