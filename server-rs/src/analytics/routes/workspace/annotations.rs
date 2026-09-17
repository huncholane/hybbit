//! Timeline annotations, ported from server/src/api/analytics/annotations
//! (getAnnotations, createAnnotation, updateAnnotation, deleteAnnotation and
//! annotationAccess).
//!
//! Timestamps: drizzle maps these columns with `mode: "string"` over postgres-js,
//! so Node sees Postgres's text output (`2026-08-18 07:00:00+00`) and writes ISO
//! strings; Rust reads `::text` and binds the same strings with explicit casts.

use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri},
    response::Response,
};
use sqlx::{PgPool, Row, postgres::PgRow};
use tracing::{debug, error, info};

use super::{
    access::RequestAccess,
    annotation_schema::{self, AnnotationScope},
    luxon,
    request::{self, object, pg_int},
    schema::{Field, validation_error_body},
};
use crate::{
    analytics::{
        chain::{ChainSteps, SiteGuard, route_scope, site_scoped},
        js::{JsValue, date, number::parse_int_10},
        utils::time_window::{is_valid_time_zone, now_ms},
    },
    state::AppState,
};

/// `annotationAccess.parseSiteId` / `parseAnnotationId`: `parseInt(raw, 10)`,
/// positive or nothing.
fn parse_positive(raw: &str) -> Option<f64> {
    let id = parse_int_10(raw);
    (!id.is_nan() && id > 0.0).then_some(id)
}

/// A Postgres failure inside the handler's `try`.
#[derive(Debug, thiserror::Error)]
enum HandlerError {
    #[error(transparent)]
    Db(#[from] sqlx::Error),
    /// A `parseInt` result past int4 that Postgres would refuse
    #[error("integer out of range for type integer")]
    OutOfRange,
}

fn bind_int(id: f64) -> Result<i32, HandlerError> {
    pg_int(id).ok_or(HandlerError::OutOfRange)
}

/// `getSiteOrganizationId`
async fn site_organization_id(pg: &PgPool, site_id: f64) -> Result<Option<String>, HandlerError> {
    let organization: Option<Option<String>> =
        sqlx::query_scalar(r#"select "organization_id" from "sites" where "sites"."site_id" = $1 limit 1"#)
            .bind(bind_int(site_id)?)
            .fetch_optional(pg)
            .await?;
    Ok(organization.flatten())
}

/// The columns `db.query.annotations.findFirst` reads, as Node sees them.
struct AnnotationRow {
    site_id: Option<i32>,
    organization_id: String,
    user_id: Option<String>,
    date: String,
    end_date: Option<String>,
}

async fn find_annotation(pg: &PgPool, annotation_id: f64) -> Result<Option<AnnotationRow>, HandlerError> {
    let row = sqlx::query(
        r#"select "site_id", "organization_id", "user_id", "date"::text as "date", "end_date"::text as "end_date"
           from "annotations" where "annotations"."annotation_id" = $1 limit 1"#,
    )
    .bind(bind_int(annotation_id)?)
    .fetch_optional(pg)
    .await?;
    row.map(|row| {
        Ok(AnnotationRow {
            site_id: row.try_get("site_id")?,
            organization_id: row.try_get("organization_id")?,
            user_id: row.try_get("user_id")?,
            date: row.try_get("date")?,
            end_date: row.try_get("end_date")?,
        })
    })
    .transpose()
    .map_err(HandlerError::Db)
}

/// `annotationBelongsToSite`
fn belongs_to_site(row: &AnnotationRow, site_id: f64, organization_id: &str) -> bool {
    row.site_id.is_some_and(|id| f64::from(id) == site_id) || (row.site_id.is_none() && row.organization_id == organization_id)
}

/// `canManageAnnotation`: admins manage everything on their sites; members only
/// what they created, and never organization-wide annotations.
async fn can_manage(access: &RequestAccess<'_>, site_id: f64, row: &AnnotationRow) -> bool {
    if access.has_site(site_id, true).await {
        return true;
    }
    if row.site_id.is_none() {
        return false;
    }
    match access.user_id() {
        Some(user_id) if !user_id.is_empty() => row.user_id.as_deref() == Some(user_id),
        _ => false,
    }
}

/// timestamptz text to ISO 8601 (`toIso` in getAnnotations.ts): through the
/// Date parser, else the value as it came.
fn to_iso(value: &str) -> String {
    if value.is_empty() {
        return value.to_string();
    }
    match date::to_iso_string(date::parse(value)) {
        Some(iso) => iso,
        None => {
            debug!(value, "Annotation timestamp not parseable by Date; returned as stored");
            value.to_string()
        }
    }
}

fn nullable_text(value: Option<String>) -> JsValue {
    value.map_or(JsValue::Null, JsValue::String)
}

fn list_row(row: &PgRow) -> Result<JsValue, sqlx::Error> {
    let date: String = row.try_get("date")?;
    let end_date: Option<String> = row.try_get("end_date")?;
    Ok(object(vec![
        ("annotationId", JsValue::Number(f64::from(row.try_get::<i32, _>("annotation_id")?))),
        ("siteId", row.try_get::<Option<i32>, _>("site_id")?.map_or(JsValue::Null, |id| JsValue::Number(f64::from(id)))),
        ("organizationId", JsValue::String(row.try_get("organization_id")?)),
        ("userId", nullable_text(row.try_get("user_id")?)),
        ("userName", nullable_text(row.try_get("user_name")?)),
        ("title", JsValue::String(row.try_get("title")?)),
        ("description", nullable_text(row.try_get("description")?)),
        ("date", JsValue::String(to_iso(&date))),
        ("endDate", end_date.map_or(JsValue::Null, |value| JsValue::String(to_iso(&value)))),
        ("color", nullable_text(row.try_get("color")?)),
        ("icon", nullable_text(row.try_get("icon")?)),
        ("isPublic", JsValue::Bool(row.try_get("is_public")?)),
        ("createdAt", nullable_text(row.try_get("created_at")?)),
        ("updatedAt", nullable_text(row.try_get("updated_at")?)),
    ]))
}

fn failure(err: &HandlerError, message: &str) -> Response {
    error!(error = %err, "{message}");
    request::error(StatusCode::INTERNAL_SERVER_ERROR, message)
}

/// GET /api/sites/:siteId/annotations (`publicAnnotationsRead`: resolveSiteId and
/// allowPublicSiteAccess only; the handler validates its own optional bounds).
pub async fn list(State(state): State<AppState>, method: Method, uri: Uri, headers: HeaderMap) -> Response {
    let params = match request::route_params(&uri, &[3]) {
        Ok(params) => params,
        Err(failure) => return request::param_failure(failure, method, uri).await,
    };
    let site = match site_scoped(
        &state,
        &headers,
        &uri,
        &params[0],
        SiteGuard::Public,
        route_scope("annotations", "read"),
        ChainSteps::GUARD_ONLY,
    )
    .await
    {
        Ok(site) => site,
        Err(response) => return response,
    };
    let Some(site_id) = parse_positive(&site.site_id) else {
        return request::error(StatusCode::BAD_REQUEST, "Invalid site ID");
    };

    let query = match annotation_schema::parse_list_query(&site.query) {
        Ok(query) => query,
        Err(issues) => return request::send(StatusCode::BAD_REQUEST, &validation_error_body(&issues)),
    };
    let time_zone = query.time_zone.clone().unwrap_or_else(|| "UTC".to_string());
    if !is_valid_time_zone(&time_zone) {
        return request::error(StatusCode::BAD_REQUEST, "Invalid time_zone");
    }

    let result: Result<Response, HandlerError> = async {
        let Some(organization_id) = site_organization_id(&state.pg, site_id).await? else {
            return Ok(request::error(StatusCode::NOT_FOUND, "Site not found"));
        };
        let access = RequestAccess::new(&state, &headers, &site.auth);
        let full_access = access.has_site(site_id, false).await;

        let zone = luxon::Zone::resolve(&time_zone);
        let now = now_ms();
        let start = query.start_date.as_deref().map(|day| luxon::day_start_iso(day, &zone, now));
        let end = query.end_date.as_deref().map(|day| luxon::next_day_start_iso(day, &zone, now));

        let mut sql = String::from(
            r#"select "annotations"."annotation_id", "annotations"."site_id", "annotations"."organization_id",
                      "annotations"."user_id", "user"."name" as "user_name", "annotations"."title",
                      "annotations"."description", "annotations"."date"::text as "date",
                      "annotations"."end_date"::text as "end_date", "annotations"."color", "annotations"."icon",
                      "annotations"."is_public", "annotations"."created_at"::text as "created_at",
                      "annotations"."updated_at"::text as "updated_at"
               from "annotations" left join "user" on "user"."id" = "annotations"."user_id"
               where (("annotations"."site_id" = $1 or ("annotations"."site_id" is null and "annotations"."organization_id" = $2))"#,
        );
        if !full_access {
            sql.push_str(r#" and "annotations"."is_public" = true"#);
        }
        let mut next_param = 3;
        if start.is_some() {
            sql.push_str(&format!(r#" and coalesce("annotations"."end_date", "annotations"."date") >= ${next_param}::timestamptz"#));
            next_param += 1;
        }
        if end.is_some() {
            sql.push_str(&format!(r#" and "annotations"."date" < ${next_param}::timestamptz"#));
        }
        sql.push_str(r#") order by "annotations"."date" asc, "annotations"."annotation_id" asc"#);

        let mut statement = sqlx::query(&sql).bind(bind_int(site_id)?).bind(&organization_id);
        if let Some(start) = &start {
            statement = statement.bind(start.clone());
        }
        if let Some(end) = &end {
            statement = statement.bind(end.clone());
        }
        let rows = statement.fetch_all(&state.pg).await?;
        let items = rows.iter().map(list_row).collect::<Result<Vec<_>, _>>()?;
        debug!(site_id, full_access, count = items.len(), "Fetched annotations");
        Ok(request::send(StatusCode::OK, &JsValue::Array(items)))
    }
    .await;
    result.unwrap_or_else(|err| failure(&err, "Failed to fetch annotations"))
}

/// POST /api/sites/:siteId/annotations (`authAnnotationsWrite`)
pub async fn create(State(state): State<AppState>, method: Method, uri: Uri, headers: HeaderMap, body: Body) -> Response {
    let params = match request::route_params(&uri, &[3]) {
        Ok(params) => params,
        Err(failure) => return request::param_failure(failure, method, uri).await,
    };
    let body = match request::read_body(&headers, body).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let site = match site_scoped(
        &state,
        &headers,
        &uri,
        &params[0],
        SiteGuard::Member,
        route_scope("annotations", "write"),
        ChainSteps::FULL,
    )
    .await
    {
        Ok(site) => site,
        Err(response) => return response,
    };
    let Some(site_id) = parse_positive(&site.site_id) else {
        return request::error(StatusCode::BAD_REQUEST, "Invalid site ID");
    };
    let input = match annotation_schema::parse_create(&body) {
        Ok(input) => input,
        Err(issues) => return request::send(StatusCode::BAD_REQUEST, &validation_error_body(&issues)),
    };

    let result: Result<Response, HandlerError> = async {
        let Some(organization_id) = site_organization_id(&state.pg, site_id).await? else {
            return Ok(request::error(StatusCode::NOT_FOUND, "Site not found"));
        };
        let access = RequestAccess::new(&state, &headers, &site.auth);
        if input.scope == AnnotationScope::Organization && !access.has_site(site_id, true).await {
            return Ok(request::error(
                StatusCode::FORBIDDEN,
                "Only organization admins can create organization-wide annotations",
            ));
        }
        let row_site = if input.scope == AnnotationScope::Organization { None } else { Some(bind_int(site_id)?) };
        let annotation_id: Option<i32> = sqlx::query_scalar(
            r#"insert into "annotations" ("site_id", "organization_id", "user_id", "title", "description", "date",
                   "end_date", "color", "icon", "is_public")
               values ($1, $2, $3, $4, $5, $6::timestamptz, $7::timestamptz, $8, $9, $10)
               returning "annotation_id""#,
        )
        .bind(row_site)
        .bind(&organization_id)
        .bind(access.user_id())
        .bind(&input.title)
        .bind(input.description.value())
        .bind(&input.date)
        .bind(input.end_date.value())
        .bind(input.color.value())
        .bind(input.icon.value().filter(|icon| !icon.is_empty()))
        .bind(input.is_public)
        .fetch_optional(&state.pg)
        .await?;
        let Some(annotation_id) = annotation_id else {
            return Ok(request::error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to create annotation"));
        };
        info!(site_id, annotation_id, organization_wide = row_site.is_none(), "Annotation created");
        Ok(request::send(
            StatusCode::CREATED,
            &object(vec![("success", true.into()), ("annotationId", JsValue::Number(f64::from(annotation_id)))]),
        ))
    }
    .await;
    result.unwrap_or_else(|err| failure(&err, "Failed to create annotation"))
}

/// Reads `/api/sites/:siteId/annotations/:annotationId` for PUT and DELETE.
fn ids(site_param: &str, annotation_param: &str) -> Result<(f64, f64), Response> {
    let site_id = parse_positive(site_param);
    let annotation_id = parse_positive(annotation_param);
    let Some(site_id) = site_id else {
        return Err(request::error(StatusCode::BAD_REQUEST, "Invalid site ID"));
    };
    let Some(annotation_id) = annotation_id else {
        return Err(request::error(StatusCode::BAD_REQUEST, "Invalid annotation ID"));
    };
    Ok((site_id, annotation_id))
}

/// PUT /api/sites/:siteId/annotations/:annotationId (`authAnnotationsWrite`)
pub async fn update(State(state): State<AppState>, method: Method, uri: Uri, headers: HeaderMap, body: Body) -> Response {
    let params = match request::route_params(&uri, &[3, 5]) {
        Ok(params) => params,
        Err(failure) => return request::param_failure(failure, method, uri).await,
    };
    let body = match request::read_body(&headers, body).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let site = match site_scoped(
        &state,
        &headers,
        &uri,
        &params[0],
        SiteGuard::Member,
        route_scope("annotations", "write"),
        ChainSteps::FULL,
    )
    .await
    {
        Ok(site) => site,
        Err(response) => return response,
    };
    let (site_id, annotation_id) = match ids(&site.site_id, &params[1]) {
        Ok(ids) => ids,
        Err(response) => return response,
    };
    let input = match annotation_schema::parse_update(&body) {
        Ok(input) => input,
        Err(issues) => return request::send(StatusCode::BAD_REQUEST, &validation_error_body(&issues)),
    };

    let result: Result<Response, HandlerError> = async {
        let Some(organization_id) = site_organization_id(&state.pg, site_id).await? else {
            return Ok(request::error(StatusCode::NOT_FOUND, "Site not found"));
        };
        let existing = find_annotation(&state.pg, annotation_id).await?;
        let Some(existing) = existing.filter(|row| belongs_to_site(row, site_id, &organization_id)) else {
            return Ok(request::error(StatusCode::NOT_FOUND, "Annotation not found"));
        };
        let access = RequestAccess::new(&state, &headers, &site.auth);
        if !can_manage(&access, site_id, &existing).await {
            return Ok(request::error(StatusCode::FORBIDDEN, "You can only edit annotations you created"));
        }

        // The merged row must still be a valid range
        let next_date = input.date.clone().unwrap_or_else(|| existing.date.clone());
        let next_end_date = match &input.end_date {
            Field::Absent => existing.end_date.clone(),
            Field::Null => None,
            Field::Value(value) => Some(value.clone()),
        };
        if let Some(end) = next_end_date.filter(|end| !end.is_empty())
            && date::parse(&end) <= date::parse(&next_date)
        {
            return Ok(request::error(StatusCode::BAD_REQUEST, "endDate must be after date"));
        }

        let mut next_site: Option<Option<i32>> = None;
        if let Some(scope) = input.scope {
            let wants_org_wide = scope == AnnotationScope::Organization;
            if wants_org_wide != existing.site_id.is_none() {
                if !access.has_site(site_id, true).await {
                    return Ok(request::error(
                        StatusCode::FORBIDDEN,
                        "Only organization admins can change an annotation's scope",
                    ));
                }
                next_site = Some(if wants_org_wide { None } else { Some(bind_int(site_id)?) });
            }
        }

        // drizzle's .set() in key order, updatedAt last
        let mut assignments: Vec<String> = Vec::new();
        let mut position = 1;
        let mut push = |column: &str, cast: &str| {
            assignments.push(format!(r#""{column}" = ${position}{cast}"#));
            position += 1;
        };
        if input.title.is_some() {
            push("title", "");
        }
        if !input.description.is_absent() {
            push("description", "");
        }
        if input.date.is_some() {
            push("date", "::timestamptz");
        }
        if !input.end_date.is_absent() {
            push("end_date", "::timestamptz");
        }
        if !input.color.is_absent() {
            push("color", "");
        }
        if !input.icon.is_absent() {
            push("icon", "");
        }
        if input.is_public.is_some() {
            push("is_public", "");
        }
        if next_site.is_some() {
            push("site_id", "");
        }
        push("updated_at", "::timestamp");
        let sql = format!(
            r#"update "annotations" set {} where "annotations"."annotation_id" = ${position} returning "annotation_id""#,
            assignments.join(", ")
        );

        let mut statement = sqlx::query_scalar::<_, i32>(&sql);
        if let Some(title) = &input.title {
            statement = statement.bind(title.clone());
        }
        if !input.description.is_absent() {
            statement = statement.bind(input.description.value().cloned());
        }
        if let Some(date) = &input.date {
            statement = statement.bind(date.clone());
        }
        if !input.end_date.is_absent() {
            statement = statement.bind(input.end_date.value().cloned());
        }
        if !input.color.is_absent() {
            statement = statement.bind(input.color.value().cloned());
        }
        if !input.icon.is_absent() {
            statement = statement.bind(input.icon.value().filter(|icon| !icon.is_empty()).cloned());
        }
        if let Some(is_public) = input.is_public {
            statement = statement.bind(is_public);
        }
        if let Some(site) = next_site {
            statement = statement.bind(site);
        }
        let now = date::to_iso_string(now_ms()).unwrap_or_default();
        statement = statement.bind(now).bind(bind_int(annotation_id)?);
        if statement.fetch_optional(&state.pg).await?.is_none() {
            return Ok(request::error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to update annotation"));
        }
        info!(site_id, annotation_id, "Annotation updated");
        Ok(request::send(StatusCode::OK, &object(vec![("success", true.into())])))
    }
    .await;
    result.unwrap_or_else(|err| failure(&err, "Failed to update annotation"))
}

/// DELETE /api/sites/:siteId/annotations/:annotationId (`authAnnotationsWrite`)
pub async fn delete(State(state): State<AppState>, method: Method, uri: Uri, headers: HeaderMap, body: Body) -> Response {
    let params = match request::route_params(&uri, &[3, 5]) {
        Ok(params) => params,
        Err(failure) => return request::param_failure(failure, method, uri).await,
    };
    if let Err(response) = request::read_body(&headers, body).await {
        return response;
    }
    let site = match site_scoped(
        &state,
        &headers,
        &uri,
        &params[0],
        SiteGuard::Member,
        route_scope("annotations", "write"),
        ChainSteps::FULL,
    )
    .await
    {
        Ok(site) => site,
        Err(response) => return response,
    };
    let (site_id, annotation_id) = match ids(&site.site_id, &params[1]) {
        Ok(ids) => ids,
        Err(response) => return response,
    };

    let result: Result<Response, HandlerError> = async {
        let Some(organization_id) = site_organization_id(&state.pg, site_id).await? else {
            return Ok(request::error(StatusCode::NOT_FOUND, "Site not found"));
        };
        let existing = find_annotation(&state.pg, annotation_id).await?;
        let Some(existing) = existing.filter(|row| belongs_to_site(row, site_id, &organization_id)) else {
            return Ok(request::error(StatusCode::NOT_FOUND, "Annotation not found"));
        };
        let access = RequestAccess::new(&state, &headers, &site.auth);
        if !can_manage(&access, site_id, &existing).await {
            return Ok(request::error(StatusCode::FORBIDDEN, "You can only delete annotations you created"));
        }
        let deleted: Option<i32> = sqlx::query_scalar(
            r#"delete from "annotations" where "annotations"."annotation_id" = $1 returning "annotation_id""#,
        )
        .bind(bind_int(annotation_id)?)
        .fetch_optional(&state.pg)
        .await?;
        if deleted.is_none() {
            return Ok(request::error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to delete annotation"));
        }
        info!(site_id, annotation_id, "Annotation deleted");
        Ok(request::send(StatusCode::OK, &object(vec![("success", true.into())])))
    }
    .await;
    result.unwrap_or_else(|err| failure(&err, "Failed to delete annotation"))
}
