//! Organization and Site access, ported from server/src/lib/access.ts and the
//! site-access half of server/src/lib/auth-utils.ts (`getSitesUserHasAccessTo`,
//! `getIsUserAdmin`, `getUserHasAccessToSite*`, `getUserIsInOrg`).

use std::{
    collections::{HashMap, HashSet},
    sync::Mutex,
    time::{Duration, Instant},
};

use sqlx::{PgPool, Row};
use tracing::error;

/// NodeCache `stdTTL: 15`
const SITES_ACCESS_TTL: Duration = Duration::from_secs(15);

/// `OrgMembership`
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrgMembership {
    pub id: String,
    pub user_id: String,
    pub organization_id: String,
    pub role: String,
    pub has_restricted_site_access: bool,
}

impl OrgMembership {
    /// `isOrgAdmin`: the two roles that bypass site gating
    pub fn is_admin(&self) -> bool {
        self.role == "admin" || self.role == "owner"
    }

    /// `isOrgOwner`: the only role that may manage billing
    pub fn is_owner(&self) -> bool {
        self.role == "owner"
    }
}

/// `getOrgMembership`
pub async fn get_org_membership(
    pg: &PgPool,
    user_id: Option<&str>,
    organization_id: Option<&str>,
) -> Result<Option<OrgMembership>, sqlx::Error> {
    let (Some(user_id), Some(organization_id)) = (user_id.filter(|id| !id.is_empty()), organization_id.filter(|id| !id.is_empty()))
    else {
        return Ok(None);
    };
    let row = sqlx::query(
        r#"SELECT id, "userId", "organizationId", role, has_restricted_site_access
           FROM member WHERE "userId" = $1 AND "organizationId" = $2 LIMIT 1"#,
    )
    .bind(user_id)
    .bind(organization_id)
    .fetch_optional(pg)
    .await?;
    row.map(|row| {
        Ok(OrgMembership {
            id: row.try_get("id")?,
            user_id: row.try_get("userId")?,
            organization_id: row.try_get("organizationId")?,
            role: row.try_get("role")?,
            has_restricted_site_access: row.try_get("has_restricted_site_access")?,
        })
    })
    .transpose()
}

/// `MemberSiteGrants`
#[derive(Clone, Debug, Default)]
pub struct MemberSiteGrants {
    /// Explicit per-member grants (member_site_access)
    pub explicit_site_ids: HashSet<i32>,
    /// Sites gated behind any team in the scoped organizations
    pub team_gated_site_ids: HashSet<i32>,
    /// Sites reachable through the teams the user belongs to
    pub user_team_site_ids: HashSet<i32>,
}

/// `resolveMemberSiteGrants`
pub async fn resolve_member_site_grants(
    pg: &PgPool,
    user_id: &str,
    organization_ids: &[String],
    granted_member_ids: &[String],
) -> Result<MemberSiteGrants, sqlx::Error> {
    if organization_ids.is_empty() && granted_member_ids.is_empty() {
        return Ok(MemberSiteGrants::default());
    }

    let explicit: Vec<i32> = if granted_member_ids.is_empty() {
        Vec::new()
    } else {
        sqlx::query_scalar("SELECT site_id FROM member_site_access WHERE member_id = ANY($1)")
            .bind(granted_member_ids)
            .fetch_all(pg)
            .await?
    };
    let (team_gated, user_teams): (Vec<i32>, Vec<String>) = if organization_ids.is_empty() {
        (Vec::new(), Vec::new())
    } else {
        let gated = sqlx::query_scalar(
            "SELECT tsa.site_id FROM team_site_access tsa JOIN team t ON tsa.team_id = t.id WHERE t.\"organizationId\" = ANY($1)",
        )
        .bind(organization_ids)
        .fetch_all(pg)
        .await?;
        let teams = sqlx::query_scalar(
            r#"SELECT tm."teamId" FROM "teamMember" tm JOIN team t ON tm."teamId" = t.id
               WHERE tm."userId" = $1 AND t."organizationId" = ANY($2)"#,
        )
        .bind(user_id)
        .bind(organization_ids)
        .fetch_all(pg)
        .await?;
        (gated, teams)
    };

    let user_team_site_ids: Vec<i32> = if user_teams.is_empty() {
        Vec::new()
    } else {
        sqlx::query_scalar("SELECT site_id FROM team_site_access WHERE team_id = ANY($1)")
            .bind(&user_teams)
            .fetch_all(pg)
            .await?
    };

    Ok(MemberSiteGrants {
        explicit_site_ids: explicit.into_iter().collect(),
        team_gated_site_ids: team_gated.into_iter().collect(),
        user_team_site_ids: user_team_site_ids.into_iter().collect(),
    })
}

/// `memberCanAccessSite`: explicit and team grants always apply; ungated sites
/// are visible only to unrestricted members.
pub fn member_can_access_site(grants: &MemberSiteGrants, site_id: i32, has_restricted_site_access: bool) -> bool {
    if grants.explicit_site_ids.contains(&site_id) || grants.user_team_site_ids.contains(&site_id) {
        return true;
    }
    if has_restricted_site_access {
        return false;
    }
    !grants.team_gated_site_ids.contains(&site_id)
}

/// `restrictedMemberSiteIds`
pub fn restricted_member_site_ids(grants: &MemberSiteGrants) -> Vec<i32> {
    let mut ids: Vec<i32> = Vec::new();
    for id in grants.explicit_site_ids.iter().chain(grants.user_team_site_ids.iter()) {
        if !ids.contains(id) {
            ids.push(*id);
        }
    }
    ids
}

/// `getIsUserAdmin`: the Better Auth system admin role, exactly "admin".
pub async fn is_system_admin(pg: &PgPool, user_id: Option<&str>) -> Result<bool, sqlx::Error> {
    let Some(user_id) = user_id else { return Ok(false) };
    let role: Option<Option<String>> = sqlx::query_scalar(r#"SELECT role FROM "user" WHERE id = $1 LIMIT 1"#)
        .bind(user_id)
        .fetch_optional(pg)
        .await?;
    Ok(role.flatten().as_deref() == Some("admin"))
}

/// Who `getSitesUserHasAccessTo` answers for: a user (session or user-owned
/// bearer) or an organization-owned API key.
#[derive(Clone, Debug, Default)]
pub struct AccessPrincipal {
    pub user_id: Option<String>,
    pub api_key_organization_id: Option<String>,
}

/// The per-process site access cache (`sitesAccessCache`).
#[derive(Default)]
pub struct SitesAccessCache {
    entries: Mutex<HashMap<String, (Instant, Vec<i32>)>>,
}

impl SitesAccessCache {
    fn get(&self, key: &str) -> Option<Vec<i32>> {
        let mut entries = self.entries.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        match entries.get(key) {
            Some((stored, ids)) if stored.elapsed() < SITES_ACCESS_TTL => Some(ids.clone()),
            Some(_) => {
                entries.remove(key);
                None
            }
            None => None,
        }
    }

    fn set(&self, key: String, ids: Vec<i32>) {
        let mut entries = self.entries.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        entries.retain(|_, (stored, _)| stored.elapsed() < SITES_ACCESS_TTL);
        entries.insert(key, (Instant::now(), ids));
    }

    /// `invalidateSitesAccessCache`
    pub fn invalidate_user(&self, user_id: &str) {
        let mut entries = self.entries.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        entries.remove(&format!("{user_id}:true"));
        entries.remove(&format!("{user_id}:false"));
    }

    /// `getSitesUserHasAccessTo`, as site ids. Failures log and answer no sites
    /// without caching, like Node.
    pub async fn sites_for(&self, pg: &PgPool, principal: &AccessPrincipal, admin_only: bool) -> Vec<i32> {
        if principal.user_id.is_none()
            && let Some(organization_id) = &principal.api_key_organization_id
        {
            let key = format!("org:{organization_id}");
            if let Some(ids) = self.get(&key) {
                return ids;
            }
            return match sqlx::query_scalar::<_, i32>("SELECT site_id FROM sites WHERE organization_id = $1")
                .bind(organization_id)
                .fetch_all(pg)
                .await
            {
                Ok(ids) => {
                    self.set(key, ids.clone());
                    ids
                }
                Err(err) => {
                    error!(error = %err, "Error getting sites for organization");
                    Vec::new()
                }
            };
        }

        let Some(user_id) = principal.user_id.as_deref() else { return Vec::new() };
        let key = format!("{user_id}:{admin_only}");
        if let Some(ids) = self.get(&key) {
            return ids;
        }
        match user_site_ids(pg, user_id, admin_only).await {
            Ok(ids) => {
                self.set(key, ids.clone());
                ids
            }
            Err(err) => {
                error!(error = %err, "Error getting sites user has access to");
                Vec::new()
            }
        }
    }
}

async fn user_site_ids(pg: &PgPool, user_id: &str, admin_only: bool) -> Result<Vec<i32>, sqlx::Error> {
    if is_system_admin(pg, Some(user_id)).await? {
        return sqlx::query_scalar("SELECT site_id FROM sites").fetch_all(pg).await;
    }

    let members = sqlx::query(
        r#"SELECT id, "organizationId", role, has_restricted_site_access FROM member WHERE "userId" = $1"#,
    )
    .bind(user_id)
    .fetch_all(pg)
    .await?;
    if members.is_empty() {
        return Ok(Vec::new());
    }

    // admin/owner (any non-"member" role): every site of the org; "member": the
    // shared Site Access rule
    let mut full_access_org_ids: Vec<String> = Vec::new();
    let mut member_rows: Vec<(String, String, bool)> = Vec::new(); // (organization, member id, restricted)
    for row in &members {
        let role: String = row.try_get("role")?;
        if admin_only && role == "member" {
            continue;
        }
        let organization_id: String = row.try_get("organizationId")?;
        if role == "member" {
            let restricted: bool = row.try_get("has_restricted_site_access")?;
            let member_id: String = row.try_get("id")?;
            // Map semantics: a later row for the same organization replaces the earlier one
            member_rows.retain(|(org, _, _)| *org != organization_id);
            member_rows.push((organization_id, member_id, restricted));
        } else {
            full_access_org_ids.push(organization_id);
        }
    }

    let member_org_ids: Vec<String> = member_rows.iter().map(|(org, _, _)| org.clone()).collect();
    let restricted_org_ids: Vec<String> =
        member_rows.iter().filter(|(_, _, restricted)| *restricted).map(|(org, _, _)| org.clone()).collect();
    let restricted_member_ids: Vec<String> =
        member_rows.iter().filter(|(_, _, restricted)| *restricted).map(|(_, id, _)| id.clone()).collect();

    let mut eager_org_ids: Vec<String> = Vec::new();
    for org in full_access_org_ids.iter().chain(member_org_ids.iter().filter(|org| !restricted_org_ids.contains(org))) {
        if !eager_org_ids.contains(org) {
            eager_org_ids.push(org.clone());
        }
    }
    if eager_org_ids.is_empty() && restricted_org_ids.is_empty() {
        return Ok(Vec::new());
    }

    let eager_sites: Vec<(i32, Option<String>)> = if eager_org_ids.is_empty() {
        Vec::new()
    } else {
        sqlx::query_as("SELECT site_id, organization_id FROM sites WHERE organization_id = ANY($1)")
            .bind(&eager_org_ids)
            .fetch_all(pg)
            .await?
    };

    if member_org_ids.is_empty() {
        return Ok(eager_sites.into_iter().map(|(id, _)| id).collect());
    }
    let grants = resolve_member_site_grants(pg, user_id, &member_org_ids, &restricted_member_ids).await?;

    let mut accessible: Vec<i32> = eager_sites
        .into_iter()
        .filter(|(site_id, organization_id)| {
            match organization_id.as_ref().and_then(|org| member_rows.iter().find(|(member_org, _, _)| member_org == org)) {
                // No member row for the org means admin/owner authority over it
                None => true,
                Some((_, _, restricted)) => member_can_access_site(&grants, *site_id, *restricted),
            }
        })
        .map(|(site_id, _)| site_id)
        .collect();

    if !restricted_org_ids.is_empty() {
        let candidates = restricted_member_site_ids(&grants);
        if !candidates.is_empty() {
            let granted: Vec<i32> =
                sqlx::query_scalar("SELECT site_id FROM sites WHERE site_id = ANY($1) AND organization_id = ANY($2)")
                    .bind(&candidates)
                    .bind(&restricted_org_ids)
                    .fetch_all(pg)
                    .await?;
            for site_id in granted {
                if !accessible.contains(&site_id) {
                    accessible.push(site_id);
                }
            }
        }
    }

    Ok(accessible)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grants(explicit: &[i32], gated: &[i32], team: &[i32]) -> MemberSiteGrants {
        MemberSiteGrants {
            explicit_site_ids: explicit.iter().copied().collect(),
            team_gated_site_ids: gated.iter().copied().collect(),
            user_team_site_ids: team.iter().copied().collect(),
        }
    }

    #[test]
    fn site_access_rule() {
        let g = grants(&[1], &[1, 2, 3], &[3]);
        assert!(member_can_access_site(&g, 1, true), "explicit grant beats team gating");
        assert!(member_can_access_site(&g, 3, true), "team grants are additive");
        assert!(!member_can_access_site(&g, 2, false), "gated by a team the member is not on");
        assert!(member_can_access_site(&g, 4, false), "ungated sites for unrestricted members");
        assert!(!member_can_access_site(&g, 4, true), "restricted members only see grants");
        let mut restricted = restricted_member_site_ids(&g);
        restricted.sort();
        assert_eq!(restricted, vec![1, 3]);
    }
}
