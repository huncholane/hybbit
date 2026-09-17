//! Site Configuration, ported from server/src/lib/siteConfig.ts: one read of the
//! `sites` row (plus its organization's IP exclusions) with Node's field defaults,
//! cached per identifier spelling for a minute.
#![allow(dead_code)] // fields and methods are consumed as ingest and settings routes are ported

use std::{
    sync::Mutex,
    time::{Duration, Instant},
};

use indexmap::IndexMap;
use serde_json::Value;
use sqlx::{PgPool, Row, postgres::PgRow};

const CACHE_TTL: Duration = Duration::from_secs(60);
/// Identifier spellings are attacker-controlled (zero-padded numbers resolve too),
/// so the cache is bounded rather than merely expiring.
const MAX_CACHE_ENTRIES: usize = 10_000;
pub const DEFAULT_BOUNCE_THRESHOLD_SECONDS: i32 = 10;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SiteType {
    Web,
    Mobile,
}

impl SiteType {
    pub fn as_str(self) -> &'static str {
        match self {
            SiteType::Web => "web",
            SiteType::Mobile => "mobile",
        }
    }
}

#[derive(Clone, Debug)]
pub struct SiteConfigData {
    pub id: Option<String>,
    pub site_id: i32,
    pub organization_id: Option<String>,
    pub site_type: SiteType,
    pub public: bool,
    pub embed_enabled: bool,
    pub salt_user_ids: bool,
    pub domain: String,
    pub block_bots: bool,
    pub first_party_proxy: bool,
    pub excluded_ips: Vec<String>,
    pub use_organization_excluded_ips: bool,
    pub organization_excluded_ips: Vec<String>,
    pub excluded_countries: Vec<String>,
    pub excluded_paths: Vec<String>,
    pub excluded_hostnames: Vec<String>,
    pub excluded_user_agents: Vec<String>,
    pub excluded_asns: Vec<String>,
    pub excluded_query_params: Vec<String>,
    pub private_link_key: Option<String>,
    pub session_replay: bool,
    pub web_vitals: bool,
    pub track_errors: bool,
    pub track_outbound: bool,
    pub track_url_params: bool,
    pub track_initial_page_view: bool,
    pub track_spa_navigation: bool,
    pub track_ip: bool,
    pub track_button_clicks: bool,
    pub track_copy: bool,
    pub track_form_interactions: bool,
    pub track_heartbeat: bool,
    pub heartbeat_interval: i32,
    pub bounce_threshold: i32,
    pub tags: Vec<String>,
}

/// How a caller named the Site. Node keys its cache by `typeof` plus the value, so a
/// number and a digit-only string are separate entries.
#[derive(Clone, Debug)]
pub enum SiteRef {
    Text(String),
    Number(i64),
}

impl SiteRef {
    fn cache_key(&self) -> String {
        match self {
            SiteRef::Text(text) => format!("string:{text}"),
            SiteRef::Number(number) => format!("number:{number}"),
        }
    }
}

struct CacheEntry {
    data: SiteConfigData,
    expires: Instant,
}

pub struct SiteConfigCache {
    pg: PgPool,
    entries: Mutex<IndexMap<String, CacheEntry>>,
}

const SITE_COLUMNS: &str = r#"id, site_id, organization_id, type, domain, "public", embed_enabled, "saltUserIds", "blockBots",
    first_party_proxy, excluded_ips, use_organization_excluded_ips, excluded_countries, excluded_paths,
    excluded_hostnames, excluded_user_agents, excluded_asns, excluded_query_params, private_link_key,
    "sessionReplay", "webVitals", "trackErrors", "trackOutbound", "trackUrlParams", "trackInitialPageView",
    "trackSpaNavigation", "trackIp", "trackButtonClicks", "trackCopy", "trackFormInteractions",
    track_heartbeat, heartbeat_interval, bounce_threshold, tags"#;

impl SiteConfigCache {
    pub fn new(pg: PgPool) -> Self {
        Self { pg, entries: Mutex::new(IndexMap::new()) }
    }

    /// Served from the cache when warm. Never errors: ingestion must degrade to "no
    /// configuration" on a Postgres blip, like Node's `getConfig`.
    pub async fn get_config(&self, site: &SiteRef) -> Option<SiteConfigData> {
        if let Some(cached) = self.cached(site) {
            return Some(cached);
        }
        match self.load(site).await {
            Ok(Some(data)) => {
                self.store(site.cache_key(), data.clone());
                Some(data)
            }
            Ok(None) => None,
            Err(error) => {
                tracing::error!(error = %error, site = ?site, "Error fetching site configuration");
                None
            }
        }
    }

    /// Always from Postgres, re-seating every unambiguous cache key; errors propagate
    /// so settings screens can answer 500 instead of claiming the Site is gone.
    pub async fn reload(&self, site: &SiteRef) -> Result<Option<SiteConfigData>, sqlx::Error> {
        let Some(data) = self.load(site).await? else {
            let stale = self.lock().shift_remove(&site.cache_key());
            if let Some(stale) = stale {
                self.invalidate(stale.data.id.as_deref(), stale.data.site_id);
            }
            return Ok(None);
        };

        self.invalidate(data.id.as_deref(), data.site_id);
        self.store(SiteRef::Number(data.site_id.into()).cache_key(), data.clone());
        if let Some(id) = &data.id {
            self.store(SiteRef::Text(id.clone()).cache_key(), data.clone());
        }
        self.store(site.cache_key(), data.clone());
        Ok(Some(data))
    }

    pub async fn resolve_site_id(&self, site: &SiteRef) -> Option<i32> {
        self.get_config(site).await.map(|data| data.site_id)
    }

    /// Drop every cached spelling of one Site.
    pub fn invalidate(&self, id: Option<&str>, site_id: i32) {
        self.lock()
            .retain(|_, entry| !(entry.data.site_id == site_id || (id.is_some() && entry.data.id.as_deref() == id)));
    }

    /// Drop every cached Site of one Organization (organization-wide settings changed).
    pub fn invalidate_organization(&self, organization_id: &str) {
        self.lock()
            .retain(|_, entry| entry.data.organization_id.as_deref() != Some(organization_id));
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, IndexMap<String, CacheEntry>> {
        self.entries.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn cached(&self, site: &SiteRef) -> Option<SiteConfigData> {
        let entries = self.lock();
        let entry = entries.get(&site.cache_key())?;
        (entry.expires > Instant::now()).then(|| entry.data.clone())
    }

    fn store(&self, key: String, data: SiteConfigData) {
        let mut entries = self.lock();
        entries.shift_remove(&key);
        entries.insert(key, CacheEntry { data, expires: Instant::now() + CACHE_TTL });

        if entries.len() > MAX_CACHE_ENTRIES {
            let now = Instant::now();
            entries.retain(|_, entry| entry.expires > now);
            while entries.len() > MAX_CACHE_ENTRIES {
                entries.shift_remove_index(0);
            }
        }
    }

    async fn load(&self, site: &SiteRef) -> Result<Option<SiteConfigData>, sqlx::Error> {
        let row = match site {
            SiteRef::Number(number) => self.row_by_site_id(*number).await?,
            SiteRef::Text(text) => match self.row_by_id(text).await? {
                Some(row) => Some(row),
                // A digit-only string falls back to the legacy numeric id
                None if !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()) => match text.parse::<i64>() {
                    Ok(number) => self.row_by_site_id(number).await?,
                    Err(_) => None,
                },
                None => None,
            },
        };
        let Some(row) = row else { return Ok(None) };

        let organization_id: Option<String> = row.try_get("organization_id")?;
        let organization_excluded_ips = match &organization_id {
            Some(organization_id) => self.organization_excluded_ips(organization_id).await?,
            None => Vec::new(),
        };
        Ok(Some(to_config(&row, organization_id, organization_excluded_ips)?))
    }

    async fn row_by_id(&self, id: &str) -> Result<Option<PgRow>, sqlx::Error> {
        sqlx::query(&format!("SELECT {SITE_COLUMNS} FROM sites WHERE id = $1 LIMIT 1"))
            .bind(id)
            .fetch_optional(&self.pg)
            .await
    }

    async fn row_by_site_id(&self, site_id: i64) -> Result<Option<PgRow>, sqlx::Error> {
        sqlx::query(&format!("SELECT {SITE_COLUMNS} FROM sites WHERE site_id = $1 LIMIT 1"))
            .bind(site_id)
            .fetch_optional(&self.pg)
            .await
    }

    async fn organization_excluded_ips(&self, organization_id: &str) -> Result<Vec<String>, sqlx::Error> {
        let value: Option<Option<Value>> = sqlx::query_scalar("SELECT excluded_ips FROM organization WHERE id = $1 LIMIT 1")
            .bind(organization_id)
            .fetch_optional(&self.pg)
            .await?;
        Ok(string_array(value.flatten()))
    }
}

/// Node keeps a jsonb column only when it is an array (`Array.isArray`), else [].
fn string_array(value: Option<Value>) -> Vec<String> {
    match value {
        Some(Value::Array(items)) => items
            .into_iter()
            .filter_map(|item| match item {
                Value::String(text) => Some(text),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

fn to_config(
    row: &PgRow,
    organization_id: Option<String>,
    organization_excluded_ips: Vec<String>,
) -> Result<SiteConfigData, sqlx::Error> {
    let flag = |column: &str| -> Result<Option<bool>, sqlx::Error> { row.try_get(column) };
    let json = |column: &str| -> Result<Vec<String>, sqlx::Error> { Ok(string_array(row.try_get(column)?)) };
    let site_type: Option<String> = row.try_get("type")?;

    Ok(SiteConfigData {
        id: row.try_get("id")?,
        site_id: row.try_get("site_id")?,
        organization_id,
        site_type: if site_type.as_deref() == Some("mobile") { SiteType::Mobile } else { SiteType::Web },
        public: flag("public")?.unwrap_or(false),
        embed_enabled: flag("embed_enabled")?.unwrap_or(false),
        salt_user_ids: flag("saltUserIds")?.unwrap_or(false),
        domain: row.try_get::<Option<String>, _>("domain")?.unwrap_or_default(),
        block_bots: flag("blockBots")?.unwrap_or(true),
        first_party_proxy: flag("first_party_proxy")?.unwrap_or(false),
        excluded_ips: json("excluded_ips")?,
        use_organization_excluded_ips: flag("use_organization_excluded_ips")?.unwrap_or(true),
        organization_excluded_ips,
        excluded_countries: json("excluded_countries")?,
        excluded_paths: json("excluded_paths")?,
        excluded_hostnames: json("excluded_hostnames")?,
        excluded_user_agents: json("excluded_user_agents")?,
        excluded_asns: json("excluded_asns")?,
        excluded_query_params: json("excluded_query_params")?,
        private_link_key: row.try_get("private_link_key")?,
        session_replay: flag("sessionReplay")?.unwrap_or(false),
        web_vitals: flag("webVitals")?.unwrap_or(false),
        track_errors: flag("trackErrors")?.unwrap_or(false),
        track_outbound: flag("trackOutbound")?.unwrap_or(true),
        track_url_params: flag("trackUrlParams")?.unwrap_or(true),
        track_initial_page_view: flag("trackInitialPageView")?.unwrap_or(true),
        track_spa_navigation: flag("trackSpaNavigation")?.unwrap_or(true),
        track_ip: flag("trackIp")?.unwrap_or(false),
        track_button_clicks: flag("trackButtonClicks")?.unwrap_or(false),
        track_copy: flag("trackCopy")?.unwrap_or(false),
        track_form_interactions: flag("trackFormInteractions")?.unwrap_or(false),
        track_heartbeat: flag("track_heartbeat")?.unwrap_or(false),
        heartbeat_interval: row.try_get::<Option<i32>, _>("heartbeat_interval")?.unwrap_or(15),
        bounce_threshold: row
            .try_get::<Option<i32>, _>("bounce_threshold")?
            .unwrap_or(DEFAULT_BOUNCE_THRESHOLD_SECONDS),
        tags: json("tags")?,
    })
}
