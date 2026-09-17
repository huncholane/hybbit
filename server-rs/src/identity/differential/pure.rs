//! Stateless functions against answers Node computed over generated corpora
//! (`pure.json`, written by the dump script).

use serde::Deserialize;
use sqlx::postgres::PgPoolOptions;

use super::{PARITY_PG, SECRET, diff_dir, report, server_dir};
use crate::{
    datacenter_asns::is_datacenter_asn,
    geo::{
        Geo,
        node_ip::{mmdb_lib_parse_ipv6, node_is_ip},
    },
    identity::{
        ip_bucket::bucket_ip_for_identity,
        lookup_asn_like_node,
        normalize_user_agent::normalize_user_agent_for_identity,
        sessions::session_key,
        sticky::tests::RecordingStickyStore,
        user_id::{UserIdDeps, UserIdOptions, UserIdService},
    },
    site_config::SiteConfigCache,
};

#[derive(Deserialize)]
struct UserAgentCase {
    source: String,
    value: String,
    node: String,
}

#[derive(Deserialize)]
struct IpBucketCase {
    ip: String,
    node: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct UserIdCase {
    pub(super) ip: String,
    kind: String,
    ua: String,
    site_id: i32,
    salted: Option<bool>,
    received_at: String,
    pub(super) datacenter: bool,
    pub(super) asn: Option<u32>,
    bucket: String,
    node: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClientIdCase {
    client_id: String,
    site_id: i32,
    salted: Option<bool>,
    received_at: String,
    node: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SessionKeyCase {
    user_id: String,
    site_id: i32,
    identified_user_id: String,
    node: String,
}

#[derive(Deserialize)]
struct NetCheckCase {
    ip: String,
    version: u8,
    bytes: Option<Vec<u8>>,
    asn: Option<u32>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct PureCorpus {
    user_agents: Vec<UserAgentCase>,
    ip_buckets: Vec<IpBucketCase>,
    pub(super) user_ids: Vec<UserIdCase>,
    client_ids: Vec<ClientIdCase>,
    session_keys: Vec<SessionKeyCase>,
    net_checks: Vec<NetCheckCase>,
    /// Every ASN below 4,300,000 that Node's `isDatacenterAsn` accepts.
    datacenter_asns: Vec<u32>,
}

#[test]
#[ignore]
fn datacenter_asn_membership_matches_node() {
    let Some(corpus) = load_pure() else { return };
    let node: std::collections::HashSet<u32> = corpus.datacenter_asns.iter().copied().collect();
    let mismatches: Vec<String> = (0..4_300_000u32)
        .filter(|&asn| is_datacenter_asn(Some(asn)) != node.contains(&asn))
        .map(|asn| format!("AS{asn}: node {}", node.contains(&asn)))
        .collect();
    println!("datacenter ASNs: {} in Node's list", node.len());
    report("isDatacenterAsn over AS0..AS4299999", 4_300_000, &mismatches);
}

pub(super) fn load_pure() -> Option<PureCorpus> {
    let path = diff_dir()?.join("pure.json");
    let text = std::fs::read_to_string(&path).ok()?;
    Some(serde_json::from_str(&text).expect("pure.json parses"))
}

#[test]
#[ignore]
fn normalize_user_agent_matches_node() {
    let Some(corpus) = load_pure() else { return };
    let mut per_source: std::collections::BTreeMap<&str, usize> = Default::default();
    let mismatches: Vec<String> = corpus
        .user_agents
        .iter()
        .inspect(|case| *per_source.entry(case.source.as_str()).or_default() += 1)
        .filter_map(|case| {
            let rust = normalize_user_agent_for_identity(&case.value);
            (rust != case.node).then(|| format!("{:?}\n    node {:?}\n    rust {:?}", case.value, case.node, rust))
        })
        .collect();
    println!("user agents by source: {per_source:?}");
    report("normalizeUserAgentForIdentity", corpus.user_agents.len(), &mismatches);
}

#[test]
#[ignore]
fn ip_bucket_matches_node() {
    let Some(corpus) = load_pure() else { return };
    let mismatches: Vec<String> = corpus
        .ip_buckets
        .iter()
        .filter_map(|case| {
            let rust = bucket_ip_for_identity(&case.ip, |_| true);
            (rust != case.node).then(|| format!("{:?}: node {:?} rust {:?}", case.ip, case.node, rust))
        })
        .collect();
    let bucketed = corpus.ip_buckets.iter().filter(|case| case.node != case.ip).count();
    println!("ip buckets: {bucketed} inputs parsed into a bucket, the rest passed through");
    report("bucketIpForIdentity", corpus.ip_buckets.len(), &mismatches);
}

#[tokio::test]
#[ignore]
async fn user_ids_match_node() {
    let Some(corpus) = load_pure() else { return };
    let geo = Geo::load(&server_dir()).expect("GeoLite2 next to the Node server");
    let pg = PgPoolOptions::new().max_connections(2).connect(PARITY_PG).await.expect("parity Postgres");
    let site_config = SiteConfigCache::new(pg);
    let sticky = RecordingStickyStore::passthrough();
    let service = UserIdService::new();
    let deps = UserIdDeps { redis: &sticky, salt_source: &site_config, secret: Some(SECRET) };

    let mut mismatches = Vec::new();
    let mut datacenter_mismatches = Vec::new();
    let mut bucket_mismatches = Vec::new();
    let mut by_kind: std::collections::BTreeMap<String, (usize, usize)> = Default::default();
    for case in &corpus.user_ids {
        // A fresh memoised resolver per case, as each request gets one
        let lookup = geo.asn_lookup();
        let is_datacenter_egress = |candidate: &str| is_datacenter_asn(lookup_asn_like_node(&lookup, candidate));
        let options = UserIdOptions {
            salt_user_ids: case.salted,
            received_at: Some(case.received_at.parse().expect("receivedAt")),
        };
        let rust = service
            .generate_user_id_with(&deps, &is_datacenter_egress, &case.ip, &case.ua, case.site_id, options, None, false)
            .await
            .expect("user id");

        let entry = by_kind.entry(case.kind.clone()).or_default();
        entry.0 += 1;
        if case.datacenter {
            entry.1 += 1;
        }
        if is_datacenter_egress(&case.ip) != case.datacenter {
            datacenter_mismatches.push(format!("{:?} node datacenter={}", case.ip, case.datacenter));
        }
        let rust_bucket = bucket_ip_for_identity(&case.ip, is_datacenter_egress);
        if rust_bucket != case.bucket {
            bucket_mismatches.push(format!("{:?} node {:?} rust {:?}", case.ip, case.bucket, rust_bucket));
        }
        if rust != case.node {
            mismatches.push(format!(
                "ip {:?} site {} salted {:?} at {} ua {:?}: node {} rust {}",
                case.ip, case.site_id, case.salted, case.received_at, case.ua, case.node, rust
            ));
        }
    }
    println!("user id inputs by kind (total, datacenter): {by_kind:?}");
    report("isDatacenterAsn(lookupAsn(ip))", corpus.user_ids.len(), &datacenter_mismatches);
    report("bucketIpForIdentity with real ASN", corpus.user_ids.len(), &bucket_mismatches);
    report("generateUserId", corpus.user_ids.len(), &mismatches);
}

#[tokio::test]
#[ignore]
async fn client_ids_match_node() {
    let Some(corpus) = load_pure() else { return };
    let pg = PgPoolOptions::new().max_connections(2).connect(PARITY_PG).await.expect("parity Postgres");
    let site_config = SiteConfigCache::new(pg);
    let service = UserIdService::new();

    let mut mismatches = Vec::new();
    for case in &corpus.client_ids {
        let options = UserIdOptions {
            salt_user_ids: case.salted,
            received_at: Some(case.received_at.parse().expect("receivedAt")),
        };
        let rust = service
            .generate_user_id_from_client_id(&site_config, Some(SECRET), &case.client_id, case.site_id, options)
            .await
            .expect("client id");
        if rust != case.node {
            mismatches.push(format!("{:?} site {}: node {} rust {}", case.client_id, case.site_id, case.node, rust));
        }
    }
    report("generateUserIdFromClientId", corpus.client_ids.len(), &mismatches);
}

#[test]
#[ignore]
fn session_keys_match_node() {
    let Some(corpus) = load_pure() else { return };
    let mismatches: Vec<String> = corpus
        .session_keys
        .iter()
        .filter_map(|case| {
            let rust = session_key(&case.user_id, case.site_id, &case.identified_user_id);
            (rust != case.node)
                .then(|| format!("{:?}/{:?}: node {} rust {}", case.user_id, case.identified_user_id, case.node, rust))
        })
        .collect();
    report("getSessionKey", corpus.session_keys.len(), &mismatches);
}

#[test]
#[ignore]
fn node_asn_reading_matches_node() {
    let Some(corpus) = load_pure() else { return };
    let geo = Geo::load(&server_dir()).expect("GeoLite2 next to the Node server");

    let mut version_mismatches = Vec::new();
    let mut byte_mismatches = Vec::new();
    let mut asn_mismatches = Vec::new();
    let mut geo_rs_differs = 0;
    for case in &corpus.net_checks {
        let version = node_is_ip(&case.ip);
        if version != case.version {
            version_mismatches.push(format!("{:?}: node {} rust {}", case.ip, case.version, version));
        }
        if let Some(bytes) = &case.bytes {
            let rust = mmdb_lib_parse_ipv6(&case.ip);
            if rust.as_slice() != bytes.as_slice() {
                byte_mismatches.push(format!("{:?}: node {:?} rust {:?}", case.ip, bytes, rust));
            }
        }
        let lookup = geo.asn_lookup();
        let rust = lookup_asn_like_node(&lookup, &case.ip);
        if rust != case.asn {
            asn_mismatches.push(format!("{:?}: node {:?} rust {:?}", case.ip, case.asn, rust));
        }
        if geo.asn(&case.ip).map(|info| info.asn) != case.asn {
            geo_rs_differs += 1;
        }
    }
    let zoned = corpus.net_checks.iter().filter(|case| case.version == 6 && case.ip.contains('%')).count();
    println!("net checks: {zoned} zoned IPv6 strings; plain geo.rs Geo::asn differs from Node on {geo_rs_differs}");
    report("net.isIP", corpus.net_checks.len(), &version_mismatches);
    report(
        "mmdb-lib parseIPv6",
        corpus.net_checks.iter().filter(|case| case.bytes.is_some()).count(),
        &byte_mismatches,
    );
    report("lookupAsn(ip)?.asn", corpus.net_checks.len(), &asn_mismatches);
}
