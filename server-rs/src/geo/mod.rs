//! GeoLite2 lookups, ported from server/src/db/geolocation/{geolocation,asn}.ts.
//! The databases are memory-mapped from GEOIP_DIR (default: the working directory,
//! where Node reads them too). City is required at startup; ASN is optional and
//! only degrades ASN-based bot detection and IP-topology inference when missing.
#![allow(dead_code)] // consumed by ingestion as it is ported

pub mod node_ip;

use std::{collections::HashMap, net::IpAddr, path::Path, sync::Mutex};

use anyhow::{Context, Result};
use maxminddb::{Mmap, Reader, geoip2};

/// `getLocation`'s per-IP result.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Location {
    pub city: Option<String>,
    pub country: Option<String>,
    pub country_iso: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub time_zone: Option<String>,
    /// ISO code of the first subdivision, without the country prefix
    pub region: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AsnInfo {
    pub asn: u32,
    pub organization: String,
}

pub struct Geo {
    city: Reader<Mmap>,
    asn: Option<Reader<Mmap>>,
}

impl Geo {
    pub fn load(dir: &Path) -> Result<Self> {
        let city_path = dir.join("GeoLite2-City.mmdb");
        // SAFETY: the databases ship read-only inside the image (or next to the Node
        // server locally) and nothing rewrites them while the process runs, which is
        // the invariant memory-mapping needs
        let city = unsafe { Reader::open_mmap(&city_path) }
            .with_context(|| format!("opening {}", city_path.display()))?;
        tracing::info!(path = %city_path.display(), "GeoIP database loaded successfully");

        let asn_path = dir.join("GeoLite2-ASN.mmdb");
        // SAFETY: as above
        let asn = match unsafe { Reader::open_mmap(&asn_path) } {
            Ok(reader) => {
                tracing::info!(path = %asn_path.display(), "GeoIP ASN database loaded successfully");
                Some(reader)
            }
            Err(error) => {
                tracing::warn!(error = %error, path = %asn_path.display(), "GeoIP ASN database not loaded, ASN-based bot detection disabled");
                None
            }
        };

        Ok(Self { city, asn })
    }

    /// City-level location, or None for invalid, private or unknown IPs. The string
    /// is read the way Node's reader reads it (see `node_ip`).
    pub fn location(&self, ip: &str) -> Option<Location> {
        let address: IpAddr = node_ip::node_ip_address(ip)?;
        let city: geoip2::City = self.city.lookup(address).ok()?.decode().ok()??;

        Some(Location {
            city: city.city.names.english.map(str::to_string),
            country: city.country.names.english.map(str::to_string),
            country_iso: city.country.iso_code.map(str::to_string),
            latitude: city.location.latitude,
            longitude: city.location.longitude,
            time_zone: city.location.time_zone.map(str::to_string),
            region: city
                .subdivisions
                .first()
                .and_then(|subdivision| subdivision.iso_code)
                .map(str::to_string),
        })
    }

    /// `lookupAsn`: None when the database is missing or the IP has no ASN record.
    pub fn asn(&self, ip: &str) -> Option<AsnInfo> {
        let reader = self.asn.as_ref()?;
        let address: IpAddr = node_ip::node_ip_address(ip)?;
        let record: geoip2::Asn = reader.lookup(address).ok()?.decode().ok()??;
        Some(AsnInfo {
            asn: record.autonomous_system_number?,
            organization: record.autonomous_system_organization.unwrap_or_default().to_string(),
        })
    }

    /// A per-request resolver that answers each IP once (`createAsnLookup`).
    pub fn asn_lookup(&self) -> AsnLookup<'_> {
        AsnLookup { geo: self, resolved: Mutex::new(HashMap::new()) }
    }
}

/// Memoised ASN lookups for the life of one request: IP resolution, identity,
/// exclusions and bot detection all ask about the same handful of IPs.
pub struct AsnLookup<'a> {
    geo: &'a Geo,
    resolved: Mutex<HashMap<String, Option<AsnInfo>>>,
}

impl AsnLookup<'_> {
    pub fn lookup(&self, ip: &str) -> Option<AsnInfo> {
        let mut resolved = self.resolved.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        resolved.entry(ip.to_string()).or_insert_with(|| self.geo.asn(ip)).clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs against the real databases when they are next to the Node server.
    fn databases() -> Option<Geo> {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../server");
        dir.join("GeoLite2-City.mmdb").exists().then(|| Geo::load(&dir).expect("loading GeoLite2"))
    }

    #[test]
    fn resolves_a_public_ip_and_rejects_garbage() {
        let Some(geo) = databases() else { return };
        let google = geo.location("8.8.8.8").expect("8.8.8.8 is in GeoLite2-City");
        assert_eq!(google.country_iso.as_deref(), Some("US"));
        assert_eq!(geo.asn("8.8.8.8").map(|info| info.asn), Some(15169));
        assert_eq!(geo.location("not an ip"), None);
        assert_eq!(geo.location("10.0.0.1"), None);
        // Node's reader rejects padding and accepts IPv6 zone ids
        assert_eq!(geo.asn(" 8.8.8.8"), None);
        assert_eq!(geo.asn("2001:4860:4860::8888%eth0").map(|info| info.asn), Some(15169));
        assert_eq!(geo.asn("127.0.0.1"), None);
    }

    #[test]
    fn memoises_per_request() {
        let Some(geo) = databases() else { return };
        let lookup = geo.asn_lookup();
        assert_eq!(lookup.lookup("1.1.1.1"), lookup.lookup("1.1.1.1"));
    }
}
