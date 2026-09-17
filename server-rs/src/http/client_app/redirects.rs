//! The redirects the Next server used to send before rendering a page: its own URL
//! normalisation (repeated slashes, trailing slash) and client/src/proxy.ts, the
//! middleware that sent `/{site}` to `/{site}/main` and OAuth callbacks to the API.
//! Status codes, Location values and query encodings match what Next 16.2 sent.

use std::fmt::Write as _;

#[derive(Debug, PartialEq, Eq)]
pub enum Redirect {
    /// 308 with `Refresh: 0;url=...`: Next's own normalisation
    Permanent { location: String, reason: &'static str },
    /// 307 with `Cache-Control: no-store, max-age=0`: proxy.ts
    Temporary { location: String, reason: &'static str },
}

/// First-segment names proxy.ts never treated as a site id.
const NOT_SITES: [&str; 15] = [
    "login",
    "signup",
    "subscribe",
    "invitation",
    "reset-password",
    "auth",
    "admin",
    "organization",
    "account",
    "settings",
    "rollup",
    "as",
    "_next",
    "api",
    "widget",
];

/// Next's base server answers a request target with a backslash or repeated
/// slashes (before the query) with a 308 to the cleaned-up URL.
pub fn repeated_slashes(path: &str, query: Option<&str>) -> Option<Redirect> {
    if !path.contains('\\') && !path.contains("//") {
        return None;
    }
    let mut cleaned = String::with_capacity(path.len());
    for character in path.chars().map(|character| if character == '\\' { '/' } else { character }) {
        if character == '/' && cleaned.ends_with('/') {
            continue;
        }
        cleaned.push(character);
    }
    if let Some(query) = query.filter(|query| !query.is_empty()) {
        cleaned.push('?');
        cleaned.push_str(query);
    }
    Some(Redirect::Permanent { location: cleaned, reason: "repeated slashes" })
}

/// `trailingSlash: false`: `/login/` is a 308 to `/login`. The path is kept as it
/// came; the query goes through Node's `querystring` like every Next redirect.
pub fn trailing_slash(path: &str, query: Option<&str>) -> Option<Redirect> {
    if path.len() <= 1 || !path.ends_with('/') {
        return None;
    }
    let mut location = path[..path.len() - 1].to_string();
    let search = node_querystring_roundtrip(query.unwrap_or(""));
    if !search.is_empty() {
        location.push('?');
        location.push_str(&search);
    }
    Some(Redirect::Permanent { location, reason: "trailing slash" })
}

/// proxy.ts's matcher, `/((?!_next/static|_next/image|favicon.ico|.*\..*).*)`: the
/// middleware never saw static assets or anything with a dot in its path.
fn middleware_runs(path: &str) -> bool {
    let rest = path.strip_prefix('/').unwrap_or(path);
    // `favicon.ico` is a regex there: any one character between the two words
    let favicon = rest.strip_prefix("favicon").is_some_and(|after| {
        let mut characters = after.chars();
        characters.next().is_some() && characters.as_str().starts_with("ico")
    });
    !(rest.starts_with("_next/static") || rest.starts_with("_next/image") || favicon || rest.contains('.'))
}

/// client/src/proxy.ts. `path` is the raw request path, `query` the raw query.
pub fn proxy(path: &str, query: Option<&str>) -> Option<Redirect> {
    if !middleware_runs(path) || path.starts_with("/widget/") {
        return None;
    }

    let search = url_search_params_roundtrip(query.unwrap_or(""));
    let with_search = |mut location: String| {
        if !search.is_empty() {
            location.push('?');
            location.push_str(&search);
        }
        location
    };
    let path = encode_path(path);

    if path.contains("/auth/callback/github") || path.contains("/auth/callback/google") {
        return Some(Redirect::Temporary { location: with_search(format!("/api{path}")), reason: "oauth callback" });
    }

    let segments: Vec<&str> = path.strip_prefix('/').unwrap_or(&path).split('/').collect();
    match segments.as_slice() {
        // /{siteId}: open the site's main dashboard
        [site] if !site.is_empty() => {
            if NOT_SITES.contains(site) {
                return None;
            }
            Some(Redirect::Temporary { location: with_search(format!("/{site}/main")), reason: "site root" })
        }
        // /{siteId}/{privateKey}: a private link without a page
        [site, key] if !site.is_empty() && key.len() == 12 && key.bytes().all(|byte| byte.is_ascii_hexdigit()) => Some(
            Redirect::Temporary { location: with_search(format!("/{site}/{key}/main")), reason: "private link root" },
        ),
        _ => None,
    }
}

/// Setting `URL.pathname` percent-encodes what the path may not contain; a path
/// that arrived over HTTP rarely has any of it, but the Location must not either.
fn encode_path(path: &str) -> String {
    let mut encoded = String::with_capacity(path.len());
    for byte in path.bytes() {
        match byte {
            0x00..=0x20 | b'"' | b'<' | b'>' | b'`' | b'{' | b'}' | 0x7f..=0xff => {
                let _ = write!(encoded, "%{byte:02X}");
            }
            _ => encoded.push(char::from(byte)),
        }
    }
    encoded
}

/// `new URLSearchParams(search).toString()`: middleware redirects reserialise the
/// query (`a%20b` becomes `a+b`, `y` becomes `y=`) and Next drops its `_rsc` marker.
fn url_search_params_roundtrip(query: &str) -> String {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
        if key != "_rsc" {
            serializer.append_pair(&key, &value);
        }
    }
    serializer.finish()
}

/// Node's `querystring.parse` followed by `querystring.stringify` with
/// `encodeURIComponent`, which is how Next rebuilds the query of its own redirects.
/// Parsing into a JavaScript object groups repeated keys and moves integer-like keys
/// to the front in ascending order.
fn node_querystring_roundtrip(query: &str) -> String {
    let mut keys: Vec<(String, Vec<String>)> = Vec::new();
    for piece in query.split('&').filter(|piece| !piece.is_empty()) {
        let (raw_key, raw_value) = piece.split_once('=').unwrap_or((piece, ""));
        let key = node_unescape(raw_key);
        let value = node_unescape(raw_value);
        if key == "__proto__" {
            continue;
        }
        match keys.iter_mut().find(|(existing, _)| *existing == key) {
            Some((_, values)) => values.push(value),
            None => keys.push((key, vec![value])),
        }
    }

    // Own property order: array indices ascending, then the rest as inserted
    let index_of = |key: &str| {
        let canonical = key == "0" || (!key.starts_with('0') && !key.is_empty() && key.bytes().all(|b| b.is_ascii_digit()));
        canonical.then(|| key.parse::<u64>().ok()).flatten().filter(|index| *index < u64::from(u32::MAX))
    };
    let mut ordered: Vec<&(String, Vec<String>)> = keys.iter().filter(|(key, _)| index_of(key).is_some()).collect();
    ordered.sort_by_key(|(key, _)| index_of(key));
    ordered.extend(keys.iter().filter(|(key, _)| index_of(key).is_none()));

    let mut fields = Vec::new();
    for (key, values) in ordered {
        for value in values {
            fields.push(format!("{}={}", encode_uri_component(key), encode_uri_component(value)));
        }
    }
    fields.join("&")
}

/// `querystring.unescape`: `+` is a space, valid `%XX` escapes are bytes, anything
/// else stays as written, and the bytes are read as UTF-8 with replacement.
fn node_unescape(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                decoded.push(b' ');
                index += 1;
            }
            b'%' if bytes.get(index + 1).is_some_and(u8::is_ascii_hexdigit)
                && bytes.get(index + 2).is_some_and(u8::is_ascii_hexdigit) =>
            {
                let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).unwrap_or("00");
                decoded.push(u8::from_str_radix(hex, 16).unwrap_or(0));
                index += 3;
            }
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

/// JavaScript's `encodeURIComponent`.
fn encode_uri_component(text: &str) -> String {
    let mut encoded = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&byte) {
            encoded.push(char::from(byte));
        } else {
            let _ = write!(encoded, "%{byte:02X}");
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    fn location(redirect: Option<Redirect>) -> Option<String> {
        redirect.map(|redirect| match redirect {
            Redirect::Permanent { location, .. } | Redirect::Temporary { location, .. } => location,
        })
    }

    fn temporary(path: &str, query: Option<&str>) -> Option<String> {
        match proxy(path, query) {
            Some(Redirect::Temporary { location, .. }) => Some(location),
            Some(other) => panic!("unexpected {other:?}"),
            None => None,
        }
    }

    // Expected values below were read from the Next 16.2.6 standalone server
    #[test]
    fn site_roots_open_the_main_dashboard() {
        assert_eq!(temporary("/12", Some("x=1")).as_deref(), Some("/12/main?x=1"));
        assert_eq!(temporary("/12", None).as_deref(), Some("/12/main"));
        assert_eq!(temporary("/12", Some("")).as_deref(), Some("/12/main"));
        assert_eq!(temporary("/%31%32", None).as_deref(), Some("/%31%32/main"));
        assert_eq!(temporary("/browsers", None).as_deref(), Some("/browsers/main"));
        assert_eq!(temporary("/_nextfoo", None).as_deref(), Some("/_nextfoo/main"));
        assert_eq!(temporary("/12", Some("x=a%20b&y")).as_deref(), Some("/12/main?x=a+b&y="));
        assert_eq!(temporary("/12", Some("x=a+b&_rsc=1&z=%41")).as_deref(), Some("/12/main?x=a+b&z=A"));
        assert_eq!(temporary("/12", Some("_rsc=abc")).as_deref(), Some("/12/main"));
        assert_eq!(temporary("/12", Some("q=%zz")).as_deref(), Some("/12/main?q=%25zz"));
        assert_eq!(
            temporary("/12", Some("q=*'()!&r=%E2%80%A8")).as_deref(),
            Some("/12/main?q=*%27%28%29%21&r=%E2%80%A8")
        );
        assert_eq!(temporary("/12", Some("=v&k=&&m")).as_deref(), Some("/12/main?=v&k=&m="));
        assert_eq!(temporary("/12", Some("a=b=c")).as_deref(), Some("/12/main?a=b%3Dc"));
    }

    #[test]
    fn reserved_first_segments_are_not_sites() {
        for name in NOT_SITES {
            assert_eq!(temporary(&format!("/{name}"), None), None, "{name}");
        }
        assert_eq!(temporary("/", None), None);
        assert_eq!(temporary("/12/main", None), None);
    }

    #[test]
    fn private_links_open_their_main_dashboard() {
        assert_eq!(temporary("/12/abcdefabcdef", Some("y=2")).as_deref(), Some("/12/abcdefabcdef/main?y=2"));
        assert_eq!(temporary("/12/ABCDEFABCDEF", None).as_deref(), Some("/12/ABCDEFABCDEF/main"));
        assert_eq!(temporary("/12/abcdefabcdef", Some("q=%7e")).as_deref(), Some("/12/abcdefabcdef/main?q=%7E"));
        assert_eq!(temporary("/12%22x/abcdefabcdef", None).as_deref(), Some("/12%22x/abcdefabcdef/main"));
        assert_eq!(temporary("/12/abcdefabcdeg", None), None);
        assert_eq!(temporary("/12/abcdefabcde", None), None);
    }

    #[test]
    fn oauth_callbacks_go_to_the_api() {
        assert_eq!(
            temporary("/auth/callback/github", Some("code=1&state=2")).as_deref(),
            Some("/api/auth/callback/github?code=1&state=2")
        );
        assert_eq!(temporary("/auth/callback/google", None).as_deref(), Some("/api/auth/callback/google"));
        assert_eq!(
            temporary("/x/auth/callback/google/y", Some("z=1")).as_deref(),
            Some("/api/x/auth/callback/google/y?z=1")
        );
        assert_eq!(
            temporary("/a/auth/callback/google", Some("x=a%20b")).as_deref(),
            Some("/api/a/auth/callback/google?x=a+b")
        );
        assert_eq!(temporary("/a/auth/callback/google%zz", None).as_deref(), Some("/api/a/auth/callback/google%zz"));
    }

    #[test]
    fn the_matcher_skips_assets_and_widgets() {
        for path in ["/favicon.ico", "/foo.png", "/12.txt", "/_next/static/x", "/_next/image", "/widget/abc", "/faviconxico"] {
            assert_eq!(proxy(path, None), None, "{path}");
        }
        // Only the widget prefix is skipped, so /widget itself is not a site either
        assert_eq!(proxy("/widget", None), None);
    }

    #[test]
    fn repeated_slashes_collapse() {
        assert_eq!(location(repeated_slashes("//12", Some("b=2"))).as_deref(), Some("/12?b=2"));
        assert_eq!(location(repeated_slashes("//login//", Some("x=1"))).as_deref(), Some("/login/?x=1"));
        assert_eq!(location(repeated_slashes("/a\\b", None)).as_deref(), Some("/a/b"));
        assert_eq!(repeated_slashes("/login/", None), None);
    }

    #[test]
    fn trailing_slashes_are_dropped_and_the_query_rebuilt() {
        let redirect = |path: &str, query: Option<&str>| location(trailing_slash(path, query));
        assert_eq!(redirect("/login/", None).as_deref(), Some("/login"));
        assert_eq!(redirect("/login/", Some("")).as_deref(), Some("/login"));
        assert_eq!(redirect("/login/", Some("a=1")).as_deref(), Some("/login?a=1"));
        assert_eq!(redirect("/login/", Some("x=a%20b")).as_deref(), Some("/login?x=a%20b"));
        assert_eq!(
            redirect("/login/", Some("x=a+b&y&z=%7e&a=1&a=2&%41=b")).as_deref(),
            Some("/login?x=a%20b&y=&z=~&a=1&a=2&A=b")
        );
        assert_eq!(redirect("/login/", Some("q=%zz")).as_deref(), Some("/login?q=%25zz"));
        assert_eq!(redirect("/login/", Some("q=%E2%80%A8&r=*'()!")).as_deref(), Some("/login?q=%E2%80%A8&r=*'()!"));
        assert_eq!(redirect("/login/", Some("=v&k=")).as_deref(), Some("/login?=v&k="));
        assert_eq!(redirect("/login/", Some("a=b=c&&d")).as_deref(), Some("/login?a=b%3Dc&d="));
        assert_eq!(
            redirect("/login/", Some("2=x&b=1&1=y&b=2&__proto__=p")).as_deref(),
            Some("/login?1=y&2=x&b=1&b=2")
        );
        assert_eq!(redirect("/login/", Some("a=%E2%80")).as_deref(), Some("/login?a=%EF%BF%BD"));
        assert_eq!(redirect("/login/", Some("a=%FF")).as_deref(), Some("/login?a=%EF%BF%BD"));
        assert_eq!(redirect("/a%20b/", None).as_deref(), Some("/a%20b"));
        assert_eq!(redirect("/a%2Fb/", None).as_deref(), Some("/a%2Fb"));
        assert_eq!(redirect("/12/main.txt/", None).as_deref(), Some("/12/main.txt"));
        assert_eq!(redirect("/", None), None);
        assert_eq!(redirect("/login", None), None);
    }
}
