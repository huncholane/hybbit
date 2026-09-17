use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};

use axum::body::to_bytes;

use super::*;

/// A throwaway export laid out like `next build` with `output: "export"` writes it.
struct Export {
    dir: PathBuf,
    public: PathBuf,
    app: ClientApp,
}

impl Drop for Export {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(self.dir.parent().unwrap_or(&self.dir));
    }
}

fn export() -> Export {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let root = std::env::temp_dir().join(format!(
        "hygo-client-app-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let dir = root.join("out");
    let public = root.join("public");
    let files: &[(&str, &str)] = &[
        ("index.html", "<html>home</html>"),
        ("index.txt", "home flight"),
        ("__next._tree.txt", "root tree"),
        ("404.html", "<html>not found</html>"),
        ("_not-found.html", "<html>not found</html>"),
        ("login.html", "<html>login</html>"),
        ("login.txt", "login flight"),
        ("settings/account.html", "<html>account</html>"),
        ("__site__.html", "<html>site redirecting</html>"),
        ("__site__.txt", "site flight"),
        ("__site__/main.html", "<html>main</html>"),
        ("__site__/main.txt", "main flight"),
        ("__site__/main/__next.$d$site.txt", "site segment"),
        ("__site__/main/__next.$d$site.main.__PAGE__.txt", "main page segment"),
        ("__site__/user/__userId__.html", "<html>user</html>"),
        ("__site__/__privateKey__/main.html", "<html>private main</html>"),
        ("__site__/__privateKey__/main.txt", "private main flight"),
        ("_next/static/chunks/app.js", "console.log(1)"),
        ("_next/static/media/font.woff2", "woff2"),
        ("hygo/frog_white.svg", "<svg/>"),
        ("countries.json", "{}"),
    ];
    for (name, content) in files {
        let path = dir.join(name);
        fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        fs::write(path, content).expect("write");
    }
    fs::create_dir_all(&public).expect("mkdir public");
    fs::write(public.join("script.js"), "tracking()").expect("write script");
    fs::write(root.join("secret.txt"), "secret").expect("write secret");

    let app = ClientApp::load(&dir).expect("export loads");
    Export { dir, public, app }
}

struct Answer {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
}

impl Answer {
    fn header(&self, name: header::HeaderName) -> Option<&str> {
        self.headers.get(name).and_then(|value| value.to_str().ok())
    }
}

async fn request(export: &Export, method: Method, target: &str, headers: HeaderMap) -> Answer {
    let uri: Uri = target.parse().expect("valid target");
    let response = export.app.respond(&method, &uri, &headers, &export.public).await;
    let status = response.status();
    let headers = response.headers().clone();
    let body = to_bytes(response.into_body(), usize::MAX).await.expect("body");
    Answer { status, headers, body: String::from_utf8_lossy(&body).into_owned() }
}

async fn get(export: &Export, target: &str) -> Answer {
    request(export, Method::GET, target, HeaderMap::new()).await
}

#[tokio::test]
async fn serves_pages_with_revalidation() {
    let export = export();
    let answer = get(&export, "/login").await;
    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(answer.body, "<html>login</html>");
    assert_eq!(answer.header(header::CONTENT_TYPE), Some("text/html; charset=utf-8"));
    assert_eq!(answer.header(header::CACHE_CONTROL), Some("no-cache"));
    assert!(answer.header(header::ETAG).is_some_and(|etag| etag.starts_with("W/\"12-")));
    assert!(answer.header(header::LAST_MODIFIED).is_some());

    assert_eq!(get(&export, "/").await.body, "<html>home</html>");
    assert_eq!(get(&export, "/settings/account").await.body, "<html>account</html>");
}

#[tokio::test]
async fn maps_dynamic_urls_onto_their_placeholder_page() {
    let export = export();
    assert_eq!(get(&export, "/12/main").await.body, "<html>main</html>");
    assert_eq!(get(&export, "/12/main?timeMode=day").await.body, "<html>main</html>");
    assert_eq!(get(&export, "/12/abcdefabcdef/main").await.body, "<html>private main</html>");
    assert_eq!(get(&export, "/12/user/a%40b").await.body, "<html>user</html>");
    // Not a site route in proxy.ts, so the [site] page renders like it did under Next
    assert_eq!(get(&export, "/as").await.body, "<html>site redirecting</html>");
    assert_eq!(get(&export, "/login.html").await.body, "<html>site redirecting</html>");
}

#[tokio::test]
async fn head_sends_headers_only() {
    let export = export();
    let answer = request(&export, Method::HEAD, "/12/main", HeaderMap::new()).await;
    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(answer.body, "");
    assert_eq!(answer.header(header::CONTENT_LENGTH), Some("17"));
    assert_eq!(answer.header(header::CONTENT_TYPE), Some("text/html; charset=utf-8"));

    let redirect = request(&export, Method::HEAD, "/12", HeaderMap::new()).await;
    assert_eq!(redirect.status, StatusCode::TEMPORARY_REDIRECT);
    assert_eq!(redirect.header(header::LOCATION), Some("/12/main"));

    let missing = request(&export, Method::HEAD, "/12/nope", HeaderMap::new()).await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
    assert_eq!(missing.body, "");
}

#[tokio::test]
async fn answers_conditional_requests() {
    let export = export();
    let first = get(&export, "/12/main").await;
    let etag = first.header(header::ETAG).expect("etag").to_string();
    let mut headers = HeaderMap::new();
    headers.insert(header::IF_NONE_MATCH, HeaderValue::from_str(&etag).expect("etag header"));
    let second = request(&export, Method::GET, "/12/main", headers).await;
    assert_eq!(second.status, StatusCode::NOT_MODIFIED);
    assert_eq!(second.body, "");
    assert_eq!(second.header(header::ETAG), Some(etag.as_str()));
}

#[tokio::test]
async fn build_assets_are_immutable() {
    let export = export();
    let script = get(&export, "/_next/static/chunks/app.js").await;
    assert_eq!(script.status, StatusCode::OK);
    assert_eq!(script.body, "console.log(1)");
    assert_eq!(script.header(header::CACHE_CONTROL), Some("public, max-age=31536000, immutable"));
    assert_eq!(script.header(header::CONTENT_TYPE), Some("application/javascript; charset=UTF-8"));
    assert_eq!(
        get(&export, "/_next/static/media/font.woff2").await.header(header::CONTENT_TYPE),
        Some("font/woff2")
    );

    let missing = get(&export, "/_next/static/chunks/gone.js").await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
    assert_eq!(missing.body, "Not Found");
    assert_eq!(missing.header(header::CONTENT_TYPE), Some("text/plain; charset=utf-8"));
    assert_eq!(missing.header(header::CACHE_CONTROL), Some(NOT_FOUND_PAGE));
}

#[tokio::test]
async fn public_files_revalidate() {
    let export = export();
    let svg = get(&export, "/hygo/frog_white.svg").await;
    assert_eq!(svg.status, StatusCode::OK);
    assert_eq!(svg.header(header::CONTENT_TYPE), Some("image/svg+xml"));
    assert_eq!(svg.header(header::CACHE_CONTROL), Some("public, max-age=0"));
    assert_eq!(
        get(&export, "/countries.json").await.header(header::CONTENT_TYPE),
        Some("application/json; charset=UTF-8")
    );
    // The backend's own public files (tracking scripts) still resolve at the root
    let script = get(&export, "/script.js").await;
    assert_eq!(script.body, "tracking()");
    assert_eq!(script.header(header::CACHE_CONTROL), Some("public, max-age=0"));
}

#[tokio::test]
async fn serves_flight_data_for_client_navigations() {
    let export = export();
    let page = get(&export, "/login.txt").await;
    assert_eq!(page.body, "login flight");
    assert_eq!(page.header(header::CONTENT_TYPE), Some("text/plain; charset=utf-8"));
    assert_eq!(page.header(header::CACHE_CONTROL), Some("no-cache"));

    assert_eq!(get(&export, "/index.txt").await.body, "home flight");
    assert_eq!(get(&export, "/__next._tree.txt").await.body, "root tree");
    assert_eq!(get(&export, "/12/main.txt?_rsc=x1").await.body, "main flight");
    assert_eq!(get(&export, "/99/main/__next.$d$site.txt").await.body, "site segment");
    assert_eq!(get(&export, "/99/main/__next.%24d%24site.main.__PAGE__.txt").await.body, "main page segment");
    assert_eq!(get(&export, "/12/abcdefabcdef/main.txt").await.body, "private main flight");
    assert_eq!(get(&export, "/12/main/__next.nope.txt").await.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn flight_requests_for_redirected_pages_redirect_too() {
    let export = export();
    let answer = get(&export, "/12.txt?_rsc=abc").await;
    assert_eq!(answer.status, StatusCode::TEMPORARY_REDIRECT);
    assert_eq!(answer.header(header::LOCATION), Some("/12/main.txt"));
    let private = get(&export, "/12/abcdefabcdef.txt?embed=true").await;
    assert_eq!(private.header(header::LOCATION), Some("/12/abcdefabcdef/main.txt?embed=true"));
    // Reserved names are pages, not sites
    assert_eq!(get(&export, "/login.txt").await.status, StatusCode::OK);
}

#[tokio::test]
async fn proxy_redirects_match_next() {
    let export = export();
    let answer = get(&export, "/12?x=1").await;
    assert_eq!(answer.status, StatusCode::TEMPORARY_REDIRECT);
    assert_eq!(answer.header(header::LOCATION), Some("/12/main?x=1"));
    assert_eq!(answer.header(header::CACHE_CONTROL), Some("no-store, max-age=0"));
    assert_eq!(answer.header(header::CONTENT_TYPE), None);
    assert_eq!(answer.body, "/12/main?x=1");

    let callback = request(&export, Method::POST, "/auth/callback/google?code=1", HeaderMap::new()).await;
    assert_eq!(callback.status, StatusCode::TEMPORARY_REDIRECT);
    assert_eq!(callback.header(header::LOCATION), Some("/api/auth/callback/google?code=1"));
}

#[tokio::test]
async fn normalises_slashes_like_next() {
    let export = export();
    let answer = get(&export, "/login/?a=1").await;
    assert_eq!(answer.status, StatusCode::PERMANENT_REDIRECT);
    assert_eq!(answer.header(header::LOCATION), Some("/login?a=1"));
    assert_eq!(answer.header("refresh".parse().expect("name")), Some("0;url=/login?a=1"));
    assert_eq!(answer.header(header::CACHE_CONTROL), None);
    assert_eq!(answer.body, "/login?a=1");

    let doubled = get(&export, "//12?b=2").await;
    assert_eq!(doubled.status, StatusCode::PERMANENT_REDIRECT);
    assert_eq!(doubled.header(header::LOCATION), Some("/12?b=2"));
}

#[tokio::test]
async fn unknown_paths_get_the_not_found_page() {
    let export = export();
    let answer = get(&export, "/12/does-not-exist").await;
    assert_eq!(answer.status, StatusCode::NOT_FOUND);
    assert_eq!(answer.body, "<html>not found</html>");
    assert_eq!(answer.header(header::CONTENT_TYPE), Some("text/html; charset=utf-8"));
    assert_eq!(answer.header(header::CACHE_CONTROL), Some(NOT_FOUND_PAGE));
    assert_eq!(get(&export, "/a/b/c/d").await.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn never_leaves_the_export() {
    let export = export();
    for target in [
        "/..%2Fsecret.txt",
        "/%2e%2e/secret.txt",
        "/_next/static/..%2F..%2F..%2Fsecret.txt",
        "/12/main/__next..%2F..%2F..%2F..%2Fsecret.txt",
        "/.%2e/secret.txt",
    ] {
        // Some of these are still valid page URLs ([site] takes any one segment);
        // what matters is that no file outside the export is read
        let answer = get(&export, target).await;
        assert_ne!(answer.body, "secret", "{target}");
    }
}

#[tokio::test]
async fn other_methods_render_pages_like_next() {
    let export = export();
    let answer = request(&export, Method::POST, "/login", HeaderMap::new()).await;
    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(answer.body, "<html>login</html>");
    let asset = request(&export, Method::POST, "/_next/static/chunks/app.js", HeaderMap::new()).await;
    assert_eq!(asset.status, StatusCode::NOT_FOUND);
}

#[test]
fn a_directory_without_an_export_is_not_loaded() {
    assert!(ClientApp::load(&std::env::temp_dir().join("hygo-no-such-export")).is_none());
}

#[test]
fn discovery_paths_stay_with_the_backend() {
    assert!(is_backend_well_known("/.well-known/oauth-authorization-server/x"));
    assert!(is_backend_well_known("/.well-known/openid-configuration"));
    assert!(!is_backend_well_known("/.well-known/security.txt"));
    assert!(!is_backend_well_known("/login"));
}
