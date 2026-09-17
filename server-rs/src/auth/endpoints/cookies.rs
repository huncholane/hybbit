//! Set-Cookie headers exactly as better-call serialises them and Better Auth's
//! cookie helpers (`setSessionCookie`, `expireCookie`, `deleteSessionCookie`) from
//! better-auth/dist/cookies/index.mjs.

use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};

use crate::auth::session::sign_value;

use super::{SESSION_EXPIRES_IN, context::Ctx, db::SessionWithUser};

/// `encodeURIComponent` leaves `A-Z a-z 0-9 - _ . ! ~ * ' ( )` alone
const URI_COMPONENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'!')
    .remove(b'~')
    .remove(b'*')
    .remove(b'\'')
    .remove(b'(')
    .remove(b')');

pub fn encode_uri_component(text: &str) -> String {
    utf8_percent_encode(text, URI_COMPONENT).to_string()
}

/// Cookie attributes in the order `_serialize` writes them.
#[derive(Clone, Debug, Default)]
pub struct CookieAttributes {
    pub max_age: Option<i64>,
    pub path: Option<&'static str>,
    pub http_only: bool,
    pub secure: bool,
    pub same_site: Option<&'static str>,
}

impl CookieAttributes {
    pub fn with_max_age(mut self, max_age: Option<i64>) -> Self {
        self.max_age = max_age;
        self
    }
}

/// better-call `_serialize`: `__Secure-` names force `Secure`
fn serialize(name: &str, value: &str, attributes: &CookieAttributes) -> String {
    let mut cookie = format!("{name}={value}");
    if let Some(max_age) = attributes.max_age.filter(|max_age| *max_age >= 0) {
        cookie.push_str(&format!("; Max-Age={max_age}"));
    }
    if let Some(path) = attributes.path {
        cookie.push_str(&format!("; Path={path}"));
    }
    if attributes.http_only {
        cookie.push_str("; HttpOnly");
    }
    if attributes.secure || name.starts_with("__Secure-") {
        cookie.push_str("; Secure");
    }
    if let Some(same_site) = attributes.same_site {
        let mut chars = same_site.chars();
        let capitalised: String = chars.next().map(|c| c.to_ascii_uppercase()).into_iter().chain(chars).collect();
        cookie.push_str(&format!("; SameSite={capitalised}"));
    }
    cookie
}

/// `serializeCookie`: the value is `encodeURIComponent`-ed
pub fn serialize_cookie(name: &str, value: &str, attributes: &CookieAttributes) -> String {
    serialize(name, &encode_uri_component(value), attributes)
}

/// `serializeSignedCookie`: `encodeURIComponent(value + "." + base64 HMAC)`
pub fn serialize_signed_cookie(name: &str, value: &str, secret: &str, attributes: &CookieAttributes) -> String {
    serialize(name, &encode_uri_component(&sign_value(value, secret)), attributes)
}

/// `createCookieGetter(options)(name)`: `__Secure-better-auth.<name>` in production
/// with `Secure; SameSite=None`, `better-auth.<name>` with `SameSite=Lax` otherwise;
/// always `Path=/` and `HttpOnly`.
pub fn auth_cookie(production: bool, name: &str) -> (String, CookieAttributes) {
    let full = crate::auth::session::cookie_name(production, name);
    let attributes = CookieAttributes {
        max_age: None,
        path: Some("/"),
        http_only: true,
        secure: production,
        same_site: Some(if production { "none" } else { "lax" }),
    };
    (full, attributes)
}

/// `authCookies.sessionToken`: Max-Age 7 days
pub fn session_token_cookie(production: bool) -> (String, CookieAttributes) {
    let (name, attributes) = auth_cookie(production, "session_token");
    (name, attributes.with_max_age(Some(SESSION_EXPIRES_IN)))
}

/// `authCookies.sessionData`: Max-Age 300 (cookie cache, unused here but still expired)
pub fn session_data_cookie(production: bool) -> (String, CookieAttributes) {
    let (name, attributes) = auth_cookie(production, "session_data");
    (name, attributes.with_max_age(Some(300)))
}

pub fn dont_remember_cookie(production: bool) -> (String, CookieAttributes) {
    auth_cookie(production, "dont_remember")
}

impl Ctx<'_> {
    /// `ctx.setCookie(name, value, attributes)`
    pub fn set_cookie(&mut self, name: &str, value: &str, attributes: &CookieAttributes) {
        let cookie = serialize_cookie(name, value, attributes);
        self.response.append_cookie(cookie);
    }

    /// `ctx.setSignedCookie(name, value, secret, attributes)`
    pub fn set_signed_cookie(&mut self, name: &str, value: &str, attributes: &CookieAttributes) {
        let cookie = serialize_signed_cookie(name, value, self.secret(), attributes);
        self.response.append_cookie(cookie);
    }

    /// `expireCookie`: drop pending cookies of that name, then send it with Max-Age=0
    pub fn expire_cookie(&mut self, name: &str, attributes: &CookieAttributes) {
        self.response.remove_cookies_named(name);
        self.set_cookie(name, "", &attributes.clone().with_max_age(Some(0)));
    }

    /// `deleteSessionCookie(ctx, skipDontRememberMe)`: expire the session token and
    /// cookie-cache cookies, every request cookie chunk of the cache, and (unless
    /// skipped) the don't-remember marker.
    pub fn delete_session_cookie(&mut self, skip_dont_remember: bool) {
        let production = self.production();
        let (token_name, token_attributes) = session_token_cookie(production);
        self.expire_cookie(&token_name, &token_attributes);
        let (data_name, data_attributes) = session_data_cookie(production);
        self.expire_cookie(&data_name, &data_attributes);
        // createSessionStore(...).clean(): every request cookie whose name starts with it
        let chunks: Vec<String> =
            self.cookies.iter().filter(|(name, _)| name.starts_with(&data_name)).map(|(name, _)| name.clone()).collect();
        for chunk in chunks {
            self.set_cookie(&chunk, "", &data_attributes.clone().with_max_age(Some(0)));
        }
        if !skip_dont_remember {
            let (name, attributes) = dont_remember_cookie(production);
            self.expire_cookie(&name, &attributes);
        }
    }

    /// `setSessionCookie(ctx, session, dontRememberMe, overrides)`. `dont_remember`
    /// None reads the request's signed marker cookie.
    pub fn set_session_cookie(&mut self, session: &SessionWithUser, dont_remember: Option<bool>, max_age_override: Option<i64>) {
        let production = self.production();
        let dont_remember = dont_remember.unwrap_or_else(|| {
            let (name, _) = dont_remember_cookie(production);
            self.verified_cookie(&name).is_some()
        });
        let (name, attributes) = session_token_cookie(production);
        let max_age = if dont_remember { None } else { Some(SESSION_EXPIRES_IN) };
        let max_age = max_age_override.or(max_age);
        self.set_signed_cookie(&name, &session.session.token, &attributes.with_max_age(max_age));
        if dont_remember {
            let (marker, marker_attributes) = dont_remember_cookie(production);
            self.set_signed_cookie(&marker, "true", &marker_attributes);
        }
        self.new_session = Some(session.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialises_like_better_call() {
        let (name, attributes) = session_token_cookie(true);
        assert_eq!(
            serialize_cookie(&name, "", &attributes.clone().with_max_age(Some(0))),
            "__Secure-better-auth.session_token=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=None"
        );
        let (name, attributes) = dont_remember_cookie(false);
        assert_eq!(serialize_cookie(&name, "a b", &attributes), "better-auth.dont_remember=a%20b; Path=/; HttpOnly; SameSite=Lax");
        // Captured from Node: the dont_remember marker for secret parity-local-secret-not-for-production
        let (name, attributes) = dont_remember_cookie(true);
        assert_eq!(
            serialize_signed_cookie(&name, "true", "parity-local-secret-not-for-production", &attributes),
            "__Secure-better-auth.dont_remember=true.J6oksQMPX6GX5w5pEMHthuJ8M%2Bmhkl8KjisDYx7Mz%2Fk%3D; Path=/; HttpOnly; Secure; SameSite=None"
        );
    }

    #[test]
    fn uri_component_encoding() {
        assert_eq!(encode_uri_component("a+b/c=d!~*'()é"), "a%2Bb%2Fc%3Dd!~*'()%C3%A9");
    }
}
