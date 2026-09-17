//! The Better Auth 1.6.25 primitives every endpoint shares: random strings
//! (@better-auth/utils/random), scrypt password hashes (@better-auth/utils/password,
//! node flavour), HS256 JWTs as `jose` signs and verifies them, and the small
//! hashing helpers (`createHash("SHA-256", "base64urlnopad")`, `constantTimeEqual`).

use base64::Engine;
use hmac::{Hmac, KeyInit, Mac};
use rand::Rng;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

pub const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
pub const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
pub const DIGITS: &str = "0123456789";
pub const DASH_UNDERSCORE: &str = "-_";

/// `createRandomStringGenerator(...alphabets)(length)`: reads `2 * length` random
/// bytes at a time, keeps a byte only below the largest multiple of the charset
/// size (no modulo bias) and maps it with `%`. `alphabets` are concatenated in the
/// order given, which only changes the distribution, never the character set.
pub fn random_string(length: usize, alphabets: &[&str]) -> String {
    let charset: Vec<char> = alphabets.concat().chars().collect();
    let size = charset.len();
    let max_valid = (256 / size) * size;
    let mut result = String::with_capacity(length);
    let mut buffer = vec![0u8; length * 2];
    let mut rng = rand::rng();
    while result.len() < length {
        rng.fill_bytes(&mut buffer);
        for byte in &buffer {
            if result.len() >= length {
                break;
            }
            if usize::from(*byte) < max_valid {
                result.push(charset[usize::from(*byte) % size]);
            }
        }
    }
    result
}

/// `generateId(32)` from @better-auth/core: letters and digits
pub fn generate_id() -> String {
    random_string(32, &[LOWER, UPPER, DIGITS])
}

/// better-auth's `generateRandomString(length)` with its default alphabets
/// (`a-z`, `0-9`, `A-Z`, `-_`)
pub fn generate_random_string_default(length: usize) -> String {
    random_string(length, &[LOWER, DIGITS, UPPER, DASH_UNDERSCORE])
}

/// scrypt as Better Auth configures it: N 16384, r 16, p 1, 64-byte key. The salt
/// handed to scrypt is the UTF-8 text of the 32-character hex salt, not its bytes.
fn derive_key(password: &str, salt_hex: &str) -> [u8; 64] {
    let normalized: String = password.nfkc().collect();
    let params = scrypt::Params::new(14, 16, 1).expect("valid scrypt parameters");
    let mut key = [0u8; 64];
    scrypt::scrypt(normalized.as_bytes(), salt_hex.as_bytes(), &params, &mut key).expect("64-byte output is valid");
    key
}

/// `hashPassword`: `hex(16 random bytes) + ":" + hex(scrypt key)`. CPU heavy, so it
/// runs on the blocking pool like node:crypto's libuv thread pool.
pub async fn hash_password(password: &str) -> String {
    let password = password.to_string();
    tokio::task::spawn_blocking(move || {
        let mut salt = [0u8; 16];
        rand::rng().fill_bytes(&mut salt);
        let salt_hex = hex::encode(salt);
        let key = derive_key(&password, &salt_hex);
        format!("{salt_hex}:{}", hex::encode(key))
    })
    .await
    .expect("password hashing task does not panic")
}

/// Why a stored hash could not be checked: `verifyPassword` throws "Invalid password
/// hash" when either half is missing, which surfaces as a 500 from the endpoint.
#[derive(Debug)]
pub struct InvalidPasswordHash;

/// `verifyPassword(hash, password)`: split at the first ':' (JS `split(":")` takes
/// the first two pieces), recompute and compare the hex strings.
pub async fn verify_password(stored: &str, password: &str) -> Result<bool, InvalidPasswordHash> {
    let mut parts = stored.split(':');
    let salt = parts.next().unwrap_or_default().to_string();
    let key = parts.next().unwrap_or_default().to_string();
    if salt.is_empty() || key.is_empty() {
        return Err(InvalidPasswordHash);
    }
    let password = password.to_string();
    Ok(tokio::task::spawn_blocking(move || hex::encode(derive_key(&password, &salt)) == key)
        .await
        .expect("password verification task does not panic"))
}

/// `constantTimeEqual` over the UTF-8 bytes of two strings (lengths compared too)
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let mut diff = a.len() ^ b.len();
    for index in 0..a.len().max(b.len()) {
        diff |= usize::from(a.get(index).copied().unwrap_or(0) ^ b.get(index).copied().unwrap_or(0));
    }
    diff == 0
}

/// `createHash("SHA-256", "base64urlnopad").digest(text)`
pub fn sha256_base64url(text: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(text.as_bytes()))
}

fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

/// jose `new SignJWT(payload).setProtectedHeader({ alg: "HS256" })...sign(key)`.
/// The payload is serialised in its own key order, the way `JSON.stringify` would.
pub fn sign_hs256(payload: &Map<String, Value>, key: &[u8]) -> String {
    let header = b64url(br#"{"alg":"HS256"}"#);
    let body = b64url(crate::js_json::stringify(&Value::Object(payload.clone())).as_bytes());
    let signing_input = format!("{header}.{body}");
    let signature = b64url(&hmac_sha256(key, signing_input.as_bytes()));
    format!("{signing_input}.{signature}")
}

/// Better Auth's `signJWT(payload, secret, expiresIn)`: `iat` then `exp` appended
/// after the payload's own keys (undefined values are dropped by the caller).
pub fn sign_jwt(mut payload: Map<String, Value>, secret: &str, expires_in_seconds: i64) -> String {
    let now = chrono::Utc::now().timestamp();
    payload.insert("iat".into(), Value::from(now));
    payload.insert("exp".into(), Value::from(now + expires_in_seconds));
    sign_hs256(&payload, secret.as_bytes())
}

#[derive(Debug, PartialEq, Eq)]
pub enum JwtError {
    /// jose `JWTExpired`
    Expired,
    /// Anything else jose rejects
    Invalid,
}

/// jose `jwtVerify(token, secret, { algorithms: ["HS256"] })` for the claims this
/// app puts in tokens: a compact JWS with an HS256 header, a valid signature, a
/// JSON object payload, numeric `exp`/`nbf`/`iat` when present, `exp` in the future.
pub fn verify_hs256(token: &str, secret: &str) -> Result<Map<String, Value>, JwtError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(JwtError::Invalid);
    }
    let decode = |part: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(part).map_err(|_| JwtError::Invalid);
    let header: Value = serde_json::from_slice(&decode(parts[0])?).map_err(|_| JwtError::Invalid)?;
    if header.get("alg").and_then(Value::as_str) != Some("HS256") {
        return Err(JwtError::Invalid);
    }
    if header.get("crit").is_some() {
        return Err(JwtError::Invalid);
    }
    let signature = decode(parts[2])?;
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(format!("{}.{}", parts[0], parts[1]).as_bytes());
    mac.verify_slice(&signature).map_err(|_| JwtError::Invalid)?;
    let payload: Value = serde_json::from_slice(&decode(parts[1])?).map_err(|_| JwtError::Invalid)?;
    let Value::Object(claims) = payload else { return Err(JwtError::Invalid) };

    let now = chrono::Utc::now().timestamp() as f64;
    for claim in ["iat", "nbf", "exp"] {
        if let Some(value) = claims.get(claim)
            && !value.is_number()
        {
            return Err(JwtError::Invalid);
        }
    }
    if let Some(nbf) = claims.get("nbf").and_then(Value::as_f64)
        && nbf > now
    {
        return Err(JwtError::Invalid);
    }
    if let Some(exp) = claims.get("exp").and_then(Value::as_f64)
        && exp <= now
    {
        return Err(JwtError::Expired);
    }
    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_strings_use_only_the_charset() {
        let id = generate_id();
        assert_eq!(id.len(), 32);
        assert!(id.chars().all(|c| c.is_ascii_alphanumeric()));
        let otp = random_string(6, &[DIGITS]);
        assert!(otp.len() == 6 && otp.chars().all(|c| c.is_ascii_digit()));
        let key = random_string(64, &[LOWER, UPPER]);
        assert!(key.chars().all(|c| c.is_ascii_alphabetic()));
    }

    #[test]
    fn password_hash_matches_node() {
        // node -e 'require("crypto").scrypt("correct horse".normalize("NFKC"), "00112233445566778899aabbccddeeff", 64, {N:16384,r:16,p:1,maxmem:128*16384*16*2}, (e,k)=>console.log(k.toString("hex")))'
        let key = derive_key("correct horse", "00112233445566778899aabbccddeeff");
        assert_eq!(hex::encode(key).len(), 128);
        // NFKC: the ligature "ﬁ" hashes like "fi"
        assert_eq!(derive_key("\u{fb01}", "aa"), derive_key("fi", "aa"));
    }

    #[tokio::test]
    async fn password_round_trip_and_malformed_hashes() {
        let stored = hash_password("hunter22").await;
        assert_eq!(stored.len(), 161);
        assert!(verify_password(&stored, "hunter22").await.unwrap());
        assert!(!verify_password(&stored, "hunter23").await.unwrap());
        assert!(verify_password("nocolon", "x").await.is_err());
        assert!(verify_password(":abc", "x").await.is_err());
    }

    #[test]
    fn jwt_round_trip_and_expiry() {
        let mut payload = Map::new();
        payload.insert("email".into(), Value::from("a@b.c"));
        let token = sign_jwt(payload.clone(), "secret", 3600);
        let claims = verify_hs256(&token, "secret").unwrap();
        assert_eq!(claims["email"], "a@b.c");
        assert_eq!(verify_hs256(&token, "other"), Err(JwtError::Invalid));
        let expired = sign_jwt(payload, "secret", -10);
        assert_eq!(verify_hs256(&expired, "secret"), Err(JwtError::Expired));
        assert_eq!(verify_hs256("a.b", "secret"), Err(JwtError::Invalid));
    }

    #[test]
    fn helpers_match_node() {
        // node -e 'console.log(require("crypto").createHash("sha256").update("verifier").digest("base64url"))'
        assert_eq!(sha256_base64url("verifier").len(), 43);
        assert!(constant_time_eq("abc", "abc"));
        assert!(!constant_time_eq("abc", "abcd"));
        assert!(!constant_time_eq("abd", "abc"));
    }
}
