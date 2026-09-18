//! HMAC signatures for links that leave the app in emails, ported from
//! server/src/lib/signedToken.ts. Only verification is needed here (the
//! unsubscribe endpoint); signing lives with the mails that build the links.

use base64::Engine;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use crate::analytics::js::{JsValue, number::number_to_string};

/// `signPayload(payload)`: base64url without padding, since Node's
/// `digest("base64url")` omits it.
pub fn sign_payload(secret: &str, payload: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(payload.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

/// `verifySignedPayload`: equal length first, then a constant-time comparison.
pub fn verify_signed_payload(secret: &str, payload: &str, signature: &str) -> bool {
    let expected = sign_payload(secret, payload);
    expected.len() == signature.len() && crate::auth::endpoints::crypto::constant_time_eq(&expected, signature)
}

/// `verifyExpiringPayload(payload, exp, sig)`: the expiry is part of the signed
/// text and travels in the URL, so a leaked link cannot be replayed for ever.
pub fn verify_expiring_payload(secret: &str, payload: &str, exp: &JsValue, signature: &str, now_ms: f64) -> bool {
    let exp_number = exp.to_number();
    if !exp_number.is_finite() || exp_number < now_ms / 1000.0 {
        return false;
    }
    let seconds = number_to_string(exp_number.floor());
    verify_signed_payload(secret, &format!("{payload}:{seconds}"), signature)
}

/// `signExpiringPayload(payload, ttlSeconds)`. Nothing here builds a link yet (the
/// mails that do are not ported), so only the tests use it; it stays because the
/// signing half is what the verification above has to match.
#[cfg(test)]
pub fn sign_expiring_payload(secret: &str, payload: &str, ttl_seconds: i64, now_ms: f64) -> (i64, String) {
    let exp = (now_ms / 1000.0).floor() as i64 + ttl_seconds;
    (exp, sign_payload(secret, &format!("{payload}:{exp}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The suite in server/src/lib/signedToken.test.ts, with its secret.
    const SECRET: &str = "test-secret";
    const NOW: f64 = 1_700_000_000_000.0;

    fn exp(value: i64) -> JsValue {
        JsValue::Number(value as f64)
    }

    #[test]
    fn round_trips_a_plain_payload_and_rejects_tampering() {
        let signature = sign_payload(SECRET, "unsubscribe:a@b.com");
        assert!(!signature.contains('='), "base64url without padding");
        assert!(verify_signed_payload(SECRET, "unsubscribe:a@b.com", &signature));
        assert!(!verify_signed_payload(SECRET, "unsubscribe:evil@b.com", &signature));
        assert!(!verify_signed_payload(SECRET, "unsubscribe:a@b.com", &format!("{signature}x")));
        assert!(!verify_signed_payload(SECRET, "unsubscribe:a@b.com", ""));
    }

    #[test]
    fn expiring_tokens_verify_within_the_ttl_and_fail_after_it() {
        let (expiry, signature) = sign_expiring_payload(SECRET, "check-install:42:acme.com", 3600, NOW);
        assert!(verify_expiring_payload(SECRET, "check-install:42:acme.com", &exp(expiry), &signature, NOW));
        assert!(!verify_expiring_payload(SECRET, "check-install:43:acme.com", &exp(expiry), &signature, NOW));

        // A signature over an already-past expiry never verifies
        let past = (NOW / 1000.0) as i64 - 10;
        let stale = sign_payload(SECRET, &format!("check-install:42:acme.com:{past}"));
        assert!(!verify_expiring_payload(SECRET, "check-install:42:acme.com", &exp(past), &stale, NOW));
    }

    #[test]
    fn rejects_a_forged_expiry_because_it_is_inside_the_signed_payload() {
        let (expiry, signature) = sign_expiring_payload(SECRET, "unsubscribe:a@b.com", 60, NOW);
        assert!(!verify_expiring_payload(SECRET, "unsubscribe:a@b.com", &exp(expiry + 999_999), &signature, NOW));
        let nonsense = JsValue::String("not-a-number".into());
        assert!(!verify_expiring_payload(SECRET, "unsubscribe:a@b.com", &nonsense, &signature, NOW));
    }

    #[test]
    fn a_fractional_expiry_signs_the_floored_value() {
        let (expiry, signature) = sign_expiring_payload(SECRET, "unsubscribe:a@b.com", 3600, NOW);
        let fractional = JsValue::String(format!("{expiry}.9"));
        assert!(verify_expiring_payload(SECRET, "unsubscribe:a@b.com", &fractional, &signature, NOW));
    }
}
