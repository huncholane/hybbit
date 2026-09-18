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

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "parity-local-secret-not-for-production";

    #[test]
    fn signatures_round_trip() {
        let signature = sign_payload(SECRET, "unsubscribe:a@b.test:2000000000");
        assert!(!signature.contains('='));
        assert!(verify_signed_payload(SECRET, "unsubscribe:a@b.test:2000000000", &signature));
        assert!(!verify_signed_payload(SECRET, "unsubscribe:a@b.test:2000000001", &signature));
        assert!(!verify_signed_payload(SECRET, "unsubscribe:a@b.test:2000000000", &signature[1..]));
    }

    #[test]
    fn expiry_is_part_of_the_signature() {
        let now = 1_700_000_000_000.0;
        let signature = sign_payload(SECRET, "unsubscribe:a@b.test:2000000000");
        let exp = JsValue::String("2000000000".into());
        assert!(verify_expiring_payload(SECRET, "unsubscribe:a@b.test", &exp, &signature, now));
        // A fractional expiry signs the floored value
        let fractional = JsValue::String("2000000000.9".into());
        assert!(verify_expiring_payload(SECRET, "unsubscribe:a@b.test", &fractional, &signature, now));
        let past = JsValue::String("1000".into());
        assert!(!verify_expiring_payload(SECRET, "unsubscribe:a@b.test", &past, &signature, now));
        let nonsense = JsValue::String("later".into());
        assert!(!verify_expiring_payload(SECRET, "unsubscribe:a@b.test", &nonsense, &signature, now));
    }
}
