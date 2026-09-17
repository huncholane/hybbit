//! Transactional email, ported from server/src/lib/email/email.ts for the messages
//! authentication sends. Like Node, nothing leaves the process unless CLOUD=true
//! (Resend is only initialised in the cloud); the HTML is still rendered first.
#![allow(dead_code)] // weekly reports and lifecycle mail move over with their jobs

pub mod templates;

use serde_json::json;
use tracing::{debug, error, info};

use crate::config::Config;

pub use templates::OtpEmailType;

const FROM: &str = "Hygo <automail@email.hygo.ai>";
const RESEND_ENDPOINT: &str = "https://api.resend.com/emails";

/// `sendEmail(email, subject, html)`: a no-op without Resend (self-hosted); failures
/// are logged and propagate, like the SDK call Node awaits.
pub async fn send_email(config: &Config, to: &str, subject: &str, html: &str) -> Result<(), anyhow::Error> {
    if !config.auth.cloud {
        debug!(subject, "Email not sent: Resend is only configured when CLOUD=true");
        return Ok(());
    }
    let api_key = config.auth.resend_api_key.clone().unwrap_or_default();
    let client = reqwest::Client::new();
    let response = client
        .post(RESEND_ENDPOINT)
        .bearer_auth(api_key)
        .json(&json!({ "from": FROM, "to": to, "subject": subject, "html": html }))
        .send()
        .await;
    match response {
        Ok(response) if response.status().is_success() => {
            info!(subject, "Email sent through Resend");
            Ok(())
        }
        // The Resend SDK resolves with { error } on HTTP failures instead of throwing
        Ok(response) => {
            error!(subject, status = response.status().as_u16(), "Resend rejected the email");
            Ok(())
        }
        Err(err) => {
            error!(subject, error = %err, "Email send failed");
            Err(err.into())
        }
    }
}

/// `OTP_SUBJECTS`
fn otp_subject(kind: OtpEmailType) -> &'static str {
    match kind {
        OtpEmailType::SignIn => "Your Hygo Sign-In Code",
        OtpEmailType::EmailVerification => "Verify Your Email Address",
        OtpEmailType::ForgetPassword => "Reset Your Password",
        OtpEmailType::ChangeEmail => "Change Your Email Address",
    }
}

/// `sendOtpEmail`
pub async fn send_otp_email(config: &Config, email: &str, otp: &str, kind: OtpEmailType) -> Result<(), anyhow::Error> {
    let html = templates::otp_email(otp, kind, templates::current_year());
    send_email(config, email, otp_subject(kind), &html).await
}

/// `sendEmailVerificationLink`
pub async fn send_email_verification_link(config: &Config, email: &str, url: &str) -> Result<(), anyhow::Error> {
    let html = templates::email_verification_link(url);
    send_email(config, email, "Verify your Hygo email", &html).await
}

/// `sendChangeEmailVerification`: mailed to the current address
pub async fn send_change_email_verification(config: &Config, current: &str, new: &str, url: &str) -> Result<(), anyhow::Error> {
    let html = templates::change_email_verification(current, new, url);
    send_email(config, current, "Confirm your email change on Hygo", &html).await
}

/// `sendInvitationEmail`
pub async fn send_invitation_email(
    config: &Config,
    email: &str,
    invited_by: &str,
    organization_name: &str,
    invite_link: &str,
) -> Result<(), anyhow::Error> {
    let html = templates::invitation_email(email, invited_by, organization_name, invite_link, templates::current_year());
    send_email(config, email, "You're Invited to Join an Organization on Hygo", &html).await
}
