//! The authentication emails as HTML, byte-identical to Node's rendering.
//!
//! OTP and invitation emails are React Email components (server/src/lib/email/
//! templates/*.tsx) rendered by @react-email/render 2.0.0. Their markup never varies
//! except for a few text nodes and one attribute, so the static chunks in
//! `rendered_chunks.rs` were cut from Node's own output (fixtures/node-renders.json)
//! and the dynamic parts are escaped the way React DOM server escapes text.

include!("rendered_chunks.rs");

/// `OtpEmailType`
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OtpEmailType {
    SignIn,
    EmailVerification,
    ForgetPassword,
    ChangeEmail,
}

impl OtpEmailType {
    pub fn parse(kind: &str) -> Option<Self> {
        match kind {
            "sign-in" => Some(Self::SignIn),
            "email-verification" => Some(Self::EmailVerification),
            "forget-password" => Some(Self::ForgetPassword),
            "change-email" => Some(Self::ChangeEmail),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::SignIn => "sign-in",
            Self::EmailVerification => "email-verification",
            Self::ForgetPassword => "forget-password",
            Self::ChangeEmail => "change-email",
        }
    }
}

/// `new Date().getFullYear()` in the process time zone (UTC in production)
pub fn current_year() -> i32 {
    use chrono::Datelike;
    chrono::Local::now().year()
}

/// React DOM's `escapeTextForBrowser`, used for text and attribute values
pub fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            other => out.push(other),
        }
    }
    out
}

/// `<Preview>`: the text cut to 150 UTF-16 units, then (when shorter) a div of
/// invisible padding characters, one group per missing unit.
fn preview(text: &str) -> String {
    const MAX: usize = 150;
    let units: Vec<u16> = text.encode_utf16().collect();
    let cut = &units[..units.len().min(MAX)];
    let visible = String::from_utf16_lossy(cut);
    let mut out = escape(&visible);
    if cut.len() < MAX {
        out.push_str("<div>");
        out.push_str(&"\u{a0}\u{200c}\u{200b}\u{200d}\u{200e}\u{200f}\u{feff}".repeat(MAX - cut.len()));
        out.push_str("</div>");
    }
    out
}

/// `OtpEmail({ otp, type })`
pub fn otp_email(otp: &str, kind: OtpEmailType, year: i32) -> String {
    let (preview_text, description) = match kind {
        OtpEmailType::SignIn => ("Your Hygo sign-in code", "Here is your one-time password to sign in to Hygo:"),
        OtpEmailType::EmailVerification => ("Verify your email address", "Here is your verification code for Hygo:"),
        OtpEmailType::ForgetPassword => {
            ("Reset your password", "You requested to reset your password for Hygo. Here is your one-time password:")
        }
        OtpEmailType::ChangeEmail => ("Change your email address", "Here is your verification code for Hygo:"),
    };
    [
        HEAD,
        &preview(preview_text),
        OTP_AFTER_PREVIEW,
        &escape(description),
        OTP_AFTER_DESCRIPTION,
        &escape(otp),
        OTP_AFTER_CODE,
        &year.to_string(),
        TAIL,
    ]
    .concat()
}

/// `InvitationEmail({ email, invitedBy, organizationName, inviteLink })`
pub fn invitation_email(email: &str, invited_by: &str, organization_name: &str, invite_link: &str, year: i32) -> String {
    [
        HEAD,
        &preview(&format!("You're invited to join {organization_name} on Hygo")),
        INVITE_AFTER_PREVIEW,
        &escape(invited_by),
        INVITE_AFTER_INVITER,
        &escape(organization_name),
        INVITE_AFTER_ORGANIZATION,
        &escape(invite_link),
        INVITE_AFTER_LINK,
        &escape(email),
        INVITE_AFTER_EMAIL,
        &year.to_string(),
        TAIL,
    ]
    .concat()
}

/// `sendEmailVerificationLink`'s inline template (values interpolated unescaped)
pub fn email_verification_link(url: &str) -> String {
    format!(
        r#"
    <div style="font-family: Arial, sans-serif; max-width: 560px; margin: 0 auto; padding: 24px; color: #111;">
      <h2 style="margin: 0 0 16px;">Verify your email</h2>
      <p>Click the button below to verify this email address on your Hygo account.</p>
      <p style="margin: 24px 0;">
        <a href="{url}" style="background: #111; color: #fff; padding: 12px 20px; border-radius: 6px; text-decoration: none; display: inline-block;">Verify email</a>
      </p>
      <p style="font-size: 12px; color: #666; word-break: break-all;">Or paste this link into your browser: {url}</p>
    </div>
  "#
    )
}

/// `sendChangeEmailVerification`'s inline template (values interpolated unescaped)
pub fn change_email_verification(current: &str, new: &str, url: &str) -> String {
    format!(
        r#"
    <div style="font-family: Arial, sans-serif; max-width: 560px; margin: 0 auto; padding: 24px; color: #111;">
      <h2 style="margin: 0 0 16px;">Confirm your new email</h2>
      <p>We received a request to change the email on your Hygo account from <strong>{current}</strong> to <strong>{new}</strong>.</p>
      <p>Click the button below to confirm the change. If you didn't request this, you can safely ignore this email.</p>
      <p style="margin: 24px 0;">
        <a href="{url}" style="background: #111; color: #fff; padding: 12px 20px; border-radius: 6px; text-decoration: none; display: inline-block;">Confirm email change</a>
      </p>
      <p style="font-size: 12px; color: #666; word-break: break-all;">Or paste this link into your browser: {url}</p>
    </div>
  "#
    )
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;

    fn node(name: &str) -> String {
        let renders: Value = serde_json::from_str(include_str!("fixtures/node-renders.json")).unwrap();
        renders[name].as_str().unwrap().to_string()
    }

    #[test]
    fn otp_emails_match_node_renders() {
        for (kind, name) in [
            (OtpEmailType::SignIn, "otp-sign-in-123456"),
            (OtpEmailType::EmailVerification, "otp-email-verification-123456"),
            (OtpEmailType::ForgetPassword, "otp-forget-password-123456"),
            (OtpEmailType::ChangeEmail, "otp-change-email-123456"),
        ] {
            assert_eq!(otp_email("123456", kind, 2026), node(name), "{name}");
        }
        assert_eq!(otp_email("<b>&\"'x", OtpEmailType::SignIn, 2026), node("otp-escape"));
    }

    #[test]
    fn invitation_emails_match_node_renders() {
        assert_eq!(
            invitation_email(
                "new@example.com",
                "owner@example.com",
                "Acme",
                "https://a.hygo.ai/invitation?invitationId=abc&organization=Acme&inviterEmail=owner@example.com",
                2026
            ),
            node("invite-basic")
        );
        assert_eq!(
            invitation_email(
                "x\"<y>@e.com",
                "a&b'<c>",
                &format!("Org <&> \"q\" 'a' {}😀", "é".repeat(3)),
                "https://a.hygo.ai/invitation?invitationId=abc&organization=Org <&> \"q\"&inviterEmail=a&b'<c>",
                2026
            ),
            node("invite-escape")
        );
        assert_eq!(invitation_email("e@x.com", "i@x.com", &"L".repeat(200), "https://x", 2026), node("invite-long"));
    }
}
