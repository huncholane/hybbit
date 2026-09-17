// Render the OTP and invitation emails exactly as server/src/lib/email/email.ts does,
// for fixed inputs, so the Rust templates can be compared byte for byte. Regenerates
// src/email/fixtures/node-renders.json: npx tsx render-emails.mts <out.json> (from server/).
import { render } from "../../../server/node_modules/@react-email/components/dist/index.mjs";
import { writeFileSync } from "node:fs";
import { OtpEmail } from "../../../server/src/lib/email/templates/OtpEmail.tsx";
import { InvitationEmail } from "../../../server/src/lib/email/templates/InvitationEmail.tsx";

const out: Record<string, string> = {};
for (const type of ["sign-in", "email-verification", "forget-password", "change-email"] as const) {
  out[`otp-${type}-123456`] = await render(OtpEmail({ otp: "123456", type }));
}
out["otp-escape"] = await render(OtpEmail({ otp: `<b>&"'x`, type: "sign-in" }));
out["invite-basic"] = await render(
  InvitationEmail({
    email: "new@example.com",
    invitedBy: "owner@example.com",
    organizationName: "Acme",
    inviteLink: "https://a.hygo.ai/invitation?invitationId=abc&organization=Acme&inviterEmail=owner@example.com",
  })
);
out["invite-escape"] = await render(
  InvitationEmail({
    email: `x"<y>@e.com`,
    invitedBy: `a&b'<c>`,
    organizationName: `Org <&> "q" 'a' ` + "é".repeat(3) + "😀",
    inviteLink: `https://a.hygo.ai/invitation?invitationId=abc&organization=Org <&> "q"&inviterEmail=a&b'<c>`,
  })
);
out["invite-long"] = await render(
  InvitationEmail({ email: "e@x.com", invitedBy: "i@x.com", organizationName: "L".repeat(200), inviteLink: "https://x" })
);
writeFileSync(process.argv[2], JSON.stringify(out, null, 1));
process.exit(0);
