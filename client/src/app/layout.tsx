import { Inter } from "next/font/google";
import { LOCALE_BOOTSTRAP_SCRIPT, LOCALE_PENDING_STYLE } from "../i18n/bootstrapScript";
import { IntlProvider } from "../i18n/IntlProvider";
import { cn } from "../lib/utils";
import "./globals.css";
import { Providers } from "./Providers";

const inter = Inter({ subsets: ["latin"] });

// The client is a static export served by the Rust backend. Prerendering sees no
// request, so search params read as empty instead of failing the build; pages whose
// markup depends on them render in the browser only (see components/ClientOnly.tsx).
export const dynamic = "force-static";

// The locale is chosen in the browser: the bootstrap script sets <html lang> before
// paint and IntlProvider loads the catalog.
export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <style dangerouslySetInnerHTML={{ __html: LOCALE_PENDING_STYLE }} />
        <script dangerouslySetInnerHTML={{ __html: LOCALE_BOOTSTRAP_SCRIPT }} />
      </head>
      <body className={cn("bg-background text-foreground h-full", inter.className)} suppressHydrationWarning>
        <IntlProvider>
          <Providers>{children}</Providers>
        </IntlProvider>
      </body>
    </html>
  );
}
