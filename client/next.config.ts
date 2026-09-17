import type { NextConfig } from "next";
import createNextIntlPlugin from "next-intl/plugin";

const withNextIntl = createNextIntlPlugin({
  experimental: {
    srcPath: "./src",
    extract: true,
    messages: {
      sourceLocale: "en",
      path: "./messages",
      format: "json",
      locales: ["en", "de", "fr", "zh", "es", "pl", "it", "ko", "pt", "ja", "cs", "uk"],
    },
  },
});

const nextConfig: NextConfig = {
  // A static export served by the Rust backend (server-rs/src/http/client_app.rs),
  // which also does what proxy.ts and the widget route handler used to do.
  output: "export",
  images: {
    unoptimized: true,
  },
  env: {
    NEXT_PUBLIC_BACKEND_URL: process.env.NEXT_PUBLIC_BACKEND_URL,
    NEXT_PUBLIC_DISABLE_SIGNUP: process.env.NEXT_PUBLIC_DISABLE_SIGNUP,
    NEXT_PUBLIC_LITE_DASHBOARD: process.env.NEXT_PUBLIC_LITE_DASHBOARD,
    NEXT_PUBLIC_APP_VERSION: process.env.npm_package_version,
  },
};

export default withNextIntl(nextConfig);
