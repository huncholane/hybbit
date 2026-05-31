import "@/app/global.css";
import { Inter } from "next/font/google";
import Script from "next/script";
import type { ReactNode } from "react";
import type { Metadata } from "next";
import { getLocale } from "next-intl/server";

const inter = Inter({
  subsets: ["latin"],
  variable: "--font-inter",
});

export const metadata: Metadata = {
  title: {
    default: "Hygo - Privacy-First Web Analytics Platform",
    template: "%s | Hygo",
  },
  description:
    "Open-source, privacy-focused web analytics platform. Track your website performance without compromising user privacy. Self-hostable alternative to Google Analytics.",
  keywords: [
    "web analytics",
    "privacy analytics",
    "open source analytics",
    "Google Analytics alternative",
    "website tracking",
    "self-hosted analytics",
  ],
  authors: [{ name: "Hygo Team" }],
  creator: "Hygo",
  publisher: "Hygo",
  metadataBase: new URL("https://hygo.ai"),
  openGraph: {
    type: "website",
    locale: "en_US",
    url: "https://hygo.ai",
    siteName: "Hygo",
    title: "Hygo - Privacy-First Web Analytics Platform",
    description:
      "Open-source, privacy-focused web analytics platform. Track your website performance without compromising user privacy.",
    images: [
      {
        url: "/opengraph-image.png",
        width: 1200,
        height: 630,
        alt: "Hygo Analytics Dashboard",
      },
    ],
  },
  twitter: {
    card: "summary_large_image",
    title: "Hygo - Privacy-First Web Analytics Platform",
    description:
      "Open-source, privacy-focused web analytics platform. Track your website performance without compromising user privacy.",
    images: ["/opengraph-image.png"],
    creator: "@yang_frog",
  },
  robots: {
    index: true,
    follow: true,
    googleBot: {
      index: true,
      follow: true,
      "max-video-preview": -1,
      "max-image-preview": "large",
      "max-snippet": -1,
    },
  },
  verification: {
    google: "",
    yandex: "",
    yahoo: "",
  },
};

export default async function Layout({ children }: { children: ReactNode }) {
  const locale = await getLocale();
  return (
    <html lang={locale} suppressHydrationWarning>
      <head>
        <Script id="rewardful-queue" strategy="beforeInteractive">
          {`(function(w,r){w._rwq=r;w[r]=w[r]||function(){(w[r].q=w[r].q||[]).push(arguments)}})(window,'rewardful');`}
        </Script>
      </head>
      <body className={`flex flex-col min-h-screen ${inter.variable} font-sans`}>
        {children}
        <Script src="https://demo.hygo.ai/api/script.js" data-site-id="21" />
        <Script
          src="https://demo.hygo.ai/api/script.js?ns=demo"
          data-site-id="3b023d1a7895"
          data-namespace="hygo_demo"
        />
        <Script src="https://r.wdfl.co/rw.js" data-rewardful="fc3780" strategy="afterInteractive" />
      </body>
    </html>
  );
}
