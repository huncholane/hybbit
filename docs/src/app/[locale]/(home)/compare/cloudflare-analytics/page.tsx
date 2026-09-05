import { ComparisonPage } from "../components/ComparisonPage";
import { cloudflareAnalyticsComparisonData, cloudflareAnalyticsExtendedData } from "./comparison-data";
import type { Metadata } from "next";
import { createOGImageUrl } from "@/lib/metadata";

export const metadata: Metadata = {
  title: "Hygo: The Full-Featured Cloudflare Analytics Alternative",
  description:
    "Looking for a Cloudflare Web Analytics alternative? Hygo adds session replay, funnels, custom events, and real referrer data, with a free tier included.",
  openGraph: {
    title: "Hygo vs Cloudflare Analytics: Basic vs Full-Featured",
    description: "Cloudflare is free but limited. Hygo offers the full analytics experience. Compare features.",
    type: "website",
    url: "https://hygo.ai/compare/cloudflare-analytics",
    images: [createOGImageUrl("Hygo vs Cloudflare Analytics: Basic vs Full-Featured", "Cloudflare is free but limited. Hygo offers the full analytics experience. Compare features.", "Compare")],
  },
  twitter: {
    card: "summary_large_image",
    title: "Hygo vs Cloudflare Analytics",
    description: "Free basic analytics vs full-featured platform. See the difference.",
    images: [createOGImageUrl("Hygo vs Cloudflare Analytics", "Free basic analytics vs full-featured platform. See the difference.", "Compare")],
  },
  alternates: {
    canonical: "https://hygo.ai/compare/cloudflare-analytics",
  },
};

const structuredData = {
  "@context": "https://schema.org",
  "@graph": [
    {
      "@type": "WebPage",
      "@id": "https://hygo.ai/compare/cloudflare-analytics",
      name: "Hygo vs Cloudflare Analytics Comparison",
      description: "Compare Hygo and Cloudflare Web Analytics",
      url: "https://hygo.ai/compare/cloudflare-analytics",
      isPartOf: {
        "@type": "WebSite",
        name: "Hygo",
        url: "https://hygo.ai",
      },
    },
    {
      "@type": "FAQPage",
      mainEntity: [
        {
          "@type": "Question",
          name: "Why is Cloudflare Analytics data inaccurate?",
          acceptedAnswer: {
            "@type": "Answer",
            text: "Cloudflare Analytics samples only about 10% of your traffic and extrapolates the rest. This means visitor counts are often significantly overcounted and you can't trust the exact numbers. Hygo processes 100% of your events with no sampling.",
          },
        },
        {
          "@type": "Question",
          name: "Do I need Cloudflare CDN to use Cloudflare Analytics?",
          acceptedAnswer: {
            "@type": "Answer",
            text: "Yes. Cloudflare Analytics requires routing your DNS through Cloudflare. Hygo works with any website regardless of CDN or hosting provider. Just add a single script tag.",
          },
        },
        {
          "@type": "Question",
          name: "What features does Cloudflare Analytics lack?",
          acceptedAnswer: {
            "@type": "Answer",
            text: "Cloudflare Analytics doesn't support custom events, conversion goals, UTM campaign tracking, session replay, funnels, user journeys, bounce rate, visit duration, entry/exit pages, or an API. It only provides basic traffic metrics with sampled data.",
          },
        },
        {
          "@type": "Question",
          name: "How long does Cloudflare keep my data?",
          acceptedAnswer: {
            "@type": "Answer",
            text: "Cloudflare retains analytics data for only 6 months. Hygo retains data for 3-5+ years depending on your plan, and you can export your data at any time.",
          },
        },
        {
          "@type": "Question",
          name: "Can I use Hygo alongside Cloudflare Analytics?",
          acceptedAnswer: {
            "@type": "Answer",
            text: "Yes. Many teams add Hygo for detailed analytics while keeping Cloudflare for basic CDN-level traffic monitoring. Just add Hygo's script tag to your site, and it works alongside any other analytics tool.",
          },
        },
      ],
    },
  ],
};

export default function CloudflareAnalytics() {
  return (
    <>
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(structuredData) }} />
      <ComparisonPage
        competitorName="Cloudflare Analytics"
        sections={cloudflareAnalyticsComparisonData}
        subtitle={cloudflareAnalyticsExtendedData.subtitle}
        introHeading={cloudflareAnalyticsExtendedData.introHeading}
        introParagraphs={cloudflareAnalyticsExtendedData.introParagraphs}
        chooseHygo={cloudflareAnalyticsExtendedData.chooseHygo}
        chooseCompetitor={cloudflareAnalyticsExtendedData.chooseCompetitor}
        hygoPricing={cloudflareAnalyticsExtendedData.hygoPricing}
        competitorPricing={cloudflareAnalyticsExtendedData.competitorPricing}
        deepDive={cloudflareAnalyticsExtendedData.deepDive}
        faqItems={cloudflareAnalyticsExtendedData.faqItems}
        relatedResources={cloudflareAnalyticsExtendedData.relatedResources}
      />
    </>
  );
}
