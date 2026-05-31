import { ComparisonPage } from "../components/ComparisonPage";
import { posthogComparisonData, posthogExtendedData } from "./comparison-data";
import type { Metadata } from "next";
import { createOGImageUrl } from "@/lib/metadata";

export const metadata: Metadata = {
  title: "Hygo vs PostHog: Simple Analytics Alternative",
  description:
    "Compare Hygo and PostHog. See why Hygo's focused web analytics beats PostHog's complex product suite for teams wanting simplicity without sacrificing power.",
  openGraph: {
    title: "Hygo vs PostHog: Focused Analytics vs Feature Bloat",
    description: "PostHog does everything. Hygo does web analytics perfectly. Compare the approaches.",
    type: "website",
    url: "https://hygo.ai/compare/posthog",
    images: [createOGImageUrl("Hygo vs PostHog: Focused Analytics vs Feature Bloat", "PostHog does everything. Hygo does web analytics perfectly. Compare the approaches.", "Compare")],
  },
  twitter: {
    card: "summary_large_image",
    title: "Hygo vs PostHog Comparison",
    description: "Focused web analytics vs all-in-one platform. Which approach fits your needs?",
    images: [createOGImageUrl("Hygo vs PostHog Comparison", "Focused web analytics vs all-in-one platform. Which approach fits your needs?", "Compare")],
  },
  alternates: {
    canonical: "https://hygo.ai/compare/posthog",
  },
};

const structuredData = {
  "@context": "https://schema.org",
  "@graph": [
    {
      "@type": "WebPage",
      "@id": "https://hygo.ai/compare/posthog",
      name: "Hygo vs PostHog Comparison",
      description: "Compare Hygo and PostHog analytics platforms",
      url: "https://hygo.ai/compare/posthog",
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
          name: "How is Hygo different from PostHog?",
          acceptedAnswer: {
            "@type": "Answer",
            text: "Hygo focuses exclusively on web analytics with a clean, simple interface. PostHog is an all-in-one product suite with analytics, feature flags, A/B testing, surveys, and more. If you primarily need web analytics, Hygo delivers a faster, simpler experience.",
          },
        },
        {
          "@type": "Question",
          name: "Is Hygo really simpler than PostHog?",
          acceptedAnswer: {
            "@type": "Answer",
            text: "Yes. Hygo provides a single-page dashboard where all essential metrics are visible at a glance. PostHog's extensive feature set means more menus, more configuration, and a steeper learning curve, especially for non-technical team members.",
          },
        },
        {
          "@type": "Question",
          name: "Does PostHog have features Hygo doesn't?",
          acceptedAnswer: {
            "@type": "Answer",
            text: "Yes, PostHog offers feature flags, A/B testing, surveys, heatmaps, and a SQL query interface that Hygo doesn't have. These are powerful tools for product teams, but they add complexity. Hygo intentionally focuses on doing web analytics well.",
          },
        },
        {
          "@type": "Question",
          name: "How does self-hosting compare?",
          acceptedAnswer: {
            "@type": "Answer",
            text: "Hygo is straightforward to self-host with a modern TypeScript/ClickHouse stack. PostHog's self-hosted version requires significantly more infrastructure (Kafka, Redis, PostgreSQL, ClickHouse, and more) and is much harder to maintain.",
          },
        },
        {
          "@type": "Question",
          name: "Can I migrate from PostHog to Hygo?",
          acceptedAnswer: {
            "@type": "Answer",
            text: "Yes. Just add Hygo's script tag to your site and data starts flowing immediately. You can run both tools in parallel during the transition. Since Hygo uses a different data model, historical PostHog data won't transfer, but new data collection begins instantly.",
          },
        },
      ],
    },
  ],
};

export default function PostHog() {
  return (
    <>
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(structuredData) }} />
      <ComparisonPage
        competitorName="PostHog"
        sections={posthogComparisonData}
        subtitle={posthogExtendedData.subtitle}
        introHeading={posthogExtendedData.introHeading}
        introParagraphs={posthogExtendedData.introParagraphs}
        chooseHygo={posthogExtendedData.chooseHygo}
        chooseCompetitor={posthogExtendedData.chooseCompetitor}
        hygoPricing={posthogExtendedData.hygoPricing}
        competitorPricing={posthogExtendedData.competitorPricing}
        faqItems={posthogExtendedData.faqItems}
        relatedResources={posthogExtendedData.relatedResources}
      />
    </>
  );
}
