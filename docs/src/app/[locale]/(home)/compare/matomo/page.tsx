import { ComparisonPage } from "../components/ComparisonPage";
import { matomoComparisonData, matomoExtendedData } from "./comparison-data";
import type { Metadata } from "next";
import { createOGImageUrl } from "@/lib/metadata";

export const metadata: Metadata = {
  title: "Hygo vs Matomo: Modern Analytics Alternative",
  description:
    "Compare Hygo and Matomo analytics. See how Hygo offers simpler setup, modern UI, privacy by default, and zero maintenance vs Matomo's complex PHP-based system.",
  openGraph: {
    title: "Hygo vs Matomo: Which Analytics Platform is Right for You?",
    description: "Side-by-side comparison of Hygo and Matomo. Modern, privacy-first analytics vs legacy PHP system.",
    type: "website",
    url: "https://hygo.ai/compare/matomo",
    images: [createOGImageUrl("Hygo vs Matomo: Which Analytics Platform is Right for You?", "Side-by-side comparison of Hygo and Matomo. Modern, privacy-first analytics vs legacy PHP system.", "Compare")],
  },
  twitter: {
    card: "summary_large_image",
    title: "Hygo vs Matomo Comparison",
    description: "Compare Hygo and Matomo analytics. See which open-source platform fits your needs.",
    images: [createOGImageUrl("Hygo vs Matomo Comparison", "Compare Hygo and Matomo analytics. See which open-source platform fits your needs.", "Compare")],
  },
  alternates: {
    canonical: "https://hygo.ai/compare/matomo",
  },
};

const structuredData = {
  "@context": "https://schema.org",
  "@graph": [
    {
      "@type": "WebPage",
      "@id": "https://hygo.ai/compare/matomo",
      name: "Hygo vs Matomo Comparison",
      description: "Compare Hygo and Matomo analytics platforms",
      url: "https://hygo.ai/compare/matomo",
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
          name: "Is Hygo really simpler than Matomo?",
          acceptedAnswer: {
            "@type": "Answer",
            text: "Yes. Matomo has 70+ reports across 12 sections, inheriting Google Analytics-style complexity. Hygo shows all essential metrics on a single intuitive dashboard. Your team can start using Hygo immediately without training.",
          },
        },
        {
          "@type": "Question",
          name: "Does Hygo require cookies like Matomo?",
          acceptedAnswer: {
            "@type": "Answer",
            text: "No. Hygo is cookie-free by default and never requires consent banners. Matomo uses cookies by default and requires configuration to achieve cookieless tracking, which can reduce its accuracy.",
          },
        },
        {
          "@type": "Question",
          name: "How does self-hosting compare?",
          acceptedAnswer: {
            "@type": "Answer",
            text: "Hygo uses a modern stack (TypeScript, ClickHouse) and is straightforward to deploy with Docker. Matomo runs on PHP/MySQL, which is widely supported but requires ongoing maintenance, updates, and security patches. Hygo also offers a managed cloud option.",
          },
        },
        {
          "@type": "Question",
          name: "Can I migrate from Matomo to Hygo?",
          acceptedAnswer: {
            "@type": "Answer",
            text: "Yes. Add Hygo's script tag to your site and data starts flowing immediately. You can run both tools in parallel during the transition. Hygo's simpler setup means you'll be collecting data within minutes.",
          },
        },
        {
          "@type": "Question",
          name: "Does Matomo have features Hygo doesn't?",
          acceptedAnswer: {
            "@type": "Answer",
            text: "Yes, Matomo offers heatmaps, A/B testing, form analytics, and a custom report builder that Hygo doesn't have. However, many of these require paid plugins. Hygo focuses on delivering the analytics features most teams actually need, with a much simpler experience.",
          },
        },
      ],
    },
  ],
};

export default function Matomo() {
  return (
    <>
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(structuredData) }} />
      <ComparisonPage
        competitorName="Matomo"
        sections={matomoComparisonData}
        subtitle={matomoExtendedData.subtitle}
        introHeading={matomoExtendedData.introHeading}
        introParagraphs={matomoExtendedData.introParagraphs}
        chooseHygo={matomoExtendedData.chooseHygo}
        chooseCompetitor={matomoExtendedData.chooseCompetitor}
        hygoPricing={matomoExtendedData.hygoPricing}
        competitorPricing={matomoExtendedData.competitorPricing}
        faqItems={matomoExtendedData.faqItems}
        relatedResources={matomoExtendedData.relatedResources}
      />
    </>
  );
}
