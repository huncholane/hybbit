import { ComparisonPage } from "../components/ComparisonPage";
import { plausibleComparisonData, plausibleExtendedData } from "./comparison-data";
import type { Metadata } from "next";
import { createOGImageUrl } from "@/lib/metadata";

export const metadata: Metadata = {
  title: "Hygo vs Plausible: The Open Source Plausible Alternative",
  description:
    "Looking for a Plausible alternative? Hygo is open-source and privacy-first too, plus session replay, funnels, user journeys, and error tracking.",
  openGraph: {
    title: "Hygo vs Plausible: Which Privacy-First Analytics Wins?",
    description: "Both respect privacy, but Hygo offers more power. Compare session replay, funnels, and pricing.",
    type: "website",
    url: "https://hygo.ai/compare/plausible",
    images: [createOGImageUrl("Hygo vs Plausible: Which Privacy-First Analytics Wins?", "Both respect privacy, but Hygo offers more power. Compare session replay, funnels, and pricing.", "Compare")],
  },
  twitter: {
    card: "summary_large_image",
    title: "Hygo vs Plausible Comparison",
    description: "Privacy-first analytics showdown. See which platform offers more value.",
    images: [createOGImageUrl("Hygo vs Plausible Comparison", "Privacy-first analytics showdown. See which platform offers more value.", "Compare")],
  },
  alternates: {
    canonical: "https://hygo.ai/compare/plausible",
  },
};

const structuredData = {
  "@context": "https://schema.org",
  "@graph": [
    {
      "@type": "WebPage",
      "@id": "https://hygo.ai/compare/plausible",
      name: "Hygo vs Plausible Comparison",
      description: "Compare Hygo and Plausible analytics platforms",
      url: "https://hygo.ai/compare/plausible",
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
          name: "How does Hygo compare to Plausible?",
          acceptedAnswer: {
            "@type": "Answer",
            text: "Both Hygo and Plausible are privacy-first analytics platforms, but Hygo offers more advanced features like session replay, funnels, user journeys, and error tracking while maintaining simplicity.",
          },
        },
        {
          "@type": "Question",
          name: "Does Hygo have features Plausible doesn't?",
          acceptedAnswer: {
            "@type": "Answer",
            text: "Yes. Hygo includes session replay, funnel analysis, user journey visualization (Sankey diagrams), Web Vitals monitoring, error tracking, and public dashboards that Plausible doesn't offer.",
          },
        },
        {
          "@type": "Question",
          name: "Which is more affordable, Hygo or Plausible?",
          acceptedAnswer: {
            "@type": "Answer",
            text: "Plausible starts at $9/month for 10k pageviews, while Hygo starts at $19/month for events-based pricing. Hygo includes more features at each price point, including session replay, funnels, and error tracking.",
          },
        },
        {
          "@type": "Question",
          name: "Can I self-host Hygo like Plausible?",
          acceptedAnswer: {
            "@type": "Answer",
            text: "Yes, Hygo is fully self-hostable under the AGPL v3 license. Both use ClickHouse for fast analytics queries. Hygo's stack is TypeScript-based, while Plausible uses Elixir.",
          },
        },
        {
          "@type": "Question",
          name: "Does Hygo have session replay?",
          acceptedAnswer: {
            "@type": "Answer",
            text: "Yes, session replay is one of the biggest differentiators. Hygo offers session replay on the Pro plan, allowing you to watch how users interact with your site. Plausible does not offer this feature at any price point.",
          },
        },
      ],
    },
  ],
};

export default function Plausible() {
  return (
    <>
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(structuredData) }} />
      <ComparisonPage
        competitorName="Plausible"
        sections={plausibleComparisonData}
        subtitle={plausibleExtendedData.subtitle}
        introHeading={plausibleExtendedData.introHeading}
        introParagraphs={plausibleExtendedData.introParagraphs}
        chooseHygo={plausibleExtendedData.chooseHygo}
        chooseCompetitor={plausibleExtendedData.chooseCompetitor}
        hygoPricing={plausibleExtendedData.hygoPricing}
        competitorPricing={plausibleExtendedData.competitorPricing}
        deepDive={plausibleExtendedData.deepDive}
        faqItems={plausibleExtendedData.faqItems}
        relatedResources={plausibleExtendedData.relatedResources}
      />
    </>
  );
}
