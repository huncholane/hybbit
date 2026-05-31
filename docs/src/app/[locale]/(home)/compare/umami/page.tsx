import { ComparisonPage } from "../components/ComparisonPage";
import { umamiComparisonData, umamiExtendedData } from "./comparison-data";
import type { Metadata } from "next";
import { createOGImageUrl } from "@/lib/metadata";

export const metadata: Metadata = {
  title: "Hygo vs Umami: Open-Source Analytics Alternative",
  description:
    "Compare Hygo and Umami analytics. Both are open-source and privacy-focused, but Hygo offers advanced features like session replay, funnels, and a managed cloud option.",
  openGraph: {
    title: "Hygo vs Umami: Open-Source Analytics Head-to-Head",
    description: "Two open-source analytics platforms compared. See which offers more features and flexibility.",
    type: "website",
    url: "https://hygo.ai/compare/umami",
    images: [createOGImageUrl("Hygo vs Umami: Open-Source Analytics Head-to-Head", "Two open-source analytics platforms compared. See which offers more features and flexibility.", "Compare")],
  },
  twitter: {
    card: "summary_large_image",
    title: "Hygo vs Umami Comparison",
    description: "Open-source analytics showdown. Compare features, hosting options, and more.",
    images: [createOGImageUrl("Hygo vs Umami Comparison", "Open-source analytics showdown. Compare features, hosting options, and more.", "Compare")],
  },
  alternates: {
    canonical: "https://hygo.ai/compare/umami",
  },
};

const structuredData = {
  "@context": "https://schema.org",
  "@graph": [
    {
      "@type": "WebPage",
      "@id": "https://hygo.ai/compare/umami",
      name: "Hygo vs Umami Comparison",
      description: "Compare Hygo and Umami analytics platforms",
      url: "https://hygo.ai/compare/umami",
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
          name: "How is Hygo different from Umami?",
          acceptedAnswer: {
            "@type": "Answer",
            text: "Both are open-source and privacy-first, but Hygo includes advanced features Umami lacks: session replay, error tracking, Web Vitals monitoring, real-time globe view, and organization support. Hygo also uses ClickHouse for better performance at scale.",
          },
        },
        {
          "@type": "Question",
          name: "Can I migrate from Umami to Hygo?",
          acceptedAnswer: {
            "@type": "Answer",
            text: "Yes. Just add Hygo's script tag to your site and data starts flowing immediately. You can run both tools in parallel during the transition. Historical Umami data won't transfer, but new data collection begins instantly.",
          },
        },
        {
          "@type": "Question",
          name: "Which is easier to self-host?",
          acceptedAnswer: {
            "@type": "Answer",
            text: "Both are straightforward to self-host with Docker. Umami supports PostgreSQL/MySQL which may be more familiar. Hygo uses ClickHouse which offers better analytics query performance at scale but is a less common database.",
          },
        },
        {
          "@type": "Question",
          name: "Does Hygo have a larger script than Umami?",
          acceptedAnswer: {
            "@type": "Answer",
            text: "Yes, Hygo's script is 18KB compared to Umami's 2KB. The additional size enables features like session replay, error tracking, and Web Vitals monitoring. Both are small enough to have negligible impact on page load.",
          },
        },
        {
          "@type": "Question",
          name: "Are both GDPR compliant?",
          acceptedAnswer: {
            "@type": "Answer",
            text: "Yes. Both Hygo and Umami are cookie-free and don't collect personal data. Hygo adds an extra privacy option with daily rotating salt for user ID hashing, ensuring visitors can't be tracked across days.",
          },
        },
      ],
    },
  ],
};

export default function Umami() {
  return (
    <>
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(structuredData) }} />
      <ComparisonPage
        competitorName="Umami"
        sections={umamiComparisonData}
        subtitle={umamiExtendedData.subtitle}
        introHeading={umamiExtendedData.introHeading}
        introParagraphs={umamiExtendedData.introParagraphs}
        chooseHygo={umamiExtendedData.chooseHygo}
        chooseCompetitor={umamiExtendedData.chooseCompetitor}
        hygoPricing={umamiExtendedData.hygoPricing}
        competitorPricing={umamiExtendedData.competitorPricing}
        faqItems={umamiExtendedData.faqItems}
        relatedResources={umamiExtendedData.relatedResources}
      />
    </>
  );
}
