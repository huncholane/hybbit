import { ComparisonPage } from "../components/ComparisonPage";
import { fathomComparisonData, fathomExtendedData } from "./comparison-data";
import type { Metadata } from "next";
import { createOGImageUrl } from "@/lib/metadata";

export const metadata: Metadata = {
  title: "Hygo vs Fathom: The Open Source Fathom Alternative",
  description:
    "Looking for a Fathom alternative? Hygo matches its privacy focus and adds session replay, funnels, error tracking, and open-source self-hosting.",
  openGraph: {
    title: "Hygo vs Fathom: More Features, Same Privacy",
    description: "Fathom keeps it simple. Hygo stays simple and adds session replay, funnels, and error tracking.",
    type: "website",
    url: "https://hygo.ai/compare/fathom",
    images: [createOGImageUrl("Hygo vs Fathom: More Features, Same Privacy", "Fathom keeps it simple. Hygo stays simple and adds session replay, funnels, and error tracking.", "Compare")],
  },
  twitter: {
    card: "summary_large_image",
    title: "Hygo vs Fathom Analytics",
    description: "Privacy-first analytics compared. See which offers more value.",
    images: [createOGImageUrl("Hygo vs Fathom Analytics", "Privacy-first analytics compared. See which offers more value.", "Compare")],
  },
  alternates: {
    canonical: "https://hygo.ai/compare/fathom",
  },
};

const structuredData = {
  "@context": "https://schema.org",
  "@graph": [
    {
      "@type": "WebPage",
      "@id": "https://hygo.ai/compare/fathom",
      name: "Hygo vs Fathom Comparison",
      description: "Compare Hygo and Fathom analytics platforms",
      url: "https://hygo.ai/compare/fathom",
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
          name: "Is Hygo open source while Fathom is not?",
          acceptedAnswer: {
            "@type": "Answer",
            text: "Yes. Hygo is fully open source under the AGPL v3 license, meaning you can inspect the code, self-host it, and verify exactly how your data is handled. Fathom is proprietary and closed-source, so you have to trust their claims about data handling.",
          },
        },
        {
          "@type": "Question",
          name: "What features does Hygo have that Fathom doesn't?",
          acceptedAnswer: {
            "@type": "Answer",
            text: "Hygo includes session replay, funnel analysis, user journey visualization (Sankey diagrams), Web Vitals monitoring, error tracking, user profiles, and sessions tracking. Fathom focuses on basic pageview and conversion analytics.",
          },
        },
        {
          "@type": "Question",
          name: "How does pricing compare between Hygo and Fathom?",
          acceptedAnswer: {
            "@type": "Answer",
            text: "Hygo starts at $19/month with events-based pricing and a 7-day free trial. Fathom starts at $15/month with pageview-based pricing. Hygo includes significantly more features at a comparable price point, including session replay, funnels, and error tracking.",
          },
        },
        {
          "@type": "Question",
          name: "Can I self-host Hygo like I can with other tools?",
          acceptedAnswer: {
            "@type": "Answer",
            text: "Yes, Hygo is fully self-hostable. Fathom does not offer self-hosting at all. If data sovereignty and infrastructure control matter to you, Hygo gives you the option to run everything on your own servers.",
          },
        },
        {
          "@type": "Question",
          name: "Is it easy to switch from Fathom to Hygo?",
          acceptedAnswer: {
            "@type": "Answer",
            text: "Yes. Just add Hygo's script tag to your site and data starts collecting immediately. You can run both in parallel during the transition. The setup takes less than 5 minutes.",
          },
        },
      ],
    },
  ],
};

export default function Fathom() {
  return (
    <>
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(structuredData) }} />
      <ComparisonPage
        competitorName="Fathom"
        sections={fathomComparisonData}
        subtitle={fathomExtendedData.subtitle}
        introHeading={fathomExtendedData.introHeading}
        introParagraphs={fathomExtendedData.introParagraphs}
        chooseHygo={fathomExtendedData.chooseHygo}
        chooseCompetitor={fathomExtendedData.chooseCompetitor}
        hygoPricing={fathomExtendedData.hygoPricing}
        competitorPricing={fathomExtendedData.competitorPricing}
        deepDive={fathomExtendedData.deepDive}
        faqItems={fathomExtendedData.faqItems}
        relatedResources={fathomExtendedData.relatedResources}
      />
    </>
  );
}
