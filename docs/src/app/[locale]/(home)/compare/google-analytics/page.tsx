import { ComparisonPage } from "../components/ComparisonPage";
import { googleAnalyticsComparisonData, googleAnalyticsExtendedData } from "./comparison-data";
import type { Metadata } from "next";
import { createOGImageUrl } from "@/lib/metadata";

export const metadata: Metadata = {
  title: "Hygo vs Google Analytics: Best Privacy-First Alternative",
  description:
    "Compare Hygo and Google Analytics. Discover why privacy-conscious businesses are switching from GA4 to Hygo's open-source, cookie-free analytics.",
  openGraph: {
    title: "Hygo vs Google Analytics: The Privacy-First Alternative",
    description:
      "Why thousands are switching from Google Analytics to Hygo. Open-source, cookie-free, GDPR compliant.",
    type: "website",
    url: "https://hygo.ai/compare/google-analytics",
    images: [createOGImageUrl("Hygo vs Google Analytics: The Privacy-First Alternative", "Why thousands are switching from Google Analytics to Hygo. Open-source, cookie-free, GDPR compliant.", "Compare")],
  },
  twitter: {
    card: "summary_large_image",
    title: "Hygo vs Google Analytics",
    description: "The privacy-first Google Analytics alternative. Compare features side-by-side.",
    images: [createOGImageUrl("Hygo vs Google Analytics", "The privacy-first Google Analytics alternative. Compare features side-by-side.", "Compare")],
  },
  alternates: {
    canonical: "https://hygo.ai/compare/google-analytics",
  },
};

const structuredData = {
  "@context": "https://schema.org",
  "@graph": [
    {
      "@type": "WebPage",
      "@id": "https://hygo.ai/compare/google-analytics",
      name: "Hygo vs Google Analytics Comparison",
      description: "Compare Hygo and Google Analytics platforms",
      url: "https://hygo.ai/compare/google-analytics",
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
          name: "Why switch from Google Analytics to Hygo?",
          acceptedAnswer: {
            "@type": "Answer",
            text: "Hygo offers privacy-first analytics without cookies, no consent banners needed, GDPR compliance by default, and a simpler interface. Unlike GA4's complex 150+ report system, Hygo shows all essential metrics on a single dashboard.",
          },
        },
        {
          "@type": "Question",
          name: "Is Hygo GDPR compliant unlike Google Analytics?",
          acceptedAnswer: {
            "@type": "Answer",
            text: "Yes. Hygo is GDPR compliant by default with no cookies, no personal data collection, and EU data storage. Google Analytics has faced GDPR issues in multiple EU countries due to data transfers to the US.",
          },
        },
        {
          "@type": "Question",
          name: "Does Hygo offer the same features as GA4?",
          acceptedAnswer: {
            "@type": "Answer",
            text: "Hygo offers all essential analytics features plus session replay, funnels, user journeys, and real-time data. While GA4 has more advanced enterprise features, Hygo provides what most businesses actually need without the complexity.",
          },
        },
        {
          "@type": "Question",
          name: "Can Hygo track conversions and goals like GA4?",
          acceptedAnswer: {
            "@type": "Answer",
            text: "Yes. Hygo supports conversion goals, funnels, and custom events with attributes. While the setup is simpler than GA4's event configuration, you get the same core conversion tracking capabilities.",
          },
        },
        {
          "@type": "Question",
          name: "Does Hygo offer real-time analytics?",
          acceptedAnswer: {
            "@type": "Answer",
            text: "Yes, Hygo provides real-time data out of the box with no sampling. Unlike GA4 which may sample data on high-traffic properties, Hygo shows every event as it happens.",
          },
        },
      ],
    },
  ],
};

export default function GoogleAnalytics() {
  return (
    <>
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(structuredData) }} />
      <ComparisonPage
        competitorName="Google Analytics"
        sections={googleAnalyticsComparisonData}
        subtitle={googleAnalyticsExtendedData.subtitle}
        introHeading={googleAnalyticsExtendedData.introHeading}
        introParagraphs={googleAnalyticsExtendedData.introParagraphs}
        chooseHygo={googleAnalyticsExtendedData.chooseHygo}
        chooseCompetitor={googleAnalyticsExtendedData.chooseCompetitor}
        hygoPricing={googleAnalyticsExtendedData.hygoPricing}
        competitorPricing={googleAnalyticsExtendedData.competitorPricing}
        faqItems={googleAnalyticsExtendedData.faqItems}
        relatedResources={googleAnalyticsExtendedData.relatedResources}
      />
    </>
  );
}
