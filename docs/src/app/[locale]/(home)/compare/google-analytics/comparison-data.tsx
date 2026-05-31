import { ComparisonSection, FAQItem, PricingInfo, RelatedResource } from "../components/ComparisonPage";

export const googleAnalyticsComparisonData: ComparisonSection[] = [
  {
    title: "Analytics Features",
    features: [
      { name: "Real-time analytics", hygoValue: true, competitorValue: true },
      { name: "Custom events", hygoValue: "With attributes", competitorValue: true },
      { name: "Funnels", hygoValue: true, competitorValue: true },
      { name: "User journeys (Sankey)", hygoValue: true, competitorValue: true },
      { name: "Conversion goals", hygoValue: true, competitorValue: true },
      { name: "UTM tracking", hygoValue: true, competitorValue: true },
      { name: "Public dashboards", hygoValue: true, competitorValue: false },
    ],
  },
  {
    title: "Advanced Features",
    features: [
      { name: "Session Replay", hygoValue: true, competitorValue: false },
      { name: "User profiles", hygoValue: true, competitorValue: false },
      { name: "Web Vitals monitoring", hygoValue: true, competitorValue: true },
      { name: "Error tracking", hygoValue: true, competitorValue: false },
      { name: "Real-time globe view", hygoValue: true, competitorValue: false },
      { name: "Autocapture", hygoValue: true, competitorValue: false },
    ],
  },
  {
    title: "Privacy & Open Source",
    features: [
      { name: "Cookie-free tracking", hygoValue: true, competitorValue: false },
      { name: "No personal data collection", hygoValue: true, competitorValue: false },
      { name: "Daily rotating salt", hygoValue: true, competitorValue: false },
      { name: "Open source", hygoValue: true, competitorValue: false },
      { name: "Self-hostable", hygoValue: true, competitorValue: false },
    ],
  },
  {
    title: "Technical & Pricing",
    features: [
      { name: "Script size", hygoValue: "18KB", competitorValue: "371KB" },
      { name: "Bypasses ad blockers", hygoValue: true, competitorValue: false },
      { name: "API access", hygoValue: true, competitorValue: true },
      { name: "Starting price", hygoValue: "$19/mo", competitorValue: "Free" },
    ],
  },
];

export const googleAnalyticsExtendedData = {
  subtitle: "See why privacy-conscious teams are switching from GA4 to Hygo's open-source, cookie-free analytics.",

  introHeading: "Why consider Hygo over Google Analytics?",
  introParagraphs: [
    "Google Analytics is the default choice for most websites, but that doesn't mean it's the best one. GA4's transition left many teams frustrated with a steep learning curve, confusing interface, and data sampling that makes reports unreliable at scale. Meanwhile, privacy regulations like GDPR have made GA4's cookie-dependent tracking a liability, and multiple EU countries have ruled it non-compliant.",
    "Hygo takes a fundamentally different approach. Instead of harvesting user data to power an ad network, Hygo exists solely to give you accurate, actionable analytics. It's cookie-free by default, so you never need consent banners. The single-page dashboard shows everything your team needs without digging through 150+ reports. And because it's open source, you can verify exactly how your data is handled.",
    "The feature gap isn't what you'd expect either. Hygo includes session replay, funnel analysis, user journey visualization, and real-time data without sampling, all capabilities that GA4 either lacks or locks behind the $50,000/year GA360 tier. For teams that want powerful analytics without the complexity, privacy concerns, or vendor lock-in, Hygo is the modern alternative GA4 should have been.",
  ],

  chooseHygo: [
    "You want privacy-first analytics without cookie banners",
    "You need a simple dashboard your whole team can understand",
    "You want to self-host and own 100% of your data",
    "You need session replay, funnels, and user journeys in one tool",
    "You want accurate data without sampling or ad-blocker issues",
    "You prefer open-source software with transparent pricing",
  ],

  chooseCompetitor: [
    "You need deep integration with Google Ads and the Google ecosystem",
    "You require highly customizable reports and dashboards",
    "You need free analytics for very high-traffic sites",
    "Your organization already has workflows built around GA4",
    "You need advanced attribution modeling for paid campaigns",
  ],

  hygoPricing: {
    name: "Hygo",
    model: "Events-based pricing",
    startingPrice: "$19/mo",
    highlights: [
      "7-day free trial, no credit card required",
      "All features included on every plan",
      "Session replay available on Pro plan",
      "Unlimited team members",
    ],
  } satisfies PricingInfo,

  competitorPricing: {
    name: "Google Analytics",
    model: "Free (ad-supported)",
    startingPrice: "Free",
    highlights: [
      "Free for most websites",
      "GA360 starts at ~$50,000/year for enterprises",
      "Data used to power Google's ad network",
      "Limited data retention (2-14 months)",
    ],
  } satisfies PricingInfo,

  faqItems: [
    {
      question: "Is it hard to migrate from Google Analytics to Hygo?",
      answer: "Not at all. Hygo uses a single script tag, so just add it to your site and you'll start collecting data immediately. There's no need to remove GA4 right away; you can run both in parallel to compare.",
    },
    {
      question: "Will I lose historical data if I switch?",
      answer: "Hygo starts collecting data from the moment you install it, so there's no migration of historical GA data. Many teams run both tools in parallel for a transition period before fully switching.",
    },
    {
      question: "Does Hygo work without cookies like GA4's consent mode?",
      answer: "Yes, but differently. Hygo is cookie-free by default, so no consent mode is needed. You never need to show a cookie banner for Hygo, which means you capture 100% of your visitors without any consent friction.",
    },
    {
      question: "Can Hygo track conversions and goals like GA4?",
      answer: "Yes. Hygo supports conversion goals, funnels, and custom events with attributes. While the setup is simpler than GA4's event configuration, you get the same core conversion tracking capabilities.",
    },
    {
      question: "Does Hygo offer real-time analytics?",
      answer: "Yes, Hygo provides real-time data out of the box with no sampling. Unlike GA4 which may sample data on high-traffic properties, Hygo shows every event as it happens.",
    },
  ] satisfies FAQItem[],

  relatedResources: [
    {
      title: "Hygo vs Plausible",
      href: "/compare/plausible",
      description: "Compare two privacy-first analytics platforms",
    },
    {
      title: "Hygo vs PostHog",
      href: "/compare/posthog",
      description: "Focused analytics vs all-in-one product suite",
    },
    {
      title: "Hygo vs Matomo",
      href: "/compare/matomo",
      description: "Modern analytics vs the legacy GA alternative",
    },
    {
      title: "Getting started with Hygo",
      href: "/docs",
      description: "Set up Hygo in under 5 minutes",
    },
    {
      title: "Self-hosting guide",
      href: "/docs/self-hosting",
      description: "Deploy Hygo on your own infrastructure",
    },
    {
      title: "Pricing",
      href: "/pricing",
      description: "Simple, transparent pricing for every team size",
    },
  ] satisfies RelatedResource[],
};
