import { ComparisonSection, FAQItem, PricingInfo, RelatedResource } from "../components/ComparisonPage";

export const posthogComparisonData: ComparisonSection[] = [
  {
    title: "Analytics Features",
    features: [
      { name: "Real-time analytics", hygoValue: true, competitorValue: true },
      { name: "Custom events", hygoValue: "With attributes", competitorValue: "With properties" },
      { name: "Funnels", hygoValue: true, competitorValue: true },
      { name: "User journeys (Sankey)", hygoValue: true, competitorValue: true },
      { name: "Conversion goals", hygoValue: true, competitorValue: true },
      { name: "UTM tracking", hygoValue: true, competitorValue: true },
      { name: "Public dashboards", hygoValue: true, competitorValue: true },
    ],
  },
  {
    title: "Advanced Features",
    features: [
      { name: "Session Replay", hygoValue: true, competitorValue: true },
      { name: "User profiles", hygoValue: true, competitorValue: true },
      { name: "Web Vitals monitoring", hygoValue: true, competitorValue: true },
      { name: "Error tracking", hygoValue: true, competitorValue: true },
      { name: "Real-time globe view", hygoValue: true, competitorValue: false },
      { name: "Autocapture", hygoValue: true, competitorValue: true },
    ],
  },
  {
    title: "Privacy & Open Source",
    features: [
      { name: "Cookie-free tracking", hygoValue: true, competitorValue: "Optional" },
      { name: "No personal data collection", hygoValue: true, competitorValue: false },
      { name: "Daily rotating salt", hygoValue: true, competitorValue: false },
      { name: "Open source", hygoValue: true, competitorValue: true },
      { name: "Self-hostable", hygoValue: true, competitorValue: "Very difficult" },
    ],
  },
  {
    title: "Technical & Pricing",
    features: [
      { name: "Script size", hygoValue: "18KB", competitorValue: "~60KB" },
      { name: "Bypasses ad blockers", hygoValue: true, competitorValue: "With proxy" },
      { name: "API access", hygoValue: true, competitorValue: true },
      { name: "Starting price", hygoValue: "$19/mo", competitorValue: "Free" },
    ],
  },
];

export const posthogExtendedData = {
  subtitle: "Hygo's focused web analytics vs PostHog's complex product suite. See which approach fits your team.",

  introHeading: "Why consider Hygo over PostHog?",
  introParagraphs: [
    "PostHog is an ambitious all-in-one product analytics platform that bundles analytics, session replay, feature flags, A/B testing, and surveys into a single tool. It's powerful, but that power comes with significant complexity. Teams often find themselves spending more time configuring PostHog than actually using it, and the ~60KB script can noticeably impact page performance.",
    "Hygo takes the opposite approach: do web analytics exceptionally well instead of doing everything adequately. The single-page dashboard gives your entire team instant access to the metrics that matter, with no training required. Non-technical team members can understand user behavior, track conversions, and watch session replays without learning a complex query language or navigating dozens of menus.",
    "Privacy is another key difference. Hygo is cookie-free by default and never collects personal data, with no configuration needed. PostHog uses cookies by default and requires setup to achieve privacy compliance. Self-hosting is also dramatically simpler: Hygo runs on TypeScript and ClickHouse, while PostHog requires Kafka, Redis, PostgreSQL, and ClickHouse. If you need focused, privacy-first web analytics that your whole team can use from day one, Hygo is the better fit.",
  ],

  chooseHygo: [
    "You want focused web analytics without the bloat",
    "You need a dashboard your non-technical team can use immediately",
    "You want privacy-first analytics that's cookie-free by default",
    "You prefer a lightweight script (18KB vs ~60KB)",
    "You want simple, predictable pricing without usage surprises",
    "You need fast self-hosting without complex infrastructure",
  ],

  chooseCompetitor: [
    "You need feature flags and A/B testing in your analytics tool",
    "You want heatmaps out of the box",
    "You need a SQL query interface for custom analysis",
    "You want surveys integrated with your analytics",
    "You need a mobile app for on-the-go analytics",
    "You prefer an all-in-one product analytics platform",
  ],

  hygoPricing: {
    name: "Hygo",
    model: "Events-based pricing",
    startingPrice: "$19/mo",
    highlights: [
      "7-day free trial, no credit card required",
      "All features included, no add-on costs",
      "Session replay available on Pro plan",
      "Predictable billing with no overages",
    ],
  } satisfies PricingInfo,

  competitorPricing: {
    name: "PostHog",
    model: "Usage-based per product",
    startingPrice: "Free",
    highlights: [
      "Generous free tier (1M events/month for analytics)",
      "Each product (replay, flags, surveys) billed separately",
      "Costs can scale quickly with multiple products enabled",
      "Self-hosting is free but complex to operate",
    ],
  } satisfies PricingInfo,

  faqItems: [
    {
      question: "How is Hygo different from PostHog?",
      answer: "Hygo focuses exclusively on web analytics with a clean, simple interface. PostHog is an all-in-one product suite with analytics, feature flags, A/B testing, surveys, and more. If you primarily need web analytics, Hygo delivers a faster, simpler experience.",
    },
    {
      question: "Is Hygo really simpler than PostHog?",
      answer: "Yes. Hygo provides a single-page dashboard where all essential metrics are visible at a glance. PostHog's extensive feature set means more menus, more configuration, and a steeper learning curve, especially for non-technical team members.",
    },
    {
      question: "Does PostHog have features Hygo doesn't?",
      answer: "Yes, PostHog offers feature flags, A/B testing, surveys, heatmaps, and a SQL query interface that Hygo doesn't have. These are powerful tools for product teams, but they add complexity. Hygo intentionally focuses on doing web analytics well.",
    },
    {
      question: "How does self-hosting compare?",
      answer: "Hygo is straightforward to self-host with a modern TypeScript/ClickHouse stack. PostHog's self-hosted version requires significantly more infrastructure (Kafka, Redis, PostgreSQL, ClickHouse, and more) and is much harder to maintain.",
    },
    {
      question: "Can I migrate from PostHog to Hygo?",
      answer: "Yes. Just add Hygo's script tag to your site and data starts flowing immediately. You can run both tools in parallel during the transition. Since Hygo uses a different data model, historical PostHog data won't transfer, but new data collection begins instantly.",
    },
  ] satisfies FAQItem[],

  relatedResources: [
    {
      title: "Hygo vs Google Analytics",
      href: "/compare/google-analytics",
      description: "The privacy-first alternative to GA4",
    },
    {
      title: "Hygo vs Plausible",
      href: "/compare/plausible",
      description: "Compare two privacy-first analytics platforms",
    },
    {
      title: "Hygo vs Umami",
      href: "/compare/umami",
      description: "Two open-source analytics tools compared",
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
