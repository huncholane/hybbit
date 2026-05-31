import { ComparisonSection, FAQItem, PricingInfo, RelatedResource } from "../components/ComparisonPage";

export const matomoComparisonData: ComparisonSection[] = [
  {
    title: "Analytics Features",
    features: [
      { name: "Real-time analytics", hygoValue: true, competitorValue: true },
      { name: "Custom events", hygoValue: "With attributes", competitorValue: true },
      { name: "Funnels", hygoValue: true, competitorValue: true },
      { name: "User journeys (Sankey)", hygoValue: true, competitorValue: false },
      { name: "Conversion goals", hygoValue: true, competitorValue: true },
      { name: "UTM tracking", hygoValue: true, competitorValue: true },
      { name: "Public dashboards", hygoValue: true, competitorValue: false },
    ],
  },
  {
    title: "Advanced Features",
    features: [
      { name: "Session Replay", hygoValue: true, competitorValue: true },
      { name: "User profiles", hygoValue: true, competitorValue: true },
      { name: "Web Vitals monitoring", hygoValue: true, competitorValue: false },
      { name: "Error tracking", hygoValue: true, competitorValue: false },
      { name: "Real-time globe view", hygoValue: true, competitorValue: false },
      { name: "Autocapture", hygoValue: true, competitorValue: false },
    ],
  },
  {
    title: "Privacy & Open Source",
    features: [
      { name: "Cookie-free tracking", hygoValue: true, competitorValue: "Optional" },
      { name: "No personal data collection", hygoValue: true, competitorValue: false },
      { name: "Daily rotating salt", hygoValue: true, competitorValue: false },
      { name: "Open source", hygoValue: true, competitorValue: true },
      { name: "Self-hostable", hygoValue: true, competitorValue: true },
    ],
  },
  {
    title: "Technical & Pricing",
    features: [
      { name: "Script size", hygoValue: "18KB", competitorValue: "20-50KB" },
      { name: "Bypasses ad blockers", hygoValue: true, competitorValue: false },
      { name: "API access", hygoValue: true, competitorValue: true },
      { name: "Starting price", hygoValue: "$19/mo", competitorValue: "\u20AC19/mo" },
    ],
  },
];

export const matomoExtendedData = {
  subtitle: "Hygo is the modern, simple alternative to Matomo: no PHP, no complex setup, and privacy-first by default.",

  introHeading: "Why consider Hygo over Matomo?",
  introParagraphs: [
    "Matomo (formerly Piwik) has been around since 2007 and positions itself as the open-source Google Analytics alternative. It's feature-rich with 70+ reports, heatmaps, A/B testing, and form analytics. But that breadth comes with Google Analytics-level complexity, and most teams need training just to find the metrics they care about, and the PHP/MySQL stack feels increasingly dated.",
    "Hygo is what a modern analytics tool should look like. A single-page dashboard shows all essential metrics at a glance, with no training required. Privacy works by default: no cookies, no consent banners, no configuration needed. The tech stack (TypeScript, ClickHouse) is built for performance, and the managed cloud option means zero server maintenance. You get session replay, user journeys, Web Vitals, and error tracking without installing plugins.",
    "Matomo's cloud pricing starts at €19/month for just 50k hits, and many useful features require paid plugins on top of that. Hygo starts at $19/month with all features included. If you're tired of Matomo's complexity, maintenance burden, or plugin costs, Hygo offers a dramatically simpler path to the analytics insights your team actually needs.",
  ],

  chooseHygo: [
    "You want a simple single-page dashboard with no training required",
    "You need privacy by default, with no cookie consent configuration needed",
    "You prefer a modern tech stack (Next.js/ClickHouse) over legacy PHP",
    "You want cloud hosting with zero maintenance",
    "You need session replay, user journeys, and Web Vitals built in",
    "You want a 7-day free trial to evaluate before committing",
  ],

  chooseCompetitor: [
    "You need heatmaps, A/B testing, or form analytics",
    "You have strict on-premise requirements for compliance",
    "You rely on the WordPress plugin ecosystem",
    "You need a Google Analytics data import tool",
    "You want a custom report builder with 70+ report types",
  ],

  hygoPricing: {
    name: "Hygo",
    model: "Events-based pricing",
    startingPrice: "$19/mo",
    highlights: [
      "7-day free trial, no credit card required",
      "All features included on every plan",
      "Session replay available on Pro plan",
      "Zero maintenance cloud hosting",
    ],
  } satisfies PricingInfo,

  competitorPricing: {
    name: "Matomo Cloud",
    model: "Pageview-based pricing",
    startingPrice: "\u20AC19/mo",
    highlights: [
      "Starts at 50k hits/month",
      "On-Premise edition available for free (self-host)",
      "Many features require paid plugins on top",
      "Self-hosting requires server maintenance",
    ],
  } satisfies PricingInfo,

  faqItems: [
    {
      question: "Is Hygo really simpler than Matomo?",
      answer: "Yes. Matomo has 70+ reports across 12 sections, inheriting Google Analytics-style complexity. Hygo shows all essential metrics on a single intuitive dashboard. Your team can start using Hygo immediately without training.",
    },
    {
      question: "Does Hygo require cookies like Matomo?",
      answer: "No. Hygo is cookie-free by default and never requires consent banners. Matomo uses cookies by default and requires configuration to achieve cookieless tracking, which can reduce its accuracy.",
    },
    {
      question: "How does self-hosting compare?",
      answer: "Hygo uses a modern stack (TypeScript, ClickHouse) and is straightforward to deploy with Docker. Matomo runs on PHP/MySQL, which is widely supported but requires ongoing maintenance, updates, and security patches. Hygo also offers a managed cloud option.",
    },
    {
      question: "Can I migrate from Matomo to Hygo?",
      answer: "Yes. Add Hygo's script tag to your site and data starts flowing immediately. You can run both tools in parallel during the transition. Hygo's simpler setup means you'll be collecting data within minutes.",
    },
    {
      question: "Does Matomo have features Hygo doesn't?",
      answer: "Yes, Matomo offers heatmaps, A/B testing, form analytics, and a custom report builder that Hygo doesn't have. However, many of these require paid plugins. Hygo focuses on delivering the analytics features most teams actually need, with a much simpler experience.",
    },
  ] satisfies FAQItem[],

  relatedResources: [
    {
      title: "Hygo vs Google Analytics",
      href: "/compare/google-analytics",
      description: "The privacy-first alternative to GA4",
    },
    {
      title: "Hygo vs PostHog",
      href: "/compare/posthog",
      description: "Focused analytics vs all-in-one product suite",
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
