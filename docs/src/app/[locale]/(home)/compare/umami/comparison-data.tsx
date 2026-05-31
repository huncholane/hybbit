import { ComparisonSection, FAQItem, PricingInfo, RelatedResource } from "../components/ComparisonPage";

export const umamiComparisonData: ComparisonSection[] = [
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
      { name: "Session Replay", hygoValue: true, competitorValue: false },
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
      { name: "Cookie-free tracking", hygoValue: true, competitorValue: true },
      { name: "No personal data collection", hygoValue: true, competitorValue: true },
      { name: "Daily rotating salt", hygoValue: true, competitorValue: false },
      { name: "Open source", hygoValue: true, competitorValue: true },
      { name: "Self-hostable", hygoValue: true, competitorValue: true },
    ],
  },
  {
    title: "Technical & Pricing",
    features: [
      { name: "Script size", hygoValue: "18KB", competitorValue: "~2KB" },
      { name: "Bypasses ad blockers", hygoValue: true, competitorValue: true },
      { name: "API access", hygoValue: true, competitorValue: true },
      { name: "Starting price", hygoValue: "$19/mo", competitorValue: "$20/mo" },
    ],
  },
];

export const umamiExtendedData = {
  subtitle: "Both are open source and privacy-first, but Hygo offers session replay, funnels, and user journeys that Umami doesn't.",

  introHeading: "Why consider Hygo over Umami?",
  introParagraphs: [
    "Umami is a popular open-source analytics tool known for its tiny 2KB script and simple, clean interface. It's a solid choice for personal blogs and small sites that just need basic traffic metrics. But Umami's simplicity comes at the cost of advanced features: no session replay, no error tracking, no Web Vitals monitoring, and limited organization support for teams.",
    "Hygo shares Umami's open-source DNA and privacy-first values but offers a much deeper feature set. You get session replay to watch how users interact with your site, funnel analysis to find conversion bottlenecks, user journey visualization with Sankey diagrams, and error tracking to catch issues before your users report them. All while maintaining the clean, intuitive dashboard experience that makes simple analytics tools appealing.",
    "On the technical side, Hygo uses ClickHouse for analytics queries, delivering fast performance even at high traffic volumes. Umami supports PostgreSQL and MySQL for self-hosting, which may be more familiar but can struggle with large datasets. Hygo also offers a mature managed cloud service, so you don't have to maintain infrastructure if you'd rather not. If you've outgrown Umami's basic metrics and need analytics that can grow with your product, Hygo is the natural next step.",
  ],

  chooseHygo: [
    "You need session replay to see how users interact with your site",
    "You want error tracking and Web Vitals monitoring built in",
    "You need organization support with team roles and permissions",
    "You want a daily rotating salt option for extra privacy",
    "You need ClickHouse performance for high-traffic analytics",
    "You want a real-time globe view of your visitors",
  ],

  chooseCompetitor: [
    "You want the smallest possible tracking script (2KB)",
    "You prefer PostgreSQL or MySQL over ClickHouse for self-hosting",
    "You only need basic pageview and event tracking",
    "You want a completely free self-hosted solution with no limits",
    "You're running a personal blog or lightweight content site",
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
    name: "Umami",
    model: "Usage-based + flat fee",
    startingPrice: "$20/mo",
    highlights: [
      "Hobby plan at $20/mo for 100k events",
      "Self-hosted version is completely free",
      "Cloud plans scale with usage",
      "No free cloud tier available",
    ],
  } satisfies PricingInfo,

  faqItems: [
    {
      question: "How is Hygo different from Umami?",
      answer: "Both are open-source and privacy-first, but Hygo includes advanced features Umami lacks: session replay, error tracking, Web Vitals monitoring, real-time globe view, and organization support. Hygo also uses ClickHouse for better performance at scale.",
    },
    {
      question: "Can I migrate from Umami to Hygo?",
      answer: "Yes. Just add Hygo's script tag to your site and data starts flowing immediately. You can run both tools in parallel during the transition. Historical Umami data won't transfer, but new data collection begins instantly.",
    },
    {
      question: "Which is easier to self-host?",
      answer: "Both are straightforward to self-host with Docker. Umami supports PostgreSQL/MySQL which may be more familiar. Hygo uses ClickHouse which offers better analytics query performance at scale but is a less common database.",
    },
    {
      question: "Does Hygo have a larger script than Umami?",
      answer: "Yes, Hygo's script is 18KB compared to Umami's 2KB. The additional size enables features like session replay, error tracking, and Web Vitals monitoring. Both are small enough to have negligible impact on page load.",
    },
    {
      question: "Are both GDPR compliant?",
      answer: "Yes. Both Hygo and Umami are cookie-free and don't collect personal data. Hygo adds an extra privacy option with daily rotating salt for user ID hashing, ensuring visitors can't be tracked across days.",
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
      title: "Hygo vs Fathom",
      href: "/compare/fathom",
      description: "Open source vs proprietary privacy analytics",
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
