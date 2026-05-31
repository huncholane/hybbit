import { ComparisonSection, FAQItem, PricingInfo, RelatedResource } from "../components/ComparisonPage";

export const fathomComparisonData: ComparisonSection[] = [
  {
    title: "Analytics Features",
    features: [
      { name: "Real-time analytics", hygoValue: true, competitorValue: true },
      { name: "Custom events", hygoValue: "With attributes", competitorValue: "Basic" },
      { name: "Funnels", hygoValue: true, competitorValue: false },
      { name: "User journeys (Sankey)", hygoValue: true, competitorValue: false },
      { name: "Conversion goals", hygoValue: true, competitorValue: true },
      { name: "UTM tracking", hygoValue: true, competitorValue: true },
      { name: "Public dashboards", hygoValue: true, competitorValue: true },
    ],
  },
  {
    title: "Advanced Features",
    features: [
      { name: "Session Replay", hygoValue: true, competitorValue: false },
      { name: "User profiles", hygoValue: true, competitorValue: false },
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
      { name: "Open source", hygoValue: true, competitorValue: false },
      { name: "Self-hostable", hygoValue: true, competitorValue: false },
    ],
  },
  {
    title: "Technical & Pricing",
    features: [
      { name: "Script size", hygoValue: "18KB", competitorValue: "~2KB" },
      { name: "Bypasses ad blockers", hygoValue: true, competitorValue: true },
      { name: "API access", hygoValue: true, competitorValue: true },
      { name: "Starting price", hygoValue: "$19/mo", competitorValue: "$15/mo" },
    ],
  },
];

export const fathomExtendedData = {
  subtitle: "Both are privacy-first, but Hygo is open source with session replay, funnels, and self-hosting that Fathom doesn't offer.",

  introHeading: "Why consider Hygo over Fathom?",
  introParagraphs: [
    "Fathom Analytics is a well-respected privacy-first analytics tool known for its clean interface and cookie-free tracking. It's a solid choice for websites that need simple traffic metrics without the complexity of Google Analytics. But Fathom is intentionally limited to basic web analytics: no session replay, no funnel analysis, no user journey visualization, and it's entirely closed-source with no self-hosting option.",
    "Hygo shares Fathom's commitment to privacy and simplicity but extends far beyond basic web metrics. You get session replay to see exactly how users interact with your site, funnel analysis to identify conversion bottlenecks, user journey visualization with Sankey diagrams, Web Vitals monitoring, and error tracking. This means you can understand not just how many visitors you get, but how they convert, where they drop off, and what issues they encounter.",
    "Transparency is another major difference. Hygo is fully open source under the AGPL v3 license, so you can inspect every line of code and self-host on your own infrastructure. Fathom is proprietary and cloud-only, so you're trusting their claims about data handling without the ability to verify. If you love Fathom's privacy-first approach but need deeper analytics, code transparency, and the freedom to self-host, Hygo gives you all of that.",
  ],

  chooseHygo: [
    "You want open-source software you can audit and self-host",
    "You need session replay, funnels, and user journey visualization",
    "You want a 7-day free trial to evaluate before committing",
    "You need error tracking and Web Vitals monitoring",
    "You prefer events-based pricing over pageview-based",
    "You want full code transparency (AGPL v3)",
  ],

  chooseCompetitor: [
    "You want the smallest possible tracking script (2KB)",
    "You prefer a more established product with a longer track record",
    "You only need basic pageview and conversion tracking",
    "You don't want to worry about self-hosting or infrastructure",
  ],

  hygoPricing: {
    name: "Hygo",
    model: "Events-based pricing",
    startingPrice: "$19/mo",
    highlights: [
      "7-day free trial, no credit card required",
      "Session replay available on Pro plan",
      "Funnels, user journeys, and error tracking included",
      "Self-hosting option available (free)",
    ],
  } satisfies PricingInfo,

  competitorPricing: {
    name: "Fathom",
    model: "Pageview-based pricing",
    startingPrice: "$15/mo",
    highlights: [
      "Starts at 100k pageviews/month",
      "No free tier available",
      "All features included on every plan",
      "Cloud-only, no self-hosting option",
    ],
  } satisfies PricingInfo,

  faqItems: [
    {
      question: "Is Hygo open source while Fathom is not?",
      answer: "Yes. Hygo is fully open source under the AGPL v3 license, meaning you can inspect the code, self-host it, and verify exactly how your data is handled. Fathom is proprietary and closed-source, so you have to trust their claims about data handling.",
    },
    {
      question: "What features does Hygo have that Fathom doesn't?",
      answer: "Hygo includes session replay, funnel analysis, user journey visualization (Sankey diagrams), Web Vitals monitoring, error tracking, user profiles, and sessions tracking. Fathom focuses on basic pageview and conversion analytics.",
    },
    {
      question: "How does pricing compare between Hygo and Fathom?",
      answer: "Hygo starts at $19/month with events-based pricing and a 7-day free trial. Fathom starts at $15/month with pageview-based pricing. Hygo includes significantly more features at a comparable price point, including session replay, funnels, and error tracking.",
    },
    {
      question: "Can I self-host Hygo like I can with other tools?",
      answer: "Yes, Hygo is fully self-hostable. Fathom does not offer self-hosting at all. If data sovereignty and infrastructure control matter to you, Hygo gives you the option to run everything on your own servers.",
    },
    {
      question: "Is it easy to switch from Fathom to Hygo?",
      answer: "Yes. Just add Hygo's script tag to your site and data starts collecting immediately. You can run both in parallel during the transition. The setup takes less than 5 minutes.",
    },
  ] satisfies FAQItem[],

  relatedResources: [
    {
      title: "Hygo vs Plausible",
      href: "/compare/plausible",
      description: "Compare two privacy-first analytics platforms",
    },
    {
      title: "Hygo vs Simple Analytics",
      href: "/compare/simpleanalytics",
      description: "Feature-rich vs minimal analytics",
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
