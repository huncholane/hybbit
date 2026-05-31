import { ComparisonSection, FAQItem, PricingInfo, RelatedResource } from "../components/ComparisonPage";

export const cloudflareAnalyticsComparisonData: ComparisonSection[] = [
  {
    title: "Analytics Features",
    features: [
      { name: "Real-time analytics", hygoValue: true, competitorValue: true },
      { name: "Custom events", hygoValue: "With attributes", competitorValue: false },
      { name: "Funnels", hygoValue: true, competitorValue: false },
      { name: "User journeys (Sankey)", hygoValue: true, competitorValue: false },
      { name: "Conversion goals", hygoValue: true, competitorValue: false },
      { name: "UTM tracking", hygoValue: true, competitorValue: false },
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
      { name: "Script size", hygoValue: "18KB", competitorValue: "N/A" },
      { name: "Bypasses ad blockers", hygoValue: true, competitorValue: false },
      { name: "API access", hygoValue: true, competitorValue: false },
      { name: "Starting price", hygoValue: "$19/mo", competitorValue: "Free" },
    ],
  },
];

export const cloudflareAnalyticsExtendedData = {
  subtitle: "Cloudflare Analytics is free but limited, and Hygo gives you accurate, unsampled data with the features you actually need.",

  introHeading: "Why consider Hygo over Cloudflare Analytics?",
  introParagraphs: [
    "Cloudflare Web Analytics is free and requires no setup if you're already using Cloudflare's CDN. But free comes with serious limitations. Cloudflare only samples about 10% of your traffic and extrapolates the rest, which means your visitor counts are estimates, not facts. Data is retained for just 6 months, and there's no support for custom events, conversion goals, UTM tracking, or even basic metrics like bounce rate and visit duration.",
    "Hygo processes 100% of your events with zero sampling, so every number in your dashboard is accurate. You get the full analytics toolkit: custom events with attributes, conversion goals, funnel analysis, session replay, user journey visualization, and 3-5+ years of data retention. Plus, Hygo works with any website regardless of hosting provider, so you're not locked into Cloudflare's CDN.",
    "Think of Cloudflare Analytics as a basic traffic counter and Hygo as a complete analytics platform. If you just need to know roughly how many people visited your site, Cloudflare is fine. But if you want to understand user behavior, optimize conversions, debug issues with session replay, or make data-driven decisions with accurate numbers, Hygo is what you need.",
  ],

  chooseHygo: [
    "You need 100% accurate data without sampling (Cloudflare uses 10% samples)",
    "You want full analytics features: UTM tracking, custom events, goals, funnels",
    "You need session replay and user journey visualization",
    "You want 3-5+ years of data retention instead of 6 months",
    "You need analytics that works without Cloudflare CDN lock-in",
    "You want open-source software you can self-host",
  ],

  chooseCompetitor: [
    "You already use Cloudflare CDN and want zero-cost basic analytics",
    "You only need a high-level traffic overview",
    "You don't need custom events, goals, or conversion tracking",
    "You want analytics with absolutely no setup beyond DNS",
    "Basic Web Vitals monitoring is all you need",
  ],

  hygoPricing: {
    name: "Hygo",
    model: "Events-based pricing",
    startingPrice: "$19/mo",
    highlights: [
      "7-day free trial, no credit card required",
      "All features included on every plan",
      "100% unsampled, accurate data",
      "3-5+ years data retention",
    ],
  } satisfies PricingInfo,

  competitorPricing: {
    name: "Cloudflare Analytics",
    model: "Free (bundled with CDN)",
    startingPrice: "Free",
    highlights: [
      "Included free with Cloudflare CDN",
      "Only 10% sampled data (not accurate)",
      "6-month data retention limit",
      "No custom events, goals, or funnels",
    ],
  } satisfies PricingInfo,

  faqItems: [
    {
      question: "Why is Cloudflare Analytics data inaccurate?",
      answer: "Cloudflare Analytics samples only about 10% of your traffic and extrapolates the rest. This means visitor counts are often significantly overcounted and you can't trust the exact numbers. Hygo processes 100% of your events with no sampling.",
    },
    {
      question: "Do I need Cloudflare CDN to use Cloudflare Analytics?",
      answer: "Yes. Cloudflare Analytics requires routing your DNS through Cloudflare. Hygo works with any website regardless of CDN or hosting provider. Just add a single script tag.",
    },
    {
      question: "What features does Cloudflare Analytics lack?",
      answer: "Cloudflare Analytics doesn't support custom events, conversion goals, UTM campaign tracking, session replay, funnels, user journeys, bounce rate, visit duration, entry/exit pages, or an API. It only provides basic traffic metrics with sampled data.",
    },
    {
      question: "How long does Cloudflare keep my data?",
      answer: "Cloudflare retains analytics data for only 6 months. Hygo retains data for 3-5+ years depending on your plan, and you can export your data at any time.",
    },
    {
      question: "Can I use Hygo alongside Cloudflare Analytics?",
      answer: "Yes. Many teams add Hygo for detailed analytics while keeping Cloudflare for basic CDN-level traffic monitoring. Just add Hygo's script tag to your site, and it works alongside any other analytics tool.",
    },
  ] satisfies FAQItem[],

  relatedResources: [
    {
      title: "Hygo vs Google Analytics",
      href: "/compare/google-analytics",
      description: "The privacy-first alternative to GA4",
    },
    {
      title: "Hygo vs Matomo",
      href: "/compare/matomo",
      description: "Modern analytics vs the legacy GA alternative",
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
