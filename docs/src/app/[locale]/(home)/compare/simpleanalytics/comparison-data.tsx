import Link from "next/link";
import { ComparisonSection, DeepDive, FAQItem, PricingInfo, RelatedResource } from "../components/ComparisonPage";

export const simpleAnalyticsComparisonData: ComparisonSection[] = [
  {
    title: "Analytics Features",
    features: [
      { name: "Real-time analytics", hygoValue: true, competitorValue: true },
      { name: "Custom events", hygoValue: "With attributes", competitorValue: "Basic" },
      { name: "Funnels", hygoValue: true, competitorValue: false },
      { name: "User journeys (Sankey)", hygoValue: true, competitorValue: false },
      { name: "Conversion goals", hygoValue: true, competitorValue: true },
      { name: "Saved segments", hygoValue: true, competitorValue: false },
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
      { name: "Script size", hygoValue: "18KB", competitorValue: "~6KB" },
      { name: "Bypasses ad blockers", hygoValue: true, competitorValue: true },
      { name: "API access", hygoValue: true, competitorValue: true },
      { name: "Starting price", hygoValue: "$19/mo", competitorValue: "$20/mo per user" },
    ],
  },
];

export const simpleAnalyticsExtendedData = {
  subtitle: "Both prioritize privacy, but Hygo is open source with session replay, funnels, and city-level geolocation that Simple Analytics lacks.",

  introHeading: "Why consider Hygo over Simple Analytics?",
  introParagraphs: [
    "Simple Analytics lives up to its name: it's a privacy-focused analytics tool that keeps things minimal. It offers a clean dashboard, cookie-free tracking, and EU-based data storage. But its simplicity means no session replay, no funnel analysis, no user journeys, and only country-level geolocation. It's also entirely closed-source with no self-hosting option.",
    "Hygo matches Simple Analytics on privacy (cookie-free, no personal data collection, EU data storage) but adds the advanced features growing teams actually need. Session replay lets you watch how users interact with your site. Funnel analysis shows where visitors drop off in your conversion flow. User journey visualization reveals the paths people take through your content. And city-level geolocation gives you much more granular insights into where your audience is.",
    "The business model difference matters too. Hygo is fully open source under AGPL v3: you can self-host it for free and verify exactly how your data is handled. Simple Analytics is proprietary, so you're locked into their cloud service with no alternative. If you want privacy-first analytics with the depth to actually improve your product and the transparency of open source, Hygo is the stronger choice.",
  ],

  chooseHygo: [
    "You want open-source software you can self-host and audit",
    "You need session replay, funnels, and user journey visualization",
    "You want city-level geolocation instead of country-level",
    "You need error tracking and Web Vitals monitoring",
    "You want organization support with team roles",
    "You want a 7-day free trial to evaluate the product",
  ],

  chooseCompetitor: [
    "You want built-in AI-powered analytics assistant",
    "You want a free tier for hobby sites without entering a card",
    "You prefer a longer-established product",
    "You don't need advanced features like funnels or session replay",
    "You want country-level data only for maximum privacy",
  ],

  hygoPricing: {
    name: "Hygo",
    model: "Events-based pricing",
    startingPrice: "$19/mo",
    highlights: [
      "7-day free trial, card charged after the trial",
      "Session replay available on Pro plan",
      "Funnels, user journeys, and error tracking included",
      "Self-hosting option available (free)",
    ],
  } satisfies PricingInfo,

  competitorPricing: {
    name: "Simple Analytics",
    model: "Per-user + pageview pricing",
    startingPrice: "$20/mo",
    highlights: [
      "Free tier for hobby sites: 1 user, 5 websites, 1 month of history",
      "$20/mo for 1 user; each extra team member is +$20/mo",
      "14-day free trial, no card required",
      "Cloud-only, no self-hosting option",
    ],
  } satisfies PricingInfo,

  deepDive: {
    title: "Simple Analytics vs Hygo, in depth",
    sections: [
      {
        heading: "Per-seat pricing vs unlimited team members",
        paragraphs: [
          <>
            Simple Analytics prices by user. Paid plans start at $20 per month for one user, with a usage slider that
            scales the price by pageviews (the slider runs from 100k up to 2.5M), and every additional team member
            costs another $20 per month. Annual billing gives you two months free, and there&apos;s a genuinely useful
            free tier for hobby sites: one user, five websites, one month of history, no card required.
          </>,
          <>
            For a solo founder that model works fine. For a team it compounds quickly: five people looking at the same
            dashboard is $100 per month before you&apos;ve touched the pageview slider. Hygo&apos;s{" "}
            <Link href="/pricing">pricing</Link> starts at $19 per month for 100k events and includes unlimited team
            members on every plan, so adding your designer, your marketer, and your co-founder costs nothing extra.
          </>,
        ],
      },
      {
        heading: "Minimal by design, and what that leaves out",
        paragraphs: [
          <>
            Simple Analytics deserves credit for being exactly what it says. The Amsterdam-based team collects the
            least data of any paid analytics tool in this category, hosts everything in the EU end to end, and ships a
            clean dashboard with an AI chat over your stats. In 2026 it also repositioned itself: rather than pitching
            a full GA replacement, it now markets itself as a complement that fixes consent loss, arguing that
            Google Analytics can miss up to 60% of traffic and telling you &ldquo;Don&apos;t replace your analytics.
            Fix it.&rdquo; If you want the most conservative data collection available in a managed EU service, or you
            plan to keep GA and run a privacy-friendly counter next to it, that&apos;s a coherent offer.
          </>,
          <>
            The trade-off is depth. There&apos;s no <Link href="/features/session-replay">session replay</Link>, no{" "}
            <Link href="/features/funnels">funnel analysis</Link>, no user journeys, no error tracking, no Web Vitals,
            and no user profiles. When a conversion drops, Simple Analytics can tell you that it happened, but
            not where in the flow or what the user saw. Hygo stays cookieless with a daily-rotating salt while
            shipping all of those, so you don&apos;t have to choose between privacy and being able to answer
            &ldquo;why.&rdquo;
          </>,
        ],
      },
      {
        heading: "EU hosting is good; owning the stack is better",
        paragraphs: [
          <>
            EU hosting end to end is a real advantage over analytics vendors running on US clouds, and Simple
            Analytics is rightly proud of it. But it&apos;s still someone else&apos;s SaaS: the code is closed source,
            there&apos;s no self-hosting option, and your data lives on their infrastructure under their terms.
          </>,
          <>
            Hygo is open source: you can audit exactly how visitor data is handled, and you can{" "}
            <Link href="/docs/self-hosting">self-host it for free</Link>, which beats even the best EU hosting for data
            sovereignty: analytics data never leaves infrastructure you control. If you&apos;d rather not run servers,
            the cloud version keeps the same cookieless, no-personal-data model.
          </>,
        ],
      },
      {
        heading: "Switching from Simple Analytics to Hygo",
        paragraphs: [
          <>
            Unusually for an analytics migration, you don&apos;t have to start from zero: Hygo ships a data importer
            for Simple Analytics, and your historical stats come with you. See the{" "}
            <Link href="/docs">docs</Link> for the import walkthrough.
          </>,
          <ol>
            <li>
              Add the Hygo tracking script: one tag, and data appears within minutes. The 7-day trial covers
              every feature; use it to evaluate replay and funnels on real traffic.
            </li>
            <li>Run the Simple Analytics importer to backfill your history, then compare the two dashboards.</li>
            <li>
              Once the numbers line up, remove the Simple Analytics script, or keep both during a transition
              period; the scripts don&apos;t conflict.
            </li>
          </ol>,
          <>
            Still weighing options? Our roundup of the{" "}
            <Link href="/blog/best-web-analytics-tools">best web analytics tools</Link> covers where each tool fits.
          </>,
        ],
      },
    ],
  } satisfies DeepDive,

  faqItems: [
    {
      question: "Is Hygo open source while Simple Analytics is not?",
      answer: "Yes. Hygo is fully open source under the AGPL v3 license: you can inspect the code and self-host it. Simple Analytics is proprietary and closed-source with no self-hosting option.",
    },
    {
      question: "What features does Hygo have that Simple Analytics doesn't?",
      answer: "Hygo includes session replay, funnel analysis, user journey visualization (Sankey diagrams), Web Vitals monitoring, error tracking, user profiles, city-level geolocation, and organization support. Simple Analytics focuses on simpler metrics with an AI assistant.",
    },
    {
      question: "How does geolocation differ between the two?",
      answer: "Hygo provides city-level geolocation data, giving you more granular insights into where your visitors are. Simple Analytics only offers country-level data, which limits your ability to understand regional traffic patterns.",
    },
    {
      question: "Are both equally private?",
      answer: "Both are privacy-first and cookie-free with EU data storage. Hygo adds a daily rotating salt option for extra privacy, ensuring visitor IDs can't be tracked across days. Both are GDPR compliant without requiring consent banners.",
    },
    {
      question: "Can I switch from Simple Analytics to Hygo easily?",
      answer: "Yes. Add Hygo's tracking script to your site and data collection begins immediately. You can run both tools in parallel during the transition. Setup takes less than 5 minutes.",
    },
  ] satisfies FAQItem[],

  relatedResources: [
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
