import { source } from "@/lib/source";
import { llms } from "fumadocs-core/source";

// cached forever
export const revalidate = false;

export function GET() {
  const navigation = `# Hygo

> Open-source, cookieless web and product analytics.

## Machine-readable resources

- [OpenAPI specification](https://hygo.ai/openapi.json): Complete discoverable REST API surface
- [Sitemap](https://hygo.ai/sitemap.xml): Public website URL index
- [Full documentation](https://hygo.ai/llms-full.txt): Documentation in one text response
- [API getting started](https://hygo.ai/docs/api/getting-started): Authentication, time ranges, filters, and rate limits

## Documentation index

`;

  return new Response(`${navigation}${llms(source).index()}`, {
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      "X-Content-Type-Options": "nosniff",
    },
  });
}
