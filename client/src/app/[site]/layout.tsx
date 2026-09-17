import { RouteParamBoundary } from "@/hooks/useRouteParams";
import { placeholderStaticParams } from "@/lib/routeParams";
import SiteLayout from "./SiteLayout";

// Static export: every site shares one prerendered page (see lib/routeParams.ts).
// The Rust server answers /{site}/... with it; nothing under it renders before
// hydration because the prerender only knows the placeholder URL.
export function generateStaticParams() {
  return placeholderStaticParams("site");
}

export default function Layout({ children }: { children: React.ReactNode }) {
  return (
    <RouteParamBoundary name="site" clientOnly>
      <SiteLayout>{children}</SiteLayout>
    </RouteParamBoundary>
  );
}
