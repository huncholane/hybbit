import { RouteParamBoundary } from "@/hooks/useRouteParams";
import { placeholderStaticParams } from "@/lib/routeParams";

// Static export: prerendered once with a placeholder private key (see lib/routeParams.ts).
export function generateStaticParams() {
  return placeholderStaticParams("privateKey");
}

export default function Layout({ children }: { children: React.ReactNode }) {
  return <RouteParamBoundary name="privateKey">{children}</RouteParamBoundary>;
}
