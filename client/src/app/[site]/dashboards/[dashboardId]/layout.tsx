import { RouteParamBoundary } from "@/hooks/useRouteParams";
import { placeholderStaticParams } from "@/lib/routeParams";

// Static export: prerendered once with a placeholder dashboard id (see lib/routeParams.ts).
export function generateStaticParams() {
  return placeholderStaticParams("dashboardId");
}

export default function Layout({ children }: { children: React.ReactNode }) {
  return <RouteParamBoundary name="dashboardId">{children}</RouteParamBoundary>;
}
