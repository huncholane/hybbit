import { RouteParamBoundary } from "@/hooks/useRouteParams";
import { placeholderStaticParams } from "@/lib/routeParams";

// Static export: prerendered once with a placeholder user id (see lib/routeParams.ts).
export function generateStaticParams() {
  return placeholderStaticParams("userId");
}

export default function Layout({ children }: { children: React.ReactNode }) {
  return <RouteParamBoundary name="userId">{children}</RouteParamBoundary>;
}
