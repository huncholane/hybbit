"use client";

import { useParams, usePathname, useSelectedLayoutSegments } from "next/navigation";
import { createContext, Fragment, useContext, useMemo } from "react";
import { ClientOnly } from "../components/ClientOnly";
import { routeParamFromPathname } from "../lib/routeParams";

type Params = Record<string, string | string[]>;

const RouteParamsContext = createContext<Record<string, string>>({});

/**
 * Rendered by the layout of each dynamic segment. Reads the segment's real value
 * from the URL and provides it to `useRouteParams`. Its subtree is keyed by that
 * value so moving to another site, user or dashboard remounts it, as Next does
 * when a dynamic segment changes. With `clientOnly`, nothing is rendered until
 * hydration: the prerendered HTML was produced for the placeholder URL, so any
 * markup derived from the path would not match the real one.
 */
export function RouteParamBoundary({
  name,
  clientOnly = false,
  children,
}: {
  name: string;
  clientOnly?: boolean;
  children: React.ReactNode;
}) {
  const parent = useContext(RouteParamsContext);
  const pathname = usePathname();
  const segmentsBelow = useSelectedLayoutSegments();
  const value = routeParamFromPathname(pathname, segmentsBelow);
  const params = useMemo(() => ({ ...parent, [name]: value }), [parent, name, value]);

  const content = (
    <RouteParamsContext.Provider value={params}>
      <Fragment key={value}>{children}</Fragment>
    </RouteParamsContext.Provider>
  );
  return clientOnly ? <ClientOnly>{content}</ClientOnly> : content;
}

/**
 * Drop-in replacement for Next's `useParams()` that returns the real dynamic
 * segment values of the current URL instead of the placeholders the static export
 * was rendered with.
 */
export function useRouteParams<T extends Params = Params>(): T {
  const nextParams = useParams<T>();
  const routeParams = useContext(RouteParamsContext);
  return useMemo(() => ({ ...nextParams, ...routeParams }) as T, [nextParams, routeParams]);
}
