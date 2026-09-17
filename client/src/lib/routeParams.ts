// The client is a static export. Dynamic routes ([site], [privateKey], [userId],
// [dashboardId]) are prerendered once with a placeholder value, and the Rust server
// answers every real URL with that page. Next's router therefore reports the
// placeholder from useParams(); the real values come from the browser URL.

/** The value a dynamic segment is exported with, e.g. `__site__`; also its directory name in the export. */
export function routeParamPlaceholder(name: string) {
  return `__${name}__`;
}

/** What `generateStaticParams` returns for a segment named `name`. */
export function placeholderStaticParams<Name extends string>(name: Name): Record<Name, string>[] {
  return [{ [name]: routeParamPlaceholder(name) } as Record<Name, string>];
}

/** Route groups like `(home)` are part of the router tree but not of the URL. */
function appearsInUrl(segment: string) {
  return !(segment.startsWith("(") && segment.endsWith(")"));
}

/**
 * The value of the dynamic segment whose layout sees `segmentsBelow` under it
 * (`useSelectedLayoutSegments()`), read from the real `pathname`. The segment is
 * as far from the end of the URL as there are URL segments below it. Encoded the
 * way Next encodes params (`encodeURIComponent(decodeURIComponent(part))`, so
 * `a@b` reads `a%40b`), keeping malformed escapes as they are.
 */
export function routeParamFromPathname(pathname: string, segmentsBelow: readonly string[]): string {
  const parts = pathname.split("/").filter(part => part !== "");
  const index = parts.length - segmentsBelow.filter(appearsInUrl).length - 1;
  const raw = parts[index] ?? "";
  try {
    return encodeURIComponent(decodeURIComponent(raw));
  } catch {
    return raw;
  }
}
