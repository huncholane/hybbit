// Locale selection shared by the browser bootstrap and the provider. The client is
// a static export, so the choice the server used to make per request (cookie, then
// Accept-Language) now happens in the browser with the same precedence.

export const SUPPORTED_LOCALES = ["en", "de", "fr", "zh", "es", "pl", "it", "ko", "pt", "ja", "cs", "uk"] as const;
export type SupportedLocale = (typeof SUPPORTED_LOCALES)[number];

export const DEFAULT_LOCALE: SupportedLocale = "en";

// Written by the language switcher; also the cookie next-intl's middleware uses.
export const LOCALE_COOKIE = "NEXT_LOCALE";

export function isSupportedLocale(locale: string): locale is SupportedLocale {
  return (SUPPORTED_LOCALES as readonly string[]).includes(locale);
}

export function getLocaleFromAcceptLanguage(acceptLanguage: string): SupportedLocale {
  const languages = acceptLanguage
    .split(",")
    .map(part => {
      const [lang, q] = part.trim().split(";q=");
      return { lang: lang.trim().split("-")[0].toLowerCase(), q: q ? parseFloat(q) : 1 };
    })
    .sort((a, b) => b.q - a.q);

  for (const { lang } of languages) {
    if (isSupportedLocale(lang)) {
      return lang;
    }
  }

  return DEFAULT_LOCALE;
}

/** Priority 1: the locale cookie (explicit choice). Priority 2: the browser's languages. */
export function resolveLocale(cookieLocale: string | undefined, acceptLanguage: string | null): SupportedLocale {
  if (cookieLocale && isSupportedLocale(cookieLocale)) {
    return cookieLocale;
  }
  if (acceptLanguage) {
    return getLocaleFromAcceptLanguage(acceptLanguage);
  }
  return DEFAULT_LOCALE;
}

/** Parses a Cookie header the way Next's `cookies()` did: later duplicates win, undecodable values are skipped. */
export function readCookie(cookieHeader: string, name: string): string | undefined {
  let found: string | undefined;
  for (const pair of cookieHeader.split(/; */)) {
    if (!pair) continue;
    const index = pair.indexOf("=");
    const key = index === -1 ? pair : pair.slice(0, index);
    if (key !== name) continue;
    if (index === -1) {
      found = "true";
      continue;
    }
    try {
      found = decodeURIComponent(pair.slice(index + 1));
    } catch {
      // Next's parser ignores values it cannot decode
    }
  }
  return found;
}

/** The browser's Accept-Language, rebuilt from navigator.languages (already in preference order). */
export function browserAcceptLanguage(): string | null {
  if (typeof navigator === "undefined") return null;
  const languages = navigator.languages?.length ? navigator.languages : navigator.language ? [navigator.language] : [];
  return languages.length ? languages.join(",") : null;
}

export function detectBrowserLocale(): SupportedLocale {
  if (typeof document === "undefined") return DEFAULT_LOCALE;
  return resolveLocale(readCookie(document.cookie, LOCALE_COOKIE), browserAcceptLanguage());
}
