import { DEFAULT_LOCALE, LOCALE_COOKIE, SUPPORTED_LOCALES } from "./locales";

export const LOCALE_PENDING_ATTRIBUTE = "data-locale-pending";

// How long the page may stay hidden waiting for a translation catalog before it is
// shown anyway (in English) so a failed chunk load never leaves a blank screen.
const REVEAL_TIMEOUT_MS = 8000;

/**
 * Inline script for <head>: picks the locale exactly like `detectBrowserLocale`
 * (cookie, then the browser languages) before first paint, sets <html lang>, and
 * hides the page while a non-English catalog loads. Kept free of dependencies
 * because it runs before any bundle.
 */
export const LOCALE_BOOTSTRAP_SCRIPT = `(function () {
  try {
    var supported = ${JSON.stringify(SUPPORTED_LOCALES)};
    var locale = ${JSON.stringify(DEFAULT_LOCALE)};
    var cookieLocale;
    var pairs = document.cookie.split(/; */);
    for (var i = 0; i < pairs.length; i++) {
      var pair = pairs[i];
      if (!pair) continue;
      var at = pair.indexOf("=");
      var key = at === -1 ? pair : pair.slice(0, at);
      if (key !== ${JSON.stringify(LOCALE_COOKIE)}) continue;
      if (at === -1) { cookieLocale = "true"; continue; }
      try { cookieLocale = decodeURIComponent(pair.slice(at + 1)); } catch (e) {}
    }
    if (cookieLocale && supported.indexOf(cookieLocale) !== -1) {
      locale = cookieLocale;
    } else {
      var languages = navigator.languages && navigator.languages.length ? navigator.languages : navigator.language ? [navigator.language] : [];
      var parsed = [];
      for (var j = 0; j < languages.length; j++) {
        var parts = String(languages[j]).trim().split(";q=");
        parsed.push({ lang: parts[0].trim().split("-")[0].toLowerCase(), q: parts[1] ? parseFloat(parts[1]) : 1 });
      }
      parsed.sort(function (a, b) { return b.q - a.q; });
      for (var k = 0; k < parsed.length; k++) {
        if (supported.indexOf(parsed[k].lang) !== -1) { locale = parsed[k].lang; break; }
      }
    }
    var root = document.documentElement;
    root.lang = locale;
    if (locale !== ${JSON.stringify(DEFAULT_LOCALE)}) {
      root.setAttribute(${JSON.stringify(LOCALE_PENDING_ATTRIBUTE)}, locale);
      setTimeout(function () { root.removeAttribute(${JSON.stringify(LOCALE_PENDING_ATTRIBUTE)}); }, ${REVEAL_TIMEOUT_MS});
    }
  } catch (e) {}
})();`;

export const LOCALE_PENDING_STYLE = `html[${LOCALE_PENDING_ATTRIBUTE}] body{visibility:hidden}`;
