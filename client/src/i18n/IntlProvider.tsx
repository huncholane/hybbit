"use client";

import { NextIntlClientProvider } from "next-intl";
import { createContext, useCallback, useContext, useLayoutEffect, useRef, useState } from "react";
import en from "../../messages/en.json";
// The bootstrap script in the root layout sets this attribute (and CSS hides the
// page) when the browser wants a language other than the prerendered English, so
// visitors never see English flash before their catalog arrives.
import { LOCALE_PENDING_ATTRIBUTE } from "./bootstrapScript";
import {
  DEFAULT_LOCALE,
  LOCALE_COOKIE,
  type SupportedLocale,
  detectBrowserLocale,
  isSupportedLocale,
} from "./locales";

type Messages = Record<string, string>;

// English is the source catalog and what the static HTML is rendered with, so it
// ships with the app; every other catalog is its own chunk, loaded on demand.
const loaders: Record<Exclude<SupportedLocale, "en">, () => Promise<{ default: Messages }>> = {
  de: () => import("../../messages/de.json"),
  fr: () => import("../../messages/fr.json"),
  zh: () => import("../../messages/zh.json"),
  es: () => import("../../messages/es.json"),
  pl: () => import("../../messages/pl.json"),
  it: () => import("../../messages/it.json"),
  ko: () => import("../../messages/ko.json"),
  pt: () => import("../../messages/pt.json"),
  ja: () => import("../../messages/ja.json"),
  cs: () => import("../../messages/cs.json"),
  uk: () => import("../../messages/uk.json"),
};

async function loadMessages(locale: SupportedLocale): Promise<Messages> {
  if (locale === "en") return en;
  return (await loaders[locale]()).default;
}

// The Node server used to hand the client its own time zone; production runs in UTC.
const TIME_ZONE = "UTC";

type LocaleState = { locale: SupportedLocale; messages: Messages };

const ChangeLocaleContext = createContext<(locale: string) => void>(() => {});

/** Switches the UI language and remembers the choice in the locale cookie. */
export function useChangeLocale() {
  return useContext(ChangeLocaleContext);
}

export function IntlProvider({ children }: { children: React.ReactNode }) {
  // Hydration has to reproduce the prerendered English markup; the detected locale
  // is applied right after
  const [state, setState] = useState<LocaleState>({ locale: DEFAULT_LOCALE, messages: en });
  const target = useRef<SupportedLocale>(DEFAULT_LOCALE);

  const applyLocale = useCallback(async (locale: SupportedLocale) => {
    target.current = locale;
    try {
      const messages = await loadMessages(locale);
      // A later choice wins over a slower earlier load
      if (target.current === locale) setState({ locale, messages });
    } catch (error) {
      console.error(`[i18n] could not load messages for "${locale}", staying on ${DEFAULT_LOCALE}`, error);
      if (target.current === locale) {
        target.current = DEFAULT_LOCALE;
        setState({ locale: DEFAULT_LOCALE, messages: en });
      }
    }
  }, []);

  // Declared before the reveal below so it runs first: until the browser's locale
  // is known, the prerendered English must stay hidden for non-English visitors
  useLayoutEffect(() => {
    const detected = detectBrowserLocale();
    target.current = detected;
    if (detected !== DEFAULT_LOCALE) void applyLocale(detected);
  }, [applyLocale]);

  // Runs after the DOM carries the target language and before the browser paints it
  useLayoutEffect(() => {
    if (state.locale !== target.current) return;
    document.documentElement.lang = state.locale;
    document.documentElement.removeAttribute(LOCALE_PENDING_ATTRIBUTE);
  }, [state]);

  const changeLocale = useCallback(
    (locale: string) => {
      document.cookie = `${LOCALE_COOKIE}=${locale};path=/;max-age=${60 * 60 * 24 * 365};SameSite=Lax`;
      if (isSupportedLocale(locale)) void applyLocale(locale);
    },
    [applyLocale]
  );

  return (
    <ChangeLocaleContext.Provider value={changeLocale}>
      <NextIntlClientProvider locale={state.locale} messages={state.messages} timeZone={TIME_ZONE}>
        {children}
      </NextIntlClientProvider>
    </ChangeLocaleContext.Provider>
  );
}
