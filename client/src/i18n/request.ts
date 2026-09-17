import { getRequestConfig } from "next-intl/server";
import en from "../../messages/en.json";

// The client is a static export: nothing renders per request, and the locale is
// picked in the browser (see i18n/locales.ts and i18n/IntlProvider.tsx). The
// next-intl plugin still requires this module, so it describes the prerender:
// English, the source locale.
export default getRequestConfig(async () => ({
  locale: "en",
  messages: en,
}));
