import Image from "next/image";
import { useExtracted } from "next-intl";
import { IS_CLOUD } from "../../lib/const";
import { useWhiteLabel } from "../../hooks/useIsWhiteLabel";
import { LanguageSwitcher } from "../../components/LanguageSwitcher";

interface FooterProps {
  disabled?: boolean;
}

export function Footer({ disabled = false }: FooterProps) {
  const APP_VERSION = process.env.NEXT_PUBLIC_APP_VERSION;
  const { isWhiteLabel } = useWhiteLabel();
  const t = useExtracted();
  if (disabled || isWhiteLabel) {
    return null;
  }

  return (
    <footer className="border-t border-neutral-200 dark:border-neutral-850 bg-neutral-50 dark:bg-neutral-900">
      <div className="max-w-[1100px] mx-auto px-4 py-12">
        {/* Main Footer Content */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8 mb-8">
          {/* Company Info */}
          <div className="space-y-4">
            <Image
              src="/hygo/horizontal_white.svg"
              alt="Hygo"
              width={140}
              height={28}
              style={{ width: 140, height: 28, objectFit: "contain" }}
              className="dark:invert-0 invert"
            />
          </div>

          {/* Resources */}
          <div className="space-y-4">
            <h3 className="text-sm font-semibold text-neutral-900 dark:text-white">{t("Resources")}</h3>
            <ul className="space-y-2 text-sm">
              <li>
                <a
                  href="https://hygo.ai/docs"
                  className="text-neutral-500 hover:text-neutral-900 dark:text-neutral-400 dark:hover:text-white transition-colors"
                >
                  {t("Documentation")}
                </a>
              </li>
              <li>
                <a
                  href="https://hygo.ai/features"
                  className="text-neutral-500 hover:text-neutral-900 dark:text-neutral-400 dark:hover:text-white transition-colors"
                >
                  {t("Features")}
                </a>
              </li>
              <li>
                <a
                  href="https://hygo.ai/docs/api/getting-started"
                  className="text-neutral-500 hover:text-neutral-900 dark:text-neutral-400 dark:hover:text-white transition-colors"
                >
                  {t("API Reference")}
                </a>
              </li>
            </ul>
          </div>

          {/* Company */}
          <div className="space-y-4">
            <h3 className="text-sm font-semibold text-neutral-900 dark:text-white">{t("Company")}</h3>
            <ul className="space-y-2 text-sm">
              <li>
                <a
                  href="https://hygo.ai/privacy"
                  className="text-neutral-500 hover:text-neutral-900 dark:text-neutral-400 dark:hover:text-white transition-colors"
                >
                  {t("Privacy Policy")}
                </a>
              </li>
              <li>
                <a
                  href="https://hygo.ai/terms-and-conditions"
                  className="text-neutral-500 hover:text-neutral-900 dark:text-neutral-400 dark:hover:text-white transition-colors"
                >
                  {t("Terms and Conditions")}
                </a>
              </li>
              <li>
                <a
                  href="https://hygo.ai/security"
                  className="text-neutral-500 hover:text-neutral-900 dark:text-neutral-400 dark:hover:text-white transition-colors"
                >
                  {t("Security")}
                </a>
              </li>
              <li>
                <a
                  href="https://hygo.ai/dpa"
                  className="text-neutral-500 hover:text-neutral-900 dark:text-neutral-400 dark:hover:text-white transition-colors"
                >
                  DPA
                </a>
              </li>
              {IS_CLOUD && (
                <li>
                  <a
                    href="mailto:hello@hygo.ai"
                    className="text-neutral-500 hover:text-neutral-900 dark:text-neutral-400 dark:hover:text-white transition-colors"
                  >
                    {t("Support")}
                  </a>
                </li>
              )}
            </ul>
          </div>
        </div>

        {/* Bottom Bar */}
        <div className="pt-8 border-t border-neutral-200 dark:border-neutral-800">
          <div className="flex flex-col md:flex-row items-center justify-between gap-4">
            <div className="flex items-center gap-4 text-sm text-neutral-500 dark:text-neutral-400">
              <span>{t("© {year} Hygo. All rights reserved.", { year: String(new Date().getFullYear()) })}</span>
              <span>v{APP_VERSION}</span>
            </div>
            <div className="flex items-center gap-4">
              <LanguageSwitcher />
            </div>
          </div>
        </div>
      </div>
    </footer>
  );
}
