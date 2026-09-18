"use client";

import { useExtracted } from "next-intl";

import { IS_CLOUD } from "../../lib/const";
import { GSCManager } from "./GSCManager";
import { SettingsSection, SettingsSections } from "./SettingsSection";

interface IntegrationsTabProps {
  disabled?: boolean;
  siteId?: number;
}

export function IntegrationsTab({ disabled = false, siteId }: IntegrationsTabProps) {
  const t = useExtracted();

  return (
    <SettingsSections>
      <SettingsSection
        title={t("Google Search Console")}
        description={t("Connect your Google Search Console account to view search performance data")}
      >
        {IS_CLOUD ? (
          <GSCManager disabled={disabled} siteId={siteId} />
        ) : (
          <div className="inline-flex rounded border border-neutral-200 px-2 py-0.5 text-xs text-neutral-500 dark:border-neutral-800 dark:text-neutral-400">
            {t("Coming soon")}
          </div>
        )}
      </SettingsSection>
    </SettingsSections>
  );
}
