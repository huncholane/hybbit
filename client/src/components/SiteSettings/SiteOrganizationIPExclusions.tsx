"use client";

import Link from "next/link";
import { useExtracted } from "next-intl";

import {
  useGetSiteOrganizationExcludedIPs,
  useSetSiteUsesOrganizationExcludedIPs,
} from "@/api/admin/hooks/useOrganizationExclusions";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import { cn } from "@/lib/utils";

import { SettingRow } from "./SettingsSection";

interface SiteOrganizationIPExclusionsProps {
  siteId: number;
  disabled?: boolean;
}

/**
 * The organization's IP exclusion list as this site sees it. Read-only here (it
 * is edited in Organization settings), with a switch to apply it to this site.
 */
export function SiteOrganizationIPExclusions({ siteId, disabled = false }: SiteOrganizationIPExclusionsProps) {
  const t = useExtracted();
  const { data, isLoading } = useGetSiteOrganizationExcludedIPs(siteId);
  const setEnabled = useSetSiteUsesOrganizationExcludedIPs();

  if (isLoading) {
    return <Skeleton className="h-20 w-full rounded-lg" />;
  }

  if (!data?.organizationId) {
    return null;
  }

  // Show the requested state while the save is in flight
  const enabled = setEnabled.isPending ? !!setEnabled.variables?.enabled : data.useOrganizationExcludedIPs;

  return (
    <div className="space-y-3 rounded-lg border border-neutral-150 p-3 dark:border-neutral-800">
      <SettingRow
        label={t("Organization IP exclusions")}
        htmlFor="useOrganizationExcludedIPs"
        description={
          <>
            {t("Also exclude the IPs set for your whole organization. Edit the list in")}{" "}
            <Link href="/settings/organization" className="underline underline-offset-2 hover:text-foreground">
              {t("Organization settings")}
            </Link>
          </>
        }
      >
        <Switch
          id="useOrganizationExcludedIPs"
          checked={enabled}
          disabled={disabled || setEnabled.isPending}
          onCheckedChange={checked => setEnabled.mutate({ siteId, enabled: checked })}
        />
      </SettingRow>

      {data.excludedIPs.length > 0 ? (
        <ul className={cn("flex flex-wrap gap-1.5", !enabled && "opacity-50")}>
          {data.excludedIPs.map(ip => (
            <li
              key={ip}
              className="rounded-md bg-neutral-100 px-2 py-0.5 font-mono text-xs text-neutral-700 dark:bg-neutral-850 dark:text-neutral-300"
            >
              {ip}
            </li>
          ))}
        </ul>
      ) : (
        <p className="text-xs text-muted-foreground">{t("Your organization has no IP exclusions yet.")}</p>
      )}
    </div>
  );
}
