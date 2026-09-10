"use client";

import { useExtracted } from "next-intl";

import {
  useGetOrganizationExcludedIPs,
  useUpdateOrganizationExcludedIPs,
} from "@/api/admin/hooks/useOrganizationExclusions";
import { PatternExclusionManager } from "@/components/SiteSettings/PatternExclusionManager";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { validateIPPattern } from "@/lib/ipValidation";

interface OrganizationIPExclusionsProps {
  organizationId: string;
  canEdit: boolean;
}

export function OrganizationIPExclusions({ organizationId, canEdit }: OrganizationIPExclusionsProps) {
  const t = useExtracted();
  const { data, isLoading } = useGetOrganizationExcludedIPs(organizationId);
  const updateExcludedIPs = useUpdateOrganizationExcludedIPs();

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-xl">{t("IP Exclusions")}</CardTitle>
        <p className="text-xs text-neutral-500">
          {t(
            "Exclude traffic from these IP addresses or ranges on every site in this organization. A site can turn this off in its Exclusions settings. Supports single IPs (192.168.1.1), CIDR notation (192.168.1.0/24), and ranges (192.168.1.1-192.168.1.10)."
          )}
        </p>
      </CardHeader>
      <CardContent>
        <PatternExclusionManager
          placeholder="e.g., 192.168.1.1 or 10.0.0.0/24"
          addLabel={t("Add IP")}
          loadingLabel={t("Loading IP exclusions...")}
          maxLabel={t("Maximum 100 IP exclusions allowed")}
          values={data?.excludedIPs}
          isLoading={isLoading}
          isSaving={updateExcludedIPs.isPending}
          onSave={excludedIPs => updateExcludedIPs.mutateAsync({ organizationId, excludedIPs })}
          validation={{ validate: validateIPPattern, invalidLabel: t("Invalid IP patterns:") }}
          disabled={!canEdit}
        />
      </CardContent>
    </Card>
  );
}
