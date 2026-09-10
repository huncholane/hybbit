import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "@/components/ui/sonner";
import {
  fetchOrganizationExcludedIPs,
  fetchSiteOrganizationExcludedIPs,
  updateOrganizationExcludedIPs,
  updateSiteConfig,
} from "../endpoints";

// Organization-wide IP exclusions
export const useGetOrganizationExcludedIPs = (organizationId?: string) => {
  return useQuery({
    queryKey: ["organizationExcludedIPs", organizationId],
    queryFn: () => fetchOrganizationExcludedIPs(organizationId!),
    enabled: !!organizationId,
  });
};

export const useUpdateOrganizationExcludedIPs = () => {
  const queryClient = useQueryClient();

  return useMutation<unknown, Error, { organizationId: string; excludedIPs: string[] }>({
    mutationFn: ({ organizationId, excludedIPs }) => updateOrganizationExcludedIPs(organizationId, excludedIPs),
    onSuccess: (_, variables) => {
      toast.success("Organization IP exclusions updated successfully");
      queryClient.invalidateQueries({ queryKey: ["organizationExcludedIPs", variables.organizationId] });
      // Each site shows a read-only copy of this list
      queryClient.invalidateQueries({ queryKey: ["siteOrganizationExcludedIPs"] });
    },
    onError: error => {
      console.error("Error updating organization excluded IPs:", error);
      toast.error(error.message || "Failed to update organization IP exclusions");
    },
  });
};

// The organization's list as one site sees it, and that site's switch
export const useGetSiteOrganizationExcludedIPs = (siteId: number) => {
  return useQuery({
    queryKey: ["siteOrganizationExcludedIPs", siteId],
    queryFn: () => fetchSiteOrganizationExcludedIPs(siteId),
    enabled: !!siteId,
  });
};

export const useSetSiteUsesOrganizationExcludedIPs = () => {
  const queryClient = useQueryClient();

  return useMutation<unknown, Error, { siteId: number; enabled: boolean }>({
    mutationFn: ({ siteId, enabled }) => updateSiteConfig(siteId, { useOrganizationExcludedIPs: enabled }),
    onSuccess: (_, variables) => {
      toast.success(
        variables.enabled
          ? "Organization IP exclusions applied to this site"
          : "Organization IP exclusions turned off for this site"
      );
      queryClient.invalidateQueries({ queryKey: ["siteOrganizationExcludedIPs", variables.siteId] });
    },
    onError: error => {
      console.error("Error updating useOrganizationExcludedIPs:", error);
      toast.error(error.message || "Failed to update organization IP exclusions for this site");
    },
  });
};
