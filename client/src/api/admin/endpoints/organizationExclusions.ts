import { authedFetch } from "../../utils";

export interface OrganizationExcludedIPsResponse {
  success: boolean;
  excludedIPs: string[];
}

export interface SiteOrganizationExcludedIPsResponse {
  success: boolean;
  organizationId: string | null;
  useOrganizationExcludedIPs: boolean;
  excludedIPs: string[];
}

export function fetchOrganizationExcludedIPs(organizationId: string) {
  return authedFetch<OrganizationExcludedIPsResponse>(`/organizations/${organizationId}/excluded-ips`);
}

// Replaces the organization's list wholesale
export function updateOrganizationExcludedIPs(organizationId: string, excludedIPs: string[]) {
  return authedFetch<OrganizationExcludedIPsResponse>(`/organizations/${organizationId}/excluded-ips`, undefined, {
    method: "PUT",
    data: { excludedIPs },
  });
}

// The organization's list as one site sees it, plus whether that site applies it
export function fetchSiteOrganizationExcludedIPs(siteId: number) {
  return authedFetch<SiteOrganizationExcludedIPsResponse>(`/sites/${siteId}/organization-excluded-ips`);
}
