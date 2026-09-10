import { eq } from "drizzle-orm";
import { FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";

import { db } from "../../db/postgres/postgres.js";
import { organization } from "../../db/postgres/schema.js";
import { validateIPPattern } from "../../lib/ipUtils.js";
import { siteConfig } from "../../lib/siteConfig.js";
import { loadSiteConfigForSettings } from "../sites/getSiteExclusions.js";

interface OrganizationParams {
  organizationId: string;
}

const updateOrganizationExcludedIPsSchema = z.object({
  excludedIPs: z.array(z.string().trim().min(1)).max(100),
});

/** GET /organizations/:organizationId/excluded-ips */
export async function getOrganizationExcludedIPs(
  request: FastifyRequest<{ Params: OrganizationParams }>,
  reply: FastifyReply
) {
  try {
    const [org] = await db
      .select({ excludedIPs: organization.excludedIPs })
      .from(organization)
      .where(eq(organization.id, request.params.organizationId))
      .limit(1);

    if (!org) {
      return reply.status(404).send({ success: false, error: "Organization not found" });
    }

    return reply.send({ success: true, excludedIPs: Array.isArray(org.excludedIPs) ? org.excludedIPs : [] });
  } catch (error) {
    request.log.error({ err: error }, "Error getting organization excluded IPs");
    return reply.status(500).send({ success: false, error: "Failed to get organization excluded IPs" });
  }
}

/** PUT /organizations/:organizationId/excluded-ips (replaces the list wholesale) */
export async function updateOrganizationExcludedIPs(
  request: FastifyRequest<{ Params: OrganizationParams; Body: unknown }>,
  reply: FastifyReply
) {
  const validationResult = updateOrganizationExcludedIPsSchema.safeParse(request.body);
  if (!validationResult.success) {
    return reply.status(400).send({
      success: false,
      error: "Invalid request data",
      details: validationResult.error.flatten(),
    });
  }

  const { excludedIPs } = validationResult.data;
  const invalidPatterns = excludedIPs.flatMap(ip => {
    const validation = validateIPPattern(ip);
    return validation.valid ? [] : [`${ip}: ${validation.error}`];
  });
  if (invalidPatterns.length > 0) {
    return reply.status(400).send({ success: false, error: "Invalid IP patterns", details: invalidPatterns });
  }

  const { organizationId } = request.params;

  try {
    const updated = await db
      .update(organization)
      .set({ excludedIPs })
      .where(eq(organization.id, organizationId))
      .returning({ id: organization.id });

    if (updated.length === 0) {
      return reply.status(404).send({ success: false, error: "Organization not found" });
    }

    // Every Site in the Organization reads this list at ingestion
    siteConfig.invalidateOrganization(organizationId);
    request.log.info({ organizationId, count: excludedIPs.length }, "Updated organization excluded IPs");

    return reply.send({ success: true, excludedIPs });
  } catch (error) {
    request.log.error({ err: error }, "Error updating organization excluded IPs");
    return reply.status(500).send({ success: false, error: "Failed to update organization excluded IPs" });
  }
}

/**
 * GET /sites/:siteId/organization-excluded-ips
 *
 * The Organization's list as one Site sees it, plus whether that Site applies it.
 * Read-only: the list is edited at the Organization, the switch through the Site
 * config endpoint.
 */
export async function getSiteOrganizationExcludedIPs(request: FastifyRequest, reply: FastifyReply) {
  try {
    const config = await loadSiteConfigForSettings(request, reply);
    if (!config) {
      return reply;
    }

    return reply.send({
      success: true,
      organizationId: config.organizationId,
      useOrganizationExcludedIPs: config.useOrganizationExcludedIPs,
      excludedIPs: config.organizationExcludedIPs,
    });
  } catch (error) {
    request.log.error({ err: error }, "Error getting organization excluded IPs for site");
    return reply.status(500).send({ success: false, error: "Failed to get organization excluded IPs" });
  }
}
