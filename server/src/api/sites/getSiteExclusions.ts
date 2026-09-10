import { FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";
import { siteConfig, type SiteConfigData } from "../../lib/siteConfig.js";

const siteParamsSchema = z.object({
  siteId: z.string().min(1),
});

/**
 * The Site Configuration fields these endpoints expose. Each is returned under
 * its own name, which is also the field name — the response key cannot drift
 * from the field being read.
 */
type ExclusionField = Extract<
  keyof SiteConfigData,
  | "excludedIPs"
  | "excludedCountries"
  | "excludedPaths"
  | "excludedHostnames"
  | "excludedUserAgents"
  | "excludedASNs"
  | "excludedQueryParams"
>;

// The API playground surfaces error bodies verbatim, so these read as prose.
// Exhaustive by type — a new exclusion field will not compile without one.
const FIELD_LABELS: Record<ExclusionField, string> = {
  excludedIPs: "excluded IPs",
  excludedCountries: "excluded countries",
  excludedPaths: "excluded paths",
  excludedHostnames: "excluded hostnames",
  excludedUserAgents: "excluded user agents",
  excludedASNs: "excluded ASNs",
  excludedQueryParams: "excluded query params",
};

/**
 * Validate the :siteId param and read the Site Configuration for a settings
 * screen. Sends the 400 or 404 itself and returns null in that case; a Postgres
 * failure propagates so the caller can answer 500.
 */
export async function loadSiteConfigForSettings(
  request: FastifyRequest,
  reply: FastifyReply
): Promise<SiteConfigData | null> {
  const validationResult = siteParamsSchema.safeParse(request.params);

  if (!validationResult.success) {
    reply.status(400).send({
      success: false,
      error: "Invalid site ID",
      details: validationResult.error.flatten(),
    });
    return null;
  }

  const numericSiteId = Number(validationResult.data.siteId);
  if (!Number.isInteger(numericSiteId) || numericSiteId <= 0) {
    reply.status(400).send({
      success: false,
      error: "Invalid site ID: must be a positive integer",
    });
    return null;
  }

  // Settings screens read back the write they just made, so this must not be
  // served from another worker's pre-write cache entry.
  const config = await siteConfig.reload(numericSiteId);

  if (!config) {
    reply.status(404).send({
      success: false,
      error: "Site not found",
    });
    return null;
  }

  return config;
}

/**
 * Read one exclusion list for a Site and return it under its own field name.
 * Shared by all seven exclusion GET endpoints.
 */
async function getExclusionField(request: FastifyRequest, reply: FastifyReply, field: ExclusionField) {
  try {
    const config = await loadSiteConfigForSettings(request, reply);
    if (!config) {
      return reply;
    }

    return reply.send({
      success: true,
      [field]: config[field],
    });
  } catch (error) {
    request.log.error({ err: error }, `Error getting ${FIELD_LABELS[field]}`);
    return reply.status(500).send({
      success: false,
      error: `Failed to get ${FIELD_LABELS[field]}`,
    });
  }
}

export function getSiteExcludedIPs(request: FastifyRequest, reply: FastifyReply) {
  return getExclusionField(request, reply, "excludedIPs");
}

export function getSiteExcludedCountries(request: FastifyRequest, reply: FastifyReply) {
  return getExclusionField(request, reply, "excludedCountries");
}

export function getSiteExcludedPaths(request: FastifyRequest, reply: FastifyReply) {
  return getExclusionField(request, reply, "excludedPaths");
}

export function getSiteExcludedHostnames(request: FastifyRequest, reply: FastifyReply) {
  return getExclusionField(request, reply, "excludedHostnames");
}

export function getSiteExcludedUserAgents(request: FastifyRequest, reply: FastifyReply) {
  return getExclusionField(request, reply, "excludedUserAgents");
}

export function getSiteExcludedASNs(request: FastifyRequest, reply: FastifyReply) {
  return getExclusionField(request, reply, "excludedASNs");
}

export function getSiteExcludedQueryParams(request: FastifyRequest, reply: FastifyReply) {
  return getExclusionField(request, reply, "excludedQueryParams");
}
