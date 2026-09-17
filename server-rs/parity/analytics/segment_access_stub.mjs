// Stands in for server/src/api/analytics/segments/segmentAccess.ts when the dump
// script imports expandSegmentParam: the two database reads come from
// globalThis.__segmentStub, the pure rule is copied verbatim.
export const NO_ACCESS_ACTOR = { userId: null, hasSiteAccess: false, isAdmin: false };

export async function loadSegmentForSite() {
  return globalThis.__segmentStub.loaded;
}

export async function resolveSegmentActor() {
  return globalThis.__segmentStub.actor;
}

export function canReadSegment(segment, actor) {
  return actor.hasSiteAccess || segment.isPublic;
}
