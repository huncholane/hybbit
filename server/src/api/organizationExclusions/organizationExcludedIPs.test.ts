import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  selectRows: [] as Array<{ excludedIPs: string[] | null }>,
  updatedRows: [] as Array<{ id: string }>,
  set: vi.fn(),
  invalidateOrganization: vi.fn(),
  reload: vi.fn(),
}));

vi.mock("../../db/postgres/postgres.js", () => ({
  db: {
    select: () => ({ from: () => ({ where: () => ({ limit: async () => mocks.selectRows }) }) }),
    update: () => ({
      set: (values: unknown) => {
        mocks.set(values);
        return { where: () => ({ returning: async () => mocks.updatedRows }) };
      },
    }),
  },
}));

vi.mock("../../lib/siteConfig.js", () => ({
  siteConfig: { invalidateOrganization: mocks.invalidateOrganization, reload: mocks.reload },
}));

import {
  getOrganizationExcludedIPs,
  getSiteOrganizationExcludedIPs,
  updateOrganizationExcludedIPs,
} from "./organizationExcludedIPs.js";

const log = { error: vi.fn(), info: vi.fn() };

function makeReply() {
  const reply = { status: vi.fn(), send: vi.fn() };
  reply.status.mockReturnValue(reply);
  reply.send.mockReturnValue(reply);
  return reply;
}

beforeEach(() => {
  vi.clearAllMocks();
  mocks.selectRows = [];
  mocks.updatedRows = [];
});

describe("updateOrganizationExcludedIPs", () => {
  it("saves the list and drops every cached Site of the organization", async () => {
    mocks.updatedRows = [{ id: "org_1" }];
    const excludedIPs = ["104.50.131.150", "2600:1700:7bd9:6730::/64", "192.168.1.1-192.168.1.10"];
    const reply = makeReply();

    await updateOrganizationExcludedIPs(
      { params: { organizationId: "org_1" }, body: { excludedIPs }, log } as any,
      reply as any
    );

    expect(mocks.set).toHaveBeenCalledWith({ excludedIPs });
    expect(mocks.invalidateOrganization).toHaveBeenCalledWith("org_1");
    expect(reply.send).toHaveBeenCalledWith({ success: true, excludedIPs });
  });

  it("rejects an invalid pattern without writing anything", async () => {
    const reply = makeReply();

    await updateOrganizationExcludedIPs(
      { params: { organizationId: "org_1" }, body: { excludedIPs: ["76.84.217.7", "not-an-ip"] }, log } as any,
      reply as any
    );

    expect(reply.status).toHaveBeenCalledWith(400);
    expect(mocks.set).not.toHaveBeenCalled();
    expect(mocks.invalidateOrganization).not.toHaveBeenCalled();
  });

  it("answers 404 for an organization that does not exist", async () => {
    const reply = makeReply();

    await updateOrganizationExcludedIPs(
      { params: { organizationId: "missing" }, body: { excludedIPs: [] }, log } as any,
      reply as any
    );

    expect(reply.status).toHaveBeenCalledWith(404);
    expect(mocks.invalidateOrganization).not.toHaveBeenCalled();
  });
});

describe("getOrganizationExcludedIPs", () => {
  it("returns the stored list", async () => {
    mocks.selectRows = [{ excludedIPs: ["76.84.217.7"] }];
    const reply = makeReply();

    await getOrganizationExcludedIPs({ params: { organizationId: "org_1" }, log } as any, reply as any);

    expect(reply.send).toHaveBeenCalledWith({ success: true, excludedIPs: ["76.84.217.7"] });
  });
});

describe("getSiteOrganizationExcludedIPs", () => {
  it("shows a site its organization's list and whether it applies it", async () => {
    mocks.reload.mockResolvedValue({
      organizationId: "org_1",
      useOrganizationExcludedIPs: false,
      organizationExcludedIPs: ["76.84.217.7"],
    });
    const reply = makeReply();

    await getSiteOrganizationExcludedIPs({ params: { siteId: "42" }, log } as any, reply as any);

    expect(mocks.reload).toHaveBeenCalledWith(42);
    expect(reply.send).toHaveBeenCalledWith({
      success: true,
      organizationId: "org_1",
      useOrganizationExcludedIPs: false,
      excludedIPs: ["76.84.217.7"],
    });
  });
});
