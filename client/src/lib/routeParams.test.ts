import { describe, expect, it } from "vitest";
import { placeholderStaticParams, routeParamFromPathname, routeParamPlaceholder } from "./routeParams";

describe("routeParamPlaceholder", () => {
  it("names the exported directory", () => {
    expect(routeParamPlaceholder("site")).toBe("__site__");
    expect(placeholderStaticParams("privateKey")).toEqual([{ privateKey: "__privateKey__" }]);
  });
});

describe("routeParamFromPathname", () => {
  it("reads a segment by how many URL segments sit below its layout", () => {
    expect(routeParamFromPathname("/12/main", ["main"])).toBe("12");
    expect(routeParamFromPathname("/12/abcdefabcdef/user/u1", ["__privateKey__", "user", "__userId__"])).toBe("12");
    expect(routeParamFromPathname("/12/abcdefabcdef/user/u1", ["user", "__userId__"])).toBe("abcdefabcdef");
    expect(routeParamFromPathname("/12/dashboards/7", [])).toBe("7");
  });

  it("ignores route groups, which are not part of the URL", () => {
    expect(routeParamFromPathname("/12/main", ["(group)", "main"])).toBe("12");
  });

  it("encodes values the way Next's useParams does", () => {
    expect(routeParamFromPathname("/12/user/a@b", [])).toBe("a%40b");
    expect(routeParamFromPathname("/12/user/a%40b", [])).toBe("a%40b");
    expect(routeParamFromPathname("/12/user/a%zz", [])).toBe("a%zz");
  });
});
