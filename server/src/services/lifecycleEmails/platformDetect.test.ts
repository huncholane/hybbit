import { describe, expect, it } from "vitest";
import { detectPlatformFromHtml, hasHygoScript, isPublicUnicastAddress } from "./platformDetect.js";

describe("isPublicUnicastAddress (SSRF guard)", () => {
  it.each([
    "127.0.0.1",
    "10.0.0.5",
    "172.16.0.1",
    "172.31.255.255",
    "192.168.1.1",
    "169.254.169.254", // cloud metadata
    "100.64.0.1", // CGNAT
    "0.0.0.0",
    "198.18.0.1",
    "224.0.0.1",
    "255.255.255.255",
    "::1",
    "::",
    "fc00::1",
    "fd12::1",
    "fe80::1",
    "::ffff:127.0.0.1", // v4-mapped loopback
    "::ffff:10.0.0.1",
  ])("rejects %s", address => {
    expect(isPublicUnicastAddress(address)).toBe(false);
  });

  it.each(["8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111", "::ffff:8.8.8.8"])(
    "allows public %s",
    address => {
      expect(isPublicUnicastAddress(address)).toBe(true);
    }
  );

  it("rejects garbage", () => {
    expect(isPublicUnicastAddress("not-an-ip")).toBe(false);
    expect(isPublicUnicastAddress("")).toBe(false);
  });
});

describe("hasHygoScript", () => {
  it("requires the script AND a matching site id", () => {
    const html = '<script src="https://app.hygo.ai/api/script.js" data-site-id="42" defer></script>';
    expect(hasHygoScript(html, 42)).toBe(true);
    // A leftover snippet for a different site must not report success
    expect(hasHygoScript(html, 43)).toBe(false);
  });

  it("does not match a prefix of a longer site id", () => {
    const html = '<script src="/api/script.js" data-site-id="421"></script>';
    expect(hasHygoScript(html, 42)).toBe(false);
  });

  it("rejects pages without the script", () => {
    expect(hasHygoScript('<span data-site-id="42"></span>', 42)).toBe(false);
  });
});

describe("detectPlatformFromHtml", () => {
  it("prefers the more specific marker (WooCommerce over WordPress)", () => {
    const html = '<link href="/wp-content/x.css"><body class="woocommerce">';
    expect(detectPlatformFromHtml(html)?.key).toBe("woocommerce");
  });

  it("detects Next.js", () => {
    expect(detectPlatformFromHtml('<script id="__NEXT_DATA__">{}</script>')?.key).toBe("next-js");
  });

  it("returns null for unknown stacks", () => {
    expect(detectPlatformFromHtml("<html><body>plain</body></html>")).toBeNull();
  });
});
