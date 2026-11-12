// The Capabilities section's wording: names, declaration marks, the basis note and the intro.
import { describe, expect, test } from "bun:test";
import { basisNote, capabilitiesIntro, capabilityParts, envNames, statusMark } from "./capabilities";

describe("capabilities wording", () => {
  test("a label splits into its name and what it covers", () => {
    expect(capabilityParts("Network: makes requests or opens sockets")).toEqual({ name: "Network", detail: "makes requests or opens sockets" });
    expect(capabilityParts("Native code")).toEqual({ name: "Native code", detail: "" });
  });

  test("each status has its mark, and a package that declares nothing gets none", () => {
    expect(statusMark({ status: "declared" })).toEqual({ text: "Declared", tone: "ok" });
    expect(statusMark({ status: "undeclared" })).toEqual({ text: "Not in its declaration", tone: "warn" });
    expect(statusMark({ status: "unused" })).toEqual({ text: "Declared, not seen used", tone: "muted" });
    expect(statusMark({ status: "not-declared" })).toBeNull();
  });

  test("text-only and possible evidence say so; code says nothing extra", () => {
    expect(basisNote({ basis: "text" })).toBe("Text mention only");
    expect(basisNote({ basis: "possible" })).toBe("Possible");
    expect(basisNote({ basis: "code" })).toBeNull();
  });

  test("the intro says whether a declaration was compared", () => {
    expect(capabilitiesIntro({ kind: "declared" })).toContain("compared with the capabilities its package.json declares");
    expect(capabilitiesIntro({ kind: "none" })).toContain("does not declare its capabilities");
    expect(capabilitiesIntro(null)).toContain("Listed, not scored");
  });

  test("a name built at runtime reads as such", () => {
    expect(envNames(["RESEND_API_KEY", "*"])).toEqual(["RESEND_API_KEY", "names built at runtime"]);
  });
});
