// Open Graph images: /og for the site, /og/<name> for a package (its name, score and grade). 1200×630 PNG.
/* oxlint-disable shadcn/no-inline-styles -- ImageResponse (Satori) renders inline styles only: no stylesheet, no Tailwind, no theme tokens */
import { ImageResponse } from "next/og";
import type { NextRequest } from "next/server";
import { MARK_INK, MARK_PULLED, WORD } from "@/components/logo";
import { toneOf, type Tone } from "@/components/score-badge";
import { AGENT_CACHE } from "@/lib/agent/agent-http";
import { parsePackageRoute } from "@/lib/package-route";
import { getPackageUncached } from "@/lib/registry";

const SIZE = { width: 1200, height: 630 };

// The site's light theme (app/globals.css)
const INK = "#171717";
const MUTED = "#696965";
const SURFACE = "#f4f4f2";
const ACCENT = "#e5512a";

const TONE: Record<Tone, { fg: string; bg: string }> = {
  none: { fg: MUTED, bg: SURFACE },
  ok: { fg: "#167d3c", bg: "#e9f5ed" },
  warn: { fg: "#9a4d00", bg: "#fcf1e3" },
  bad: { fg: "#c42b2b", bg: "#fcebea" },
};

function Logo({ height }: { height: number }) {
  return (
    <svg viewBox="0 -760 2956 980" height={height} width={(height * 2956) / 980}>
      <g transform="translate(0 40) scale(0.86669)">
        <path d={MARK_INK} fill={INK} />
        <path d={MARK_PULLED} fill={ACCENT} />
      </g>
      <path d={WORD} transform="translate(940 0)" fill={INK} />
    </svg>
  );
}

function Frame({ children }: { children: React.ReactNode }) {
  return <div style={{ width: "100%", height: "100%", display: "flex", flexDirection: "column", justifyContent: "space-between", background: "#ffffff", color: INK, padding: "64px 72px", fontFamily: "sans-serif" }}>{children}</div>;
}

function siteCard() {
  return (
    <Frame>
      <Logo height={72} />
      <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
        <div style={{ fontSize: 68, fontWeight: 600, letterSpacing: "-0.02em", lineHeight: 1.1 }}>Check npm packages before you install them</div>
        <div style={{ fontSize: 32, color: MUTED, lineHeight: 1.35 }}>A security score for every version, with the cited line behind every lost point. Works with bun, npm and pnpm.</div>
      </div>
      <div style={{ fontSize: 28, color: MUTED }}>apmjs.dev</div>
    </Frame>
  );
}

function packageCard(input: { name: string; version: string | null; description: string; score: number | null; grade: string | null }) {
  const tone = TONE[toneOf(input.score)];
  const nameSize = input.name.length > 28 ? 56 : input.name.length > 18 ? 72 : 88;
  const description = input.description.length > 140 ? `${input.description.slice(0, 137)}…` : input.description;

  return (
    <Frame>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <Logo height={56} />
        <div style={{ fontSize: 28, color: MUTED }}>apmjs.dev</div>
      </div>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 48 }}>
        <div style={{ display: "flex", flexDirection: "column", gap: 18, flex: 1, minWidth: 0 }}>
          <div style={{ fontSize: nameSize, fontWeight: 600, fontFamily: "monospace", letterSpacing: "-0.02em", lineHeight: 1.05, wordBreak: "break-all" }}>{input.name}</div>
          {input.version && <div style={{ fontSize: 30, color: MUTED, fontFamily: "monospace" }}>{input.version}</div>}
          {description && <div style={{ fontSize: 30, color: MUTED, lineHeight: 1.35 }}>{description}</div>}
        </div>
        <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", width: 260, height: 260, borderRadius: 40, background: tone.bg, color: tone.fg, flexShrink: 0 }}>
          {input.score === null ? (
            <div style={{ fontSize: 44, fontWeight: 600 }}>not scored</div>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", alignItems: "center" }}>
              <div style={{ fontSize: 120, fontWeight: 700, lineHeight: 1 }}>{String(input.score)}</div>
              <div style={{ fontSize: 32, marginTop: 12 }}>{`grade ${input.grade ?? "?"} · of 100`}</div>
            </div>
          )}
        </div>
      </div>
      <div style={{ fontSize: 26, color: MUTED }}>apm security score: every lost point cites the file and line behind it</div>
    </Frame>
  );
}

export async function GET(_request: NextRequest, ctx: RouteContext<"/og/[[...name]]">): Promise<Response> {
  const segs = (await ctx.params).name ?? [];

  // the site card never changes between deploys
  if (segs.length === 0) return new ImageResponse(siteCard(), { ...SIZE, headers: { "cache-control": "public, max-age=3600, s-maxage=3600" } });
  const route = parsePackageRoute(segs);

  if (route?.kind !== "package") return new Response("Not found", { status: 404 });
  // a package card shows a score that a yank, a revoke or a dismissal changes: stored for seconds, not an hour
  const headers = { "cache-control": AGENT_CACHE.image };
  const found = await getPackageUncached(route.name);

  if (found.kind === "missing") return new Response("Not found", { status: 404, headers });
  // registry down: the card still names the package, unscored
  const pkg = found.kind === "ok" ? found.value : null;
  const card = packageCard({ name: pkg?.name ?? route.name, version: pkg?.latest ?? null, description: pkg?.description ?? "", score: pkg?.score?.score ?? null, grade: pkg?.score?.grade ?? null });

  return new ImageResponse(card, { ...SIZE, headers });
}
