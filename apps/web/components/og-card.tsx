// The Open Graph cards app/og/[[...name]]/route.tsx renders: the site's, and a package's (its name, latest version,
// score and grade). 1200×630, for ImageResponse (Satori).
/* oxlint-disable shadcn/no-inline-styles -- ImageResponse (Satori) renders inline styles only: no stylesheet, no Tailwind, no theme tokens */
import { MARK_INK, MARK_PULLED, WORD } from "@/components/logo";
import { toneOf, type Tone } from "@/components/score-badge";
import type { PackageInfo } from "@/lib/registry";

export const OG_SIZE = { width: 1200, height: 630 };

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

export function siteCard() {
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

/**
 * What a package card shows: the name, latest version, score and grade, and no text the publisher wrote. A card is
 * kept for a few seconds by the site and for as long as they like by the sites that unfurl it (X, Slack, chat apps),
 * and a revoke changes a package's description: so the card has none to keep.
 */
export type PackageCardInput = { readonly name: string; readonly version: string | null; readonly score: number | null; readonly grade: string | null };

/** The card's input from the package answer; with no answer (the registry down), the name alone, unscored. */
export function packageCardInput(input: { name: string; pkg: PackageInfo | null }): PackageCardInput {
  const { pkg } = input;

  return { name: pkg?.name ?? input.name, version: pkg?.latest ?? null, score: pkg?.score?.score ?? null, grade: pkg?.score?.grade ?? null };
}

export function packageCard(input: PackageCardInput) {
  const tone = TONE[toneOf(input.score)];
  const nameSize = input.name.length > 28 ? 56 : input.name.length > 18 ? 72 : 88;

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
