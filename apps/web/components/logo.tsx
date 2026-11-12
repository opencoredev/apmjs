// The apm mark: a package cube cut into three version slabs, the middle one pulled out
// (a version taken back). Face tones come from --logo-* tokens so it follows light and dark.
import { cn } from "cn";

const INK = { left: "var(--logo-left)", right: "var(--logo-right)", top: "var(--logo-top)" } as const;
const PULLED = { left: "#ff4f1f", right: "#c73a10", top: "#ff8a63" } as const;

type Faces = { left: string; right: string; top: string };
type Slab = { top: string; left: string; right: string; tone: Faces };

// Isometric slabs, back to front. Generated once (see shots/logo-option-1.svg) and inlined here.
const SLABS: readonly Slab[] = [
  { top: "14.4,12.25 25.23,18.5 14.4,24.75 3.58,18.5", left: "3.58,18.5 14.4,24.75 14.4,28.5 3.58,22.25", right: "25.23,18.5 14.4,24.75 14.4,28.5 25.23,22.25", tone: INK },
  { top: "17.65,9.75 28.47,16 17.65,22.25 6.82,16", left: "6.82,16 17.65,22.25 17.65,26 6.82,19.75", right: "28.47,16 17.65,22.25 17.65,26 28.47,19.75", tone: PULLED },
  { top: "14.4,3.5 25.23,9.75 14.4,16 3.58,9.75", left: "3.58,9.75 14.4,16 14.4,19.75 3.58,13.5", right: "25.23,9.75 14.4,16 14.4,19.75 25.23,13.5", tone: INK },
];

function Mark() {
  return (
    <>
      {SLABS.map((s, i) => (
        <g key={i}>
          <polygon points={s.top} fill={s.tone.top} />
          <polygon points={s.left} fill={s.tone.left} />
          <polygon points={s.right} fill={s.tone.right} />
        </g>
      ))}
    </>
  );
}

// "apm" drawn from one 3.4-unit stroke: single-storey a, p with descender, two-arch m.
const WORD = "M54.3,9 V23 M49,10.7 a5.3,5.3 0 1 0 0.01,0 Z M61.7,9 V29 M67,10.7 a5.3,5.3 0 1 0 0.01,0 Z M79.7,23 V15.3 a4.6,4.6 0 0 1 9.2,0 V23 M88.9,15.3 a4.6,4.6 0 0 1 9.2,0 V23";

export function LogoMark({ className }: { className?: string }) {
  return (
    <svg viewBox="3 3 26 26" className={cn("size-6", className)} aria-hidden>
      <Mark />
    </svg>
  );
}

export function Logo({ className }: { className?: string }) {
  return (
    <svg viewBox="3 3 97 26.5" className={cn("h-7 w-auto", className)} role="img" aria-label="apm">
      <Mark />
      <path d={WORD} fill="none" stroke="currentColor" strokeWidth={3.4} strokeLinejoin="round" />
    </svg>
  );
}
