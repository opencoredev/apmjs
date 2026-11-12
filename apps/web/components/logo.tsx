// The apm mark: a package cut into three slabs, the middle one pulled out (a version taken back).
// Flat isometric in one ink with a single accent on the pulled slab; faces are separated by knockouts, not shading.
// The wordmark is Host Grotesk 500 at the site's -0.02em tracking, outlined, so it renders the same before the font loads.
// Generated in font units (1000 upm, baseline y=0); see shots/logo-v2-3.svg.
import { cn } from "cn";

const MARK_INK = "M330,-162 L20,-340 L196,-442 L232,-421 L216,-412 L216,-234 L336,-165 Z M330,0 L0,-190 L0,-317 L330,-127 L366,-148 L476,-84 Z M330,-912 L640,-732 L330,-554 L20,-732 Z M660,-582 L330,-392 L0,-582 L0,-709 L330,-519 L660,-709 Z";
const MARK_PULLED = "M880,-398 L570,-219 L260,-398 L266,-401 L330,-364 L634,-540 Z M570,-57 L240,-248 L240,-375 L570,-184 L900,-375 L900,-248 Z";
const WORD = "M214 12Q156 12 116 -8Q75 -29 54 -63Q34 -97 34 -137Q34 -216 91 -259Q148 -302 241 -302Q283 -302 316 -296Q349 -289 370 -282V-305Q370 -363 338 -391Q307 -419 255 -419Q216 -419 186 -403Q156 -387 148 -347H42Q48 -401 78 -436Q109 -472 155 -490Q201 -508 255 -508Q363 -508 422 -454Q480 -400 480 -305V-175Q480 -137 484 -120Q489 -103 500 -98Q510 -94 528 -94H533V0H509Q459 0 426 -15Q392 -30 379 -75Q355 -38 314 -13Q273 12 214 12ZM236 -74Q274 -74 301 -92Q328 -111 344 -142Q361 -172 365 -207Q343 -213 313 -219Q283 -225 252 -225Q199 -225 172 -203Q145 -181 145 -145Q145 -114 169 -94Q193 -74 236 -74Z M584 220V-496H694V-420Q718 -455 760 -482Q802 -508 866 -508Q938 -508 993 -474Q1048 -440 1080 -381Q1111 -322 1111 -247Q1111 -173 1080 -114Q1048 -55 993 -22Q938 12 866 12Q808 12 764 -11Q720 -34 694 -74V220ZM846 -84Q891 -84 926 -105Q960 -126 980 -162Q999 -199 999 -247Q999 -296 980 -334Q960 -371 926 -392Q891 -412 846 -412Q801 -412 766 -392Q732 -371 712 -334Q693 -297 693 -248Q693 -199 712 -162Q732 -126 766 -105Q801 -84 846 -84Z M1168 0V-496H1278V-431Q1302 -467 1342 -488Q1381 -508 1430 -508Q1488 -508 1530 -485Q1571 -462 1594 -416Q1621 -459 1666 -484Q1712 -508 1766 -508Q1859 -508 1912 -452Q1964 -395 1964 -284V0H1855V-273Q1855 -343 1828 -378Q1800 -414 1746 -414Q1691 -414 1656 -373Q1622 -332 1622 -256V0H1512V-273Q1512 -343 1484 -378Q1456 -414 1402 -414Q1348 -414 1313 -373Q1278 -332 1278 -256V0Z";

// light-dark() follows the page's color-scheme; the fill attribute is the fallback where it is unsupported.
const ACCENT = { light: "#e5512a", lightDark: "light-dark(#e5512a, #ff6a43)" } as const;

function Mark() {
  return (
    <g transform="translate(0 40) scale(0.86669)">
      <path d={MARK_INK} fill="currentColor" />
      <path d={MARK_PULLED} fill={ACCENT.light} style={{ fill: ACCENT.lightDark }} />
    </g>
  );
}

export function LogoMark({ className }: { className?: string }) {
  return (
    <svg viewBox="-10 -760 800 800" className={cn("size-6", className)} aria-hidden>
      <Mark />
    </svg>
  );
}

export function Logo({ className }: { className?: string }) {
  return (
    <svg viewBox="0 -760 2956 980" className={cn("h-7 w-auto", className)} role="img" aria-label="apm">
      <Mark />
      <path d={WORD} transform="translate(940 0)" fill="currentColor" />
    </svg>
  );
}
