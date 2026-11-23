"use client";

// After each client-router navigation, asks the inline loader (lib/analytics.ts, databuddyLoaderScript) to add the
// databuddy.js tag if it has not yet. That matters after a hard load of a private page, where the loader added none:
// the effect runs once the router has committed the new URL, so the tag is added only when location already names a
// public page and databuddy.js never sees the private page's path or query. The loader alone decides; where it
// declined (another origin, an opt-out) it left nothing to call, and this does nothing.
import { usePathname } from "next/navigation";
import { useEffect } from "react";

declare global {
  interface Window {
    /** Defined by the inline loader (DATABUDDY_LOAD_GLOBAL) only where the tracker may load. */
    __apmLoadDatabuddy?: () => void;
  }
}

export function DatabuddyRouteLoader() {
  const pathname = usePathname();

  useEffect(() => {
    try {
      window.__apmLoadDatabuddy?.();
    } catch {
      // analytics never breaks navigation
    }
  }, [pathname]);

  return null;
}
