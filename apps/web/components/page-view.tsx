"use client";

// One page view, sent when a public page mounts (lib/analytics.ts). A page that does not render this sends nothing.
import { useEffect } from "react";
import { sendPageView, type PageLabel } from "@/lib/analytics";

export function PageView({ label }: { label: PageLabel }): null {
  useEffect(() => sendPageView(label), [label]);

  return null;
}
