"use client";

// Refreshes the package page while its version's analysis is queued, so the score appears without a reload. Mounted
// only while the page shows the queued notice; the refreshed page drops it once the version is scored.
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { refreshStep } from "@/lib/queued-refresh";

export function QueuedRefresh() {
  const router = useRouter();
  const [stopped, setStopped] = useState(false);

  useEffect(() => {
    const startedAt = Date.now();
    let timer: ReturnType<typeof setTimeout> | undefined;

    const next = (): void => {
      const step = refreshStep({ startedAt, now: Date.now() });

      if (step.kind === "stop") {
        setStopped(true);

        return;
      }

      timer = setTimeout(() => {
        router.refresh();
        next();
      }, step.ms);
    };

    next();

    return () => clearTimeout(timer);
  }, [router]);

  return (
    <span className="mt-1 block text-sm" aria-live="polite">
      {stopped ? "Still queued. Reload the page to check again." : "This page checks again every few seconds."}
    </span>
  );
}
