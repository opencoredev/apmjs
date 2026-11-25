"use client";

// Sends the custom events that server-rendered elements declare with lib/databuddy-client.ts's clickEvent and
// copyEvent: one click listener and one copy listener on the document, so the docs overview, the 404 page and the
// package page's evidence lines stay server components. Mounted with DatabuddyNavigation, so only on a build with a
// client id; track() itself does nothing where the tracker did not load.
import { useEffect } from "react";
import { eventFromAttributes, track } from "@/lib/databuddy-client";

function closest(target: EventTarget | Node | null, selector: string): HTMLElement | null {
  const node = target instanceof Node ? target : null;
  const el = node instanceof Element ? node : (node?.parentElement ?? null);
  const found = el?.closest(selector);

  return found instanceof HTMLElement ? found : null;
}

export function AnalyticsEvents() {
  useEffect(() => {
    const onClick = (e: MouseEvent) => {
      const el = closest(e.target, "[data-event]");
      const event = el && eventFromAttributes({ name: el.dataset.event, props: el.dataset.eventProps });

      if (event) track(event);
    };

    const onCopy = () => {
      const el = closest(document.getSelection()?.anchorNode ?? null, "[data-copy-event]");
      const event = el && eventFromAttributes({ name: el.dataset.copyEvent, props: el.dataset.eventProps });

      if (event) track(event);
    };

    document.addEventListener("click", onClick, { capture: true });
    document.addEventListener("copy", onCopy);

    return () => {
      document.removeEventListener("click", onClick, { capture: true });
      document.removeEventListener("copy", onCopy);
    };
  }, []);

  return null;
}
