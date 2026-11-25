// Databuddy's tracker, mounted once in app/layout.tsx's <head> (lib/analytics.ts says what it sends and when it loads
// nothing). A server component that renders one inline, synchronous loader script and no databuddy.js tag: React
// hoists an async external script above everything else in the head, so a static tag would start before any check
// could run. The loader adds the tag itself, and only at https://apmjs.dev, without an opt-out, on a public page;
// DatabuddyRouteLoader adds it later when the visitor reaches a public page by the client router.
import { Suspense } from "react";
import { databuddyLoaderScript } from "@/lib/analytics";
import { AnalyticsEvents } from "./analytics-events";
import { DatabuddyRouteLoader } from "./databuddy-route-loader";

/** Databuddy's client id, inlined at build time; "" on every build but production's. */
const CLIENT_ID = process.env.NEXT_PUBLIC_DATABUDDY_CLIENT_ID?.trim() ?? "";

export function Databuddy() {
  if (CLIENT_ID === "") return null;

  return <script dangerouslySetInnerHTML={{ __html: databuddyLoaderScript("web", CLIENT_ID) }} />;
}

/**
 * The client-router half of the loader and the listener for declared click and copy events, for the body; nothing
 * without a client id. usePathname suspends while a route's params are unknown at prerender (Cache Components), so
 * the route loader sits in its own boundary with no fallback.
 */
export function DatabuddyNavigation() {
  if (CLIENT_ID === "") return null;

  return (
    <>
      <Suspense fallback={null}>
        <DatabuddyRouteLoader />
      </Suspense>
      <AnalyticsEvents />
    </>
  );
}
