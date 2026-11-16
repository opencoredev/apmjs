"use client";

import { useSyncExternalStore } from "react";
import { SignInPanel } from "@/components/sign-in-panel";
import { safeNext } from "@/lib/safe-next";

const subscribe = (onChange: () => void): (() => void) => {
  window.addEventListener("popstate", onChange);

  return () => window.removeEventListener("popstate", onChange);
};

/**
 * The page's query (?next=, ?error=), read in the browser. The page is prerendered, so its HTML is made with no query
 * ("" here); useSearchParams would instead leave the whole panel out of the HTML, to be rendered once the page's
 * JavaScript runs. The buttons only show once the sign-in options are loaded, after hydration, so `next` is read by then.
 */
function useQuery(): URLSearchParams {
  return new URLSearchParams(
    useSyncExternalStore(
      subscribe,
      () => window.location.search,
      () => "",
    ),
  );
}

export function SignInView() {
  const params = useQuery();
  const failed = params.get("error") !== null;

  return (
    <div className="flex w-full max-w-md flex-col gap-4">
      {failed && (
        <p role="alert" className="rounded-lg bg-bad-soft px-4 py-3 text-sm text-bad">
          Sign-in did not finish. Try again.
        </p>
      )}
      <SignInPanel next={safeNext(params.get("next"))} />
    </div>
  );
}
