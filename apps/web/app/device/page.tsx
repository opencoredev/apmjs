import { Suspense } from "react";
import { DeviceView } from "./device-view";

export const metadata = { title: "Log in the CLI · apm" };

export default function DevicePage() {
  return (
    <div className="flex justify-center pt-4 sm:pt-10">
      <Suspense fallback={<div className="h-64 w-full max-w-md animate-pulse rounded-2xl bg-muted" />}>
        <DeviceView />
      </Suspense>
    </div>
  );
}
