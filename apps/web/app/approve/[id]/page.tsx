import { Suspense } from "react";
import { ApproveView } from "./approve-view";

export const metadata = { title: "Approve a version · apm" };

export default function ApprovePage() {
  return (
    <Suspense fallback={<div className="h-96 animate-pulse rounded-2xl bg-muted" />}>
      <ApproveView />
    </Suspense>
  );
}
