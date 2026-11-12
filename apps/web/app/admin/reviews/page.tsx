import { Suspense } from "react";
import { ReviewQueueView } from "./review-queue-view";

export const metadata = { title: "AI review queue · apm" };

export default function ReviewQueuePage() {
  return (
    <Suspense fallback={<div className="h-96 animate-pulse rounded-2xl bg-muted" />}>
      <ReviewQueueView />
    </Suspense>
  );
}
