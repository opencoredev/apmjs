import { Suspense } from "react";
import { SearchHome } from "@/components/search-home";
import { RecentActivity, RecentActivitySkeleton } from "@/components/recent-activity";

// Runs before hydration: with ?q= in the URL the empty-state list stays hidden until the results take over.
const HIDE_EMPTY_STATE = `if(/[?&]q=[^&]/.test(location.search))document.documentElement.dataset.q=""`;

export default function Home() {
  return (
    <>
      <script dangerouslySetInnerHTML={{ __html: HIDE_EMPTY_STATE }} />
      <SearchHome
        recent={
          <Suspense fallback={<RecentActivitySkeleton />}>
            <RecentActivity />
          </Suspense>
        }
      />
    </>
  );
}
