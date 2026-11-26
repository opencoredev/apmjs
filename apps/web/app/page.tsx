import { Suspense } from "react";
import { SearchHome } from "@/components/search-home";
import { RecentActivity, RecentActivitySkeleton } from "@/components/recent-activity";
import { PopularPackages } from "@/components/popular-packages";
import { AgentSetup } from "@/components/agent-setup";
import { CliInstall } from "@/components/cli-install";
import { JsonLd } from "@/components/json-ld";
import { organizationJsonLd, pageMetadata, SITE_DESCRIPTION, SITE_TITLE, websiteJsonLd } from "@/lib/agent/seo";

export const metadata = { ...pageMetadata({ title: SITE_TITLE, description: SITE_DESCRIPTION, path: "/" }), title: { absolute: SITE_TITLE } };

// Runs before hydration: with ?q= in the URL the empty-state list stays hidden until the results take over.
const HIDE_EMPTY_STATE = `if(/[?&]q=[^&]/.test(location.search))document.documentElement.dataset.q=""`;

export default function Home() {
  return (
    <>
      <script dangerouslySetInnerHTML={{ __html: HIDE_EMPTY_STATE }} />
      <JsonLd data={websiteJsonLd()} />
      <JsonLd data={organizationJsonLd()} />
      <SearchHome
        recent={
          <div className="flex flex-col gap-10">
            <CliInstall />
            <PopularPackages />
            <AgentSetup />
            <Suspense fallback={<RecentActivitySkeleton />}>
              <RecentActivity />
            </Suspense>
          </div>
        }
      />
    </>
  );
}
