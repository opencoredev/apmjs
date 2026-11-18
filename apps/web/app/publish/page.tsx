import { PUBLIC_REGISTRY_URL, SITE_URL } from "@/lib/agent/site";
import { PublishView } from "./publish-view";

export const metadata = { title: "Publish · apm" };

export default function PublishPage() {
  return <PublishView registry={PUBLIC_REGISTRY_URL} site={SITE_URL} />;
}
