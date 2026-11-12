// Shown when the registry could not be read: an outage, not a missing package.
import { buttonVariants } from "@/components/ui/button";

export function RegistryUnavailable({ what, retryHref }: { what: string; retryHref: string }) {
  return (
    <div role="alert" className="flex max-w-xl flex-col items-start gap-4 rounded-2xl bg-surface px-5 py-6 sm:px-6">
      <div className="flex flex-col gap-2">
        <h1 className="text-2xl font-medium tracking-tight">The registry did not answer</h1>
        <p className="text-[15px] leading-6 text-pretty text-muted-foreground">
          We couldn&apos;t load {what} just now. This is a problem on our side, not a sign that the package is gone. Try again in a moment.
        </p>
      </div>
      {/* A plain link, so the retry is a full request that checks the registry again. */}
      <a href={retryHref} className={buttonVariants({ size: "lg" })}>
        Try again
      </a>
    </div>
  );
}

/** The /package/... path for a name, one encoded segment per name part. */
export function packagePath(name: string): string {
  return `/package/${name.split("/").map(encodeURIComponent).join("/")}`;
}
