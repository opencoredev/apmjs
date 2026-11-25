// The home page's one line on getting the apm CLI: the install script, Homebrew by its full tap name (plain
// `brew install apm` is another project's formula), and the docs quickstart.
import { ArrowRightIcon } from "lucide-react";
import { CopyBlock } from "@/components/copy-button";

const INSTALL = "curl -fsSL https://apmjs.dev/install | sh";
const BREW = "brew install opencoredev/tap/apm";
const QUICKSTART = "https://docs.apmjs.dev/quickstart";

export function CliInstall() {
  return (
    <section aria-labelledby="cli-install" className="flex flex-col gap-2">
      <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
        <h2 id="cli-install" className="text-[15px] font-medium">
          Install the apm CLI
        </h2>
        <a href={QUICKSTART} className="inline-flex min-h-6 items-center gap-1 text-sm text-muted-foreground underline-offset-4 hover:text-foreground hover:underline">
          Quickstart
          <ArrowRightIcon className="size-3.5" aria-hidden />
        </a>
      </div>
      <CopyBlock oneLine text={INSTALL} label="Copy the install command" />
      <p className="text-[13px] leading-5 text-pretty text-muted-foreground">
        Or with Homebrew: <code className="font-mono text-[12.5px] text-foreground">{BREW}</code>
      </p>
    </section>
  );
}
