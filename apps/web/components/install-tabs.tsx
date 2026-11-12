"use client";

import { useState } from "react";
import { CopyIcon, CheckIcon } from "lucide-react";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";

const CLIENTS = ["apm", "bun", "npm", "pnpm"] as const;
type Client = (typeof CLIENTS)[number];
const isClient = (v: unknown): v is Client => typeof v === "string" && (CLIENTS as readonly string[]).includes(v);

export function InstallTabs({ name, version }: { name: string; version: string | null }) {
  const [client, setClient] = useState<Client>("apm");
  const [copied, setCopied] = useState(false);
  const spec = version ? `${name}@${version}` : name;
  const cmd: Record<Client, string> = {
    apm: `apm add ${name}`,
    bun: `bun add ${spec}`,
    npm: `npm install ${spec}`,
    pnpm: `pnpm add ${spec}`,
  };
  return (
    <div className="rounded-xl bg-surface p-1.5">
      <div className="flex items-center justify-between gap-2 px-1.5 pt-0.5 pb-1.5">
        <span className="text-sm text-muted-foreground">Install</span>
        <Tabs
          value={client}
          onValueChange={(v) => {
            if (isClient(v)) setClient(v);
          }}
        >
          <TabsList className="h-8 rounded-full bg-transparent p-0">
            {CLIENTS.map((c) => (
              <TabsTrigger key={c} value={c} className="h-7 rounded-full px-3 font-mono text-xs data-active:bg-background data-active:shadow-xs">
                {c}
              </TabsTrigger>
            ))}
          </TabsList>
        </Tabs>
      </div>
      <div className="flex items-center gap-2 rounded-lg bg-background py-1.5 pr-1.5 pl-4 ring-1 ring-border">
        <code className="min-w-0 flex-1 truncate font-mono text-[15px]">
          <span className="text-faint select-none">$ </span>
          {cmd[client]}
        </code>
        <button
          type="button"
          aria-label={copied ? "Copied" : "Copy install command"}
          className="grid size-9 shrink-0 place-items-center rounded-md text-muted-foreground transition-colors hover:bg-surface hover:text-foreground active:scale-95"
          onClick={() => {
            void navigator.clipboard.writeText(cmd[client]).then(() => {
              setCopied(true);
              setTimeout(() => setCopied(false), 1200);
            });
          }}
        >
          {copied ? <CheckIcon className="size-4 text-ok" /> : <CopyIcon className="size-4" />}
        </button>
      </div>
      {client === "apm" && <p className="px-2.5 pt-2 pb-1 text-[13px] leading-5 text-muted-foreground">Checks the score and the 24-hour cooldown first, then runs your project’s own package manager with the exact version.</p>}
    </div>
  );
}
