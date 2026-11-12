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
    <div className="rounded-lg border">
      <Tabs value={client} onValueChange={(v) => {
          if (isClient(v)) setClient(v);
        }}>
        <TabsList variant="line" className="w-full justify-start border-b px-2">
          {CLIENTS.map((c) => (
            <TabsTrigger key={c} value={c} className="font-mono text-xs">
              {c}
            </TabsTrigger>
          ))}
        </TabsList>
      </Tabs>
      <div className="flex items-center gap-2 px-3 py-2.5">
        <code className="flex-1 truncate font-mono text-sm">{cmd[client]}</code>
        <button
          type="button"
          aria-label="Copy install command"
          className="grid size-8 place-items-center rounded-md text-muted-foreground hover:bg-muted hover:text-foreground"
          onClick={() => {
            void navigator.clipboard.writeText(cmd[client]).then(() => {
              setCopied(true);
              setTimeout(() => setCopied(false), 1200);
            });
          }}
        >
          {copied ? <CheckIcon className="size-4" /> : <CopyIcon className="size-4" />}
        </button>
      </div>
      {client === "apm" && <p className="border-t px-3 py-2 text-xs text-muted-foreground">Checks score and cooldown first, then runs your project’s own package manager with the exact version.</p>}
    </div>
  );
}
