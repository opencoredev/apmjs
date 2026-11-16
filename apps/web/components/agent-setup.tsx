"use client";

// The home page's agent setup: a prompt that has a coding agent connect apm's MCP server itself, or the one
// setting per agent to add by hand, plus the line that tells the agent when to call it. Static: no data reads.
import Link from "next/link";
import { useState } from "react";
import { cn } from "cn";
import { ArrowRightIcon, BotIcon, ChevronDownIcon } from "lucide-react";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { CopyBlock, CopyGlyph, CopyStatus, useCopy } from "@/components/copy-button";
import { INSTRUCTIONS_LINE, mcpSetups, setupPrompt } from "@/lib/agent-prompt";

const SETUPS = mcpSetups();

type SetupKey = keyof typeof SETUPS;

const KEYS = ["claude", "codex", "cursor"] as const satisfies readonly SetupKey[];

const isKey = (v: unknown): v is SetupKey => KEYS.some((k) => k === v);

export function AgentSetup() {
  const [key, setKey] = useState<SetupKey>("claude");
  const [manual, setManual] = useState(false);
  const prompt = useCopy();
  const setup = SETUPS[key];

  return (
    <section aria-labelledby="agent-setup" className="grid gap-y-4 lg:grid-cols-4 lg:gap-x-2">
      <div className="flex flex-col gap-3 lg:col-span-2 lg:pr-10">
        <h2 id="agent-setup" className="text-[15px] font-medium">
          Set up your coding agent
        </h2>
        <p className="text-sm leading-6 text-pretty text-muted-foreground">
          apm&apos;s MCP server lets Claude Code, Codex or Cursor check a package before adding it: the score, the 24-hour cooldown and the dependency tree. It is read-only and
          needs no account.
        </p>
      </div>
      <div className="flex min-w-0 flex-col items-start gap-3 lg:col-span-2 lg:pt-8">
        <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
          <Button variant="secondary" onClick={() => prompt.copy(setupPrompt())}>
            {prompt.state === "copied" ? <CopyGlyph copied /> : <BotIcon aria-hidden />}
            {prompt.state === "copied" ? "Prompt copied" : "Copy setup prompt"}
          </Button>
          <span className="text-[13px] leading-5 text-muted-foreground">Paste it into your agent. It connects apm and adds a rule to your agent&apos;s instructions.</span>
        </div>
        <CopyStatus state={prompt.state} manual="Couldn't copy automatically. Open “Set up by hand” and copy the setting instead." />
        <div className="flex items-center gap-4 text-sm">
          <button
            type="button"
            aria-expanded={manual}
            aria-controls="agent-setup-manual"
            onClick={() => setManual((v) => !v)}
            className="inline-flex items-center gap-1 text-muted-foreground transition-colors hover:text-foreground"
          >
            Set up by hand
            <ChevronDownIcon className={cn("size-3.5 transition-transform duration-150", manual && "rotate-180")} aria-hidden />
          </button>
          <Link href="/docs#agents" className="inline-flex items-center gap-1 font-medium underline-offset-4 hover:underline">
            Agent guide
            <ArrowRightIcon className="size-3.5" aria-hidden />
          </Link>
        </div>
      </div>
      <div id="agent-setup-manual" hidden={!manual} className="mt-2 min-w-0 flex-col gap-4 lg:col-span-4 [&:not([hidden])]:flex">
        <Tabs
          value={key}
          onValueChange={(v) => {
            if (isKey(v)) setKey(v);
          }}
        >
          <TabsList aria-label="Agent" className="h-8 gap-0.5 rounded-lg bg-surface p-0.5">
            {KEYS.map((k) => (
              <TabsTrigger key={k} value={k} className="h-7 rounded-md px-2.5 text-[13px] data-active:bg-background data-active:shadow-xs dark:data-active:bg-input">
                {SETUPS[k].agent}
              </TabsTrigger>
            ))}
          </TabsList>
        </Tabs>
        <CopyBlock key={key} text={setup.text} label={`Copy the ${setup.agent} setting`} caption={setup.kind === "command" ? `${setup.where}:` : `In ${setup.where}:`} />
        <CopyBlock wrap text={INSTRUCTIONS_LINE} label="Copy the instructions line" caption="Then add this line to AGENTS.md, CLAUDE.md or a Cursor rule:" />
        <p className="text-[13px] leading-5 text-muted-foreground">Start a new agent session afterwards: the server loads when a session starts.</p>
      </div>
    </section>
  );
}
