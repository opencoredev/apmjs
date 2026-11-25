"use client";

// The home page's agent setup: a prompt that has a coding agent save the line that tells it to check packages with
// apm (over plain HTTP, so any agent can), or that line to add by hand, with apm's MCP server as an option. Static.
import Link from "next/link";
import { useState } from "react";
import { cn } from "cn";
import { ArrowRightIcon, BotIcon, ChevronDownIcon } from "lucide-react";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { CopyBlock, CopyGlyph, CopyStatus, useCopy } from "@/components/copy-button";
import { INSTRUCTIONS_LINE, mcpSetups, setupPrompt } from "@/lib/agent-prompt";
import { clickEvent, track } from "@/lib/databuddy-client";

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
    <section aria-labelledby="agent-setup" className="overflow-hidden rounded-xl border">
      <div className="flex flex-col gap-4 p-4 sm:flex-row sm:items-center sm:justify-between sm:gap-6 sm:p-5">
        <div className="flex min-w-0 gap-3.5">
          <span className="grid size-9 shrink-0 place-items-center rounded-lg bg-surface text-muted-foreground" aria-hidden>
            <BotIcon className="size-[18px]" />
          </span>
          <div className="flex min-w-0 flex-col gap-1">
            <h2 id="agent-setup" className="text-[15px] leading-6 font-medium">
              Set up your coding agent
            </h2>
            <p className="max-w-[60ch] text-[13px] leading-5 text-pretty text-muted-foreground">
              Paste one prompt into Claude Code, Codex, Cursor or any other coding agent, and it checks a package&apos;s score, 24-hour cooldown and dependencies before adding it.{" "}
              <span className="whitespace-nowrap">Read-only, no account needed.</span>
            </p>
          </div>
        </div>
        <Button size="lg" className="w-full sm:w-auto" onClick={() => {
            track({ name: "agent_setup_copied", props: { kind: "prompt" } });
            prompt.copy(setupPrompt(), () => setManual(true));
          }}>
          <CopyGlyph copied={prompt.state === "copied"} className="[&_svg]:text-current" />
          {prompt.state === "copied" ? "Prompt copied" : "Copy setup prompt"}
        </Button>
      </div>
      <CopyStatus state={prompt.state} className="px-4 pb-3 sm:px-5" manual="Couldn't copy automatically. Copy the setting below instead." />
      <div className="flex items-center justify-between gap-4 border-t bg-surface/40 px-4 py-2.5 text-[13px] sm:px-5">
        <button
          type="button"
          aria-expanded={manual}
          aria-controls="agent-setup-manual"
          onClick={() => setManual((v) => !v)}
          className="-mx-1 inline-flex h-7 items-center gap-1 rounded-md px-1 text-muted-foreground transition-colors hover:text-foreground"
        >
          Set up by hand
          <ChevronDownIcon className={cn("size-3.5 transition-transform duration-150", manual && "rotate-180")} aria-hidden />
        </button>
        <Link href="/docs#agents" {...clickEvent({ name: "docs_cta_clicked", props: { location: "agent_setup" } })} className="-mx-1 inline-flex h-7 items-center gap-1 rounded-md px-1 text-muted-foreground transition-colors hover:text-foreground">
          Agent guide
          <ArrowRightIcon className="size-3.5" aria-hidden />
        </Link>
      </div>
      <div id="agent-setup-manual" hidden={!manual} className="min-w-0 flex-col gap-6 border-t p-4 sm:p-5 [&:not([hidden])]:flex">
        <CopyBlock wrap text={INSTRUCTIONS_LINE} label="Copy the instructions line" event={{ name: "agent_setup_copied", props: { kind: "instructions" } }} caption="Add this line to AGENTS.md, CLAUDE.md or a Cursor rule. Any agent that can fetch a URL can follow it." />
        <div className="flex min-w-0 flex-col gap-3">
          <p className="text-[13px] text-muted-foreground">Optional: connect apm&apos;s MCP server, so the agent gets the verdict as a tool call.</p>
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
          <CopyBlock key={key} text={setup.text} label={`Copy the ${setup.agent} setting`} event={{ name: "mcp_setup_copied", props: { agent: key, source: "home" } }} caption={setup.kind === "command" ? `${setup.where}:` : `In ${setup.where}:`} />
          <p className="text-[13px] leading-5 text-muted-foreground">Start a new agent session afterwards: the server loads when a session starts.</p>
        </div>
      </div>
    </section>
  );
}
