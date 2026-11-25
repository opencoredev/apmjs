"use client";

import Link from "next/link";
import { useEffect, useRef, useState } from "react";
import { ArrowRightIcon, BotIcon, ChevronRightIcon } from "lucide-react";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { CopyBlock, CopyGlyph, CopyStatus, useCopy } from "@/components/copy-button";
import { INSTALL_CLIENTS, InstallClient, installCommand, installNote, type InstallNote } from "@/lib/install-note";
import { packagePrompt } from "@/lib/agent-prompt";
import { clickEvent, copyEvent, installDefaultClient, track, type TrackedEvent } from "@/lib/databuddy-client";

const isClient = (v: unknown): v is InstallClient => InstallClient.safeParse(v).success;

/** Databuddy's client id, inlined at build time; "" on every build but production's, which reads no flags. */
const DATABUDDY_CLIENT_ID = process.env.NEXT_PUBLIC_DATABUDDY_CLIENT_ID?.trim() ?? "";

/** The flag is asked once per document; every install box after the first reuses the answer. */
let startingClient: Promise<InstallClient> | null = null;

function DocsLink({ href }: { href: string }) {
  return (
    <Link
      href={href}
      {...clickEvent({ name: "docs_cta_clicked", props: { location: "install_note" } })}
      className="inline-flex items-center gap-1 font-medium whitespace-nowrap text-foreground underline-offset-4 hover:underline"
    >
      Setup guide
      <ArrowRightIcon className="size-3.5" aria-hidden />
    </Link>
  );
}

/** Note text with each command-line flag (--strict) set in mono, so the sans face can't join its dashes into a dash. */
function WithFlags({ text }: { text: string }) {
  return text.split(/(--[a-z][a-z-]*)/).map((part, i) =>
    i % 2 === 1 ? (
      <code key={i} className="font-mono text-[13px] whitespace-nowrap text-foreground">
        {part}
      </code>
    ) : (
      part
    ),
  );
}

/** What the selected client's command does and does not check, with the setting a stock client needs. */
function Note({ note, client }: { note: InstallNote; client: InstallClient }) {
  if (note.kind === "checked") {
    return (
      <div className="flex flex-col gap-1 text-sm leading-6 text-pretty text-muted-foreground">
        <p>
          {note.text} <DocsLink href={note.docs} />
        </p>
        <details className="group">
          <summary className="inline-flex cursor-pointer list-none items-center gap-1 text-[13px] transition-colors hover:text-foreground [&::-webkit-details-marker]:hidden">
            <ChevronRightIcon className="size-3.5 transition-transform duration-150 group-open:rotate-90" aria-hidden />
            What it refuses and warns about
          </summary>
          <p className="mt-1">
            <WithFlags text={note.detail} />
          </p>
        </details>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-3 text-sm leading-6 text-pretty text-muted-foreground">
      <p>{note.lead}</p>
      <CopyBlock oneLine={!note.config.includes("\n")} text={note.config} label={`Copy the ${note.file} setting`} event={{ name: "registry_setup_copied", props: { client } }} />
      <p>
        <WithFlags text={note.effect} /> <DocsLink href={note.docs} />
      </p>
    </div>
  );
}

/** A list line's marker (its indent and "1." or "-", or an indent alone) and its text, so wrapped text hangs under the text. */
const LIST_LINE = /^(\s*(?:\d+\.|-)\s|\s+)(.*)$/;

/** The prompt as it is copied, with each list item's wrapped lines indented under its text. */
function PromptView({ prompt }: { prompt: string }) {
  return (
    <div className="font-mono text-[12.5px] leading-5 text-muted-foreground">
      {prompt.split("\n").map((line, i) => {
        const m = LIST_LINE.exec(line);

        if (line === "") return <div key={i} className="h-3" aria-hidden />;

        if (!m) return <p key={i} className="whitespace-pre-wrap [overflow-wrap:anywhere]">{line}</p>;

        return (
          <p key={i} className="grid grid-cols-[auto_minmax(0,1fr)]">
            <span className="whitespace-pre">{m[1]}</span>
            <span className="whitespace-pre-wrap [overflow-wrap:anywhere]">{m[2]}</span>
          </p>
        );
      })}
    </div>
  );
}

/** One click copies a prompt that has a coding agent add the package only after apm's verdict. */
function AgentPrompt({ name }: { name: string }) {
  const prompt = packagePrompt({ name });
  const { state, copy } = useCopy();
  const detailsRef = useRef<HTMLDetailsElement>(null);
  const preRef = useRef<HTMLDivElement>(null);

  return (
    <div className="flex flex-col gap-2 border-t pt-4">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
        <Button
          variant="secondary"
          onClick={() =>
            copy(
              prompt,
              () => {
                if (detailsRef.current) detailsRef.current.open = true;

                if (preRef.current) window.getSelection()?.selectAllChildren(preRef.current);
              },
              () => track({ name: "agent_prompt_copied", props: { package: name } }),
            )
          }
        >
          {state === "copied" ? <CopyGlyph copied /> : <BotIcon aria-hidden />}
          {state === "copied" ? "Prompt copied" : "Copy prompt for your agent"}
        </Button>
        <span className="text-[13px] leading-5 text-muted-foreground">Paste it into Claude Code, Codex or Cursor. Your agent checks {name} with apm before adding it.</span>
      </div>
      <CopyStatus state={state} manual="Couldn't copy automatically. The prompt is selected below: press Ctrl+C or ⌘C." />
      <details ref={detailsRef} className="group">
        <summary className="inline-flex cursor-pointer list-none items-center gap-1 text-[13px] text-muted-foreground transition-colors hover:text-foreground [&::-webkit-details-marker]:hidden">
          <ChevronRightIcon className="size-3.5 transition-transform duration-150 group-open:rotate-90" aria-hidden />
          Read the prompt
        </summary>
        <div className="relative mt-2 overflow-hidden rounded-xl ring-1 ring-border">
          <div ref={preRef} className="max-h-80 overflow-auto pt-3 pr-12 pb-8 pl-4">
            <PromptView prompt={prompt} />
          </div>
          <div aria-hidden className="pointer-events-none absolute inset-x-0 bottom-0 h-10 bg-linear-to-t from-background to-transparent" />
          <button
            type="button"
            aria-label={state === "copied" ? "Copied" : "Copy the prompt"}
            className="absolute top-1.5 right-1.5 grid size-9 place-items-center rounded-lg bg-background text-muted-foreground transition-[background-color,color,scale] duration-150 hover:bg-surface hover:text-foreground active:scale-[0.96]"
            onClick={() =>
              copy(
                prompt,
                () => {
                  if (preRef.current) window.getSelection()?.selectAllChildren(preRef.current);
                },
                () => track({ name: "agent_prompt_copied", props: { package: name } }),
              )
            }
          >
            <CopyGlyph copied={state === "copied"} />
          </button>
        </div>
      </details>
    </div>
  );
}

export function InstallTabs({ name, version, registry }: { name: string; version: string | null; registry: string }) {
  const [client, setClient] = useState<InstallClient>("apm");
  const chosen = useRef(false);
  const { state, copy } = useCopy();

  // The install-default-client flag may start the box on another client; a tab the visitor already pressed wins.
  useEffect(() => {
    let live = true;

    startingClient ??= installDefaultClient({ clientId: DATABUDDY_CLIENT_ID, fallback: "apm" });
    void startingClient.then((c) => {
      if (live && !chosen.current) setClient(c);
    });

    return () => {
      live = false;
    };
  }, []);
  const codeRef = useRef<HTMLElement>(null);
  const command = installCommand({ client, name, version });
  const copied = { name: "install_command_copied", props: { client, package: name } } as const satisfies TrackedEvent;

  return (
    <section data-install aria-labelledby="install" className="flex flex-col gap-3">
      <div className="flex items-center justify-between gap-3">
        <h2 id="install" className="scroll-mt-24 text-xl font-medium tracking-tight">
          Install
        </h2>
        <Tabs
          value={client}
          onValueChange={(v) => {
            if (!isClient(v)) return;
            chosen.current = true;
            setClient(v);
          }}
        >
          <TabsList
            onPointerDown={() => {
              chosen.current = true;
            }}
            onKeyDown={() => {
              chosen.current = true;
            }}
            className="h-8 gap-0.5 rounded-lg bg-surface p-0.5">
            {INSTALL_CLIENTS.map((c) => (
              <TabsTrigger key={c} value={c} className="h-7 rounded-md px-2.5 font-mono text-xs data-active:bg-background data-active:shadow-xs dark:data-active:bg-input">
                {c}
              </TabsTrigger>
            ))}
          </TabsList>
        </Tabs>
      </div>
      <div className="flex items-center gap-2 rounded-xl bg-surface py-1.5 pr-1.5 pl-3 sm:pl-4">
        <code ref={codeRef} {...copyEvent(copied)} className="min-w-0 flex-1 truncate font-mono text-[15px]">
          <span className="text-faint select-none">$ </span>
          {command}
        </code>
        <button
          type="button"
          aria-label={state === "copied" ? "Copied" : "Copy install command"}
          className="grid size-9 shrink-0 place-items-center rounded-lg text-muted-foreground transition-[background-color,color,scale] duration-150 hover:bg-background hover:text-foreground active:scale-[0.96]"
          onClick={() =>
            copy(
              command,
              () => {
                if (codeRef.current) window.getSelection()?.selectAllChildren(codeRef.current);
              },
              () => track(copied),
            )
          }
        >
          <CopyGlyph copied={state === "copied"} />
        </button>
      </div>
      <CopyStatus state={state} manual="Couldn't copy automatically. The command is selected: press Ctrl+C or ⌘C." />
      <Note note={installNote({ client, registry })} client={client} />
      <AgentPrompt name={name} />
    </section>
  );
}
