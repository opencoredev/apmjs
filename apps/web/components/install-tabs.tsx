"use client";

import Link from "next/link";
import { useRef, useState } from "react";
import { ArrowRightIcon, CopyIcon, CheckIcon } from "lucide-react";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { INSTALL_CLIENTS, InstallClient, installCommand, installNote, type InstallNote } from "@/lib/install-note";

const isClient = (v: unknown): v is InstallClient => InstallClient.safeParse(v).success;

/** Clipboard API needs a secure context (HTTPS); fall back to a hidden textarea on plain HTTP. */
async function copyText(text: string): Promise<boolean> {
  try {
    if (navigator.clipboard) {
      await navigator.clipboard.writeText(text);

      return true;
    }
  } catch {
    // fall through to the textarea route
  }

  const ta = document.createElement("textarea");
  ta.value = text;
  ta.setAttribute("readonly", "");
  ta.style.position = "fixed";
  ta.style.opacity = "0";
  document.body.appendChild(ta);
  ta.select();
  let ok = false;

  try {
    ok = document.execCommand("copy");
  } catch {
    ok = false;
  }

  ta.remove();

  return ok;
}

function DocsLink({ href }: { href: string }) {
  return (
    <Link href={href} className="inline-flex items-center gap-1 font-medium whitespace-nowrap text-foreground underline-offset-4 hover:underline">
      Setup guide
      <ArrowRightIcon className="size-3.5" aria-hidden />
    </Link>
  );
}

/** What the selected client's command does and does not check, with the setting a stock client needs. */
function Note({ note }: { note: InstallNote }) {
  if (note.kind === "checked") {
    return (
      <p className="px-2.5 pt-2.5 pb-1 text-[13px] leading-5 text-pretty text-muted-foreground">
        {note.text} <DocsLink href={note.docs} />
      </p>
    );
  }

  return (
    <div className="flex flex-col gap-2 px-2.5 pt-2.5 pb-1 text-[13px] leading-5 text-pretty text-muted-foreground">
      <p className="text-foreground">{note.lead}</p>
      <figure className="overflow-hidden rounded-lg bg-background ring-1 ring-border">
        <figcaption className="sr-only">{note.file}</figcaption>
        <pre className="px-3 py-2 font-mono text-[12.5px] leading-5 whitespace-pre-wrap text-foreground [overflow-wrap:anywhere]">{note.config}</pre>
      </figure>
      <p>
        {note.checks} <DocsLink href={note.docs} />
      </p>
    </div>
  );
}

export function InstallTabs({ name, version, registry }: { name: string; version: string | null; registry: string }) {
  const [client, setClient] = useState<InstallClient>("apm");
  const [copied, setCopied] = useState<"yes" | "manual" | false>(false);
  const codeRef = useRef<HTMLElement>(null);
  const command = installCommand({ client, name, version });

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
            {INSTALL_CLIENTS.map((c) => (
              <TabsTrigger key={c} value={c} className="h-7 rounded-full px-3 font-mono text-xs data-active:bg-background data-active:shadow-xs">
                {c}
              </TabsTrigger>
            ))}
          </TabsList>
        </Tabs>
      </div>
      <div className="flex items-center gap-2 rounded-lg bg-background py-1.5 pr-1.5 pl-4 ring-1 ring-border">
        <code ref={codeRef} className="min-w-0 flex-1 truncate font-mono text-[15px]">
          <span className="text-faint select-none">$ </span>
          {command}
        </code>
        <button
          type="button"
          aria-label={copied === "yes" ? "Copied" : "Copy install command"}
          className="grid size-9 shrink-0 place-items-center rounded-md text-muted-foreground transition-colors hover:bg-surface hover:text-foreground active:scale-95"
          onClick={() => {
            void copyText(command).then((ok) => {
              setCopied(ok ? "yes" : "manual");

              if (!ok && codeRef.current) window.getSelection()?.selectAllChildren(codeRef.current);
              setTimeout(() => setCopied(false), ok ? 1200 : 3000);
            });
          }}
        >
          {copied === "yes" ? <CheckIcon className="size-4 text-ok" /> : <CopyIcon className="size-4" />}
        </button>
      </div>
      <p role="status" aria-live="polite" className={copied === "manual" ? "px-2.5 pt-2 text-[13px] leading-5 text-warn" : "sr-only"}>
        {copied === "manual" ? "Couldn't copy automatically. The command is selected: press Ctrl+C or ⌘C." : copied === "yes" ? "Copied" : ""}
      </p>
      <Note note={installNote({ client, registry })} />
    </div>
  );
}
