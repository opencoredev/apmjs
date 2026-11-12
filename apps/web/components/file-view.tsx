// One file of one published version, opened from an evidence citation. Package code is untrusted: it is
// rendered as text children only (React escapes it), never as HTML, and hidden characters are shown as markers.
import Link from "next/link";
import { notFound } from "next/navigation";
import { ArrowLeftIcon } from "lucide-react";
import { cn } from "cn";
import { z } from "zod";
import { scriptLine } from "@/lib/evidence";
import { chunkLines, displayLines } from "@/lib/file-lines";
import { formatSize } from "@/lib/format";
import { packagePath, scoreHref } from "@/lib/package-route";
import { openingWindow } from "@/lib/file-excerpt";
import { getExcerpt, getFile, type FileAnswer } from "@/lib/registry";
import { ExcerptView } from "./file-excerpt";
import { RegistryUnavailable } from "./registry-unavailable";
import { LineFocus, type LineAnchor } from "./line-focus";

type Target = { name: string; version: string; path: string };

const Scripts = z.object({ scripts: z.record(z.string(), z.unknown()) });

/** package.json anchors (#scripts.postinstall) and the line each one opens at. */
function scriptAnchors(path: string, text: string): LineAnchor[] {
  if (path !== "package.json") return [];
  let parsed: unknown;

  try {
    parsed = JSON.parse(text);
  } catch {
    return [];
  }

  const manifest = Scripts.safeParse(parsed);
  const out: LineAnchor[] = [];

  for (const key of manifest.success ? Object.keys(manifest.data.scripts) : []) {
    const line = scriptLine(text, `scripts.${key}`);

    if (line !== null) out.push({ anchor: `scripts.${key}`, line });
  }

  return out;
}

function FileText({ file }: { file: Extract<FileAnswer, { kind: "text" }> }) {
  const lines = displayLines(file.text);
  const chunks = chunkLines(lines);
  const digits = String(lines.length).length;

  return (
    <div className="overflow-hidden rounded-2xl bg-inverse text-inverse-foreground">
      <div className="flex items-center justify-between gap-4 border-b border-inverse-border px-4 py-2.5 text-[13px] text-inverse-muted sm:px-5">
        <span className="min-w-0 truncate font-mono">{file.path}</span>
        <span className="shrink-0 tabular-nums">
          {lines.length.toLocaleString("en")} {lines.length === 1 ? "line" : "lines"}
        </span>
      </div>
      {/* A keyboard user can scroll the code sideways once it has focus. */}
      <div role="region" aria-label={`Contents of ${file.path}`} tabIndex={0} className="overflow-x-auto outline-none focus-visible:ring-2 focus-visible:ring-inverse-muted focus-visible:ring-inset">
        <div className="relative w-max min-w-full py-3 font-mono text-[12.5px] leading-5">
          <LineFocus last={lines.length} anchors={scriptAnchors(file.path, file.text)} />
          {chunks.map((c, i) => (
            // every block but the last skips layout and paint while off screen; its height is exact (rows x 20px)
            <div key={c.start} data-start={c.start} className={cn("flex", i < chunks.length - 1 && "file-chunk")}>
              <pre data-gutter aria-hidden className="sticky left-0 z-[1] shrink-0 cursor-pointer bg-inverse pr-4 pl-4 text-right text-inverse-muted select-none sm:pl-5" style={{ width: `calc(${digits}ch + 2.25rem)` }}>
                {c.numbers}
              </pre>
              <pre className="pr-6">
                <code>{c.text}</code>
              </pre>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function Notice({ children }: { children: React.ReactNode }) {
  return <p className="rounded-xl bg-surface px-5 py-4 text-[15px] leading-6 text-pretty text-muted-foreground">{children}</p>;
}

const binaryNotice = (size: number) => <Notice>This is a binary file ({formatSize(size)}). The file view shows text files only.</Notice>;

/**
 * A file over the whole-file limit: the lines around the cited one (or the top, when no line is named), with
 * controls that load more. A line past the end says so and shows the top instead.
 */
async function LargeFile({ file, line }: { file: Extract<FileAnswer, { kind: "too-large" }>; line: number | null }) {
  const target = { name: file.name, version: file.version, path: file.path };
  let got = await getExcerpt({ ...target, ...openingWindow(line) });
  const pastEnd = line !== null && got.kind === "unavailable" && got.reason.kind === "status" && got.reason.status === 416;

  if (pastEnd) got = await getExcerpt({ ...target, ...openingWindow(null) });
  const why = `This file is ${formatSize(file.size)}, over the ${formatSize(file.limit)} the full view shows, so apm shows ${line !== null && !pastEnd ? "the lines around the cited one" : "it in parts"}. Lines longer than 4 kB are cut.`;

  if (got.kind !== "ok") return <Notice>This file is {formatSize(file.size)} and its lines couldn&apos;t be read just now. Reload to try again.</Notice>;

  if (got.value.kind === "binary") return binaryNotice(file.size);

  return (
    <>
      {pastEnd && <Notice>This file has {got.value.totalLines.toLocaleString("en")} lines, so it has no line {line?.toLocaleString("en")}. It is shown from the top.</Notice>}
      <ExcerptView excerpt={got.value} cited={pastEnd ? null : line} />
      <p className="-mt-3 text-sm leading-6 text-pretty text-muted-foreground">{why}</p>
    </>
  );
}

function Body({ file, line }: { file: FileAnswer; line: number | null }) {
  switch (file.kind) {
    case "text":
      return <FileText file={file} />;
    case "binary":
      return binaryNotice(file.size);
    case "too-large":
      return <LargeFile file={file} line={line} />;
    default: {
      const _exhaustive: never = file;

      return _exhaustive;
    }
  }
}

/** One file of one version. `line` is the cited line from ?line=; only a file too large to show whole needs it. */
export async function FileView({ name, version, path, line }: Target & { line: number | null }) {
  const got = await getFile({ name, version, path });

  if (got.kind === "missing") notFound();

  if (got.kind === "unavailable") {
    const status = got.reason.kind === "status" ? got.reason.status : null;

    if (status === 410 || status === 422) {
      return (
        <FileShell name={name} version={version} path={path} meta={null}>
          <Notice>{status === 410 ? "This version was revoked, so apm doesn't show its files." : "apm can't show this file: its path appears more than once in the tarball, or the tarball can't be read."}</Notice>
        </FileShell>
      );
    }

    return <RegistryUnavailable what={`${path} from ${name}@${version}`} retryHref={`${packagePath(name)}/v/${encodeURIComponent(version)}/file/${path.split("/").map(encodeURIComponent).join("/")}`} />;
  }

  return (
    <FileShell name={name} version={version} path={path} meta={formatSize(got.value.size)}>
      <Body file={got.value} line={line} />
      <p className="text-sm leading-6 text-pretty text-muted-foreground">Shown as plain text from the published tarball, after apm checked it against the version&apos;s checksum. Nothing in it runs on this page.</p>
    </FileShell>
  );
}

/** A path that may wrap after each "/" rather than in the middle of a name. */
function PathBreaks({ path }: { path: string }) {
  const parts = path.split("/");

  return parts.map((p, i) => (
    // segments are positional and may repeat, so the index is the key
    <span key={i}>
      {p}
      {i < parts.length - 1 && (
        <>
          /<wbr />
        </>
      )}
    </span>
  ));
}

function FileShell({ name, version, path, meta, children }: Target & { meta: string | null; children: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-6">
      {/* A full page load, so the package page opens at its score. */}
      <a href={scoreHref(name, version)} className="-my-1 inline-flex w-fit items-center gap-1.5 py-1 text-sm text-muted-foreground transition-colors hover:text-foreground">
        <ArrowLeftIcon className="size-4" aria-hidden />
        Back to the score
      </a>
      <header className="flex flex-col gap-2.5">
        <h1 className="font-mono text-xl leading-snug font-medium tracking-tight [overflow-wrap:anywhere] sm:text-2xl">
          <PathBreaks path={path} />
        </h1>
        <p className="flex flex-wrap items-center gap-x-2 gap-y-1 text-sm text-muted-foreground">
          <Link href={packagePath(name)} prefetch={false} className="font-mono text-foreground underline-offset-4 hover:underline">
            {name}
          </Link>
          <span className="inline-flex h-6 items-center rounded-full bg-surface px-2.5 font-mono text-[13px]">{version}</span>
          {meta && (
            <>
              <span aria-hidden>·</span>
              <span className="tabular-nums">{meta}</span>
            </>
          )}
        </p>
      </header>
      {children}
    </div>
  );
}
