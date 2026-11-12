// The Capabilities section of a version page: what the code can do, each with the lines that show it and how it
// compares with the package's declaration. Separate from the score: none of it costs points on its own.
import { citeEvidence } from "@/lib/evidence";
import { basisNote, capabilitiesIntro, capabilityParts, envNames, statusMark, type StatusMark } from "@/lib/capabilities";
import { splitPossible, splitTestFile } from "@/lib/limitations";
import { fileHref } from "@/lib/package-route";
import type { Capability, Declaration } from "@/lib/registry";

/** The code signal each capability's evidence came from, so a citation links the way the score's evidence does. */
const CITED_AS: Record<Capability["id"], string> = { network: "network", env: "network", filesystem: "network", shell: "shell-exec", eval: "eval", native: "binary", install: "install-script" };

const MARK_TONE: Record<StatusMark["tone"], string> = { ok: "bg-ok-soft text-ok", warn: "bg-warn-soft text-warn", muted: "bg-surface text-muted-foreground" };

/** How many evidence lines each capability shows. */
const SHOWN = 3;

function CapabilityEvidence({ capability, evidence, name, version }: { capability: Capability["id"]; evidence: string; name: string; version: string | null }) {
  const { text, testFile } = splitTestFile(splitPossible(evidence).text);
  const cited = version ? citeEvidence(CITED_AS[capability], text) : null;
  const href = cited && version ? fileHref({ name, version, ...cited.citation }) : null;
  const row = "border-l-2 pl-3 font-mono text-[12.5px] leading-5 text-muted-foreground [overflow-wrap:anywhere]";
  const note = testFile ? <span className="block font-sans text-[13px]">From a test file the package ships.</span> : null;

  if (!cited || !href) {
    return (
      <li className={row}>
        {text}
        {note}
      </li>
    );
  }

  return (
    <li>
      {/* a full page load: the file view reads the #L anchor when it starts */}
      <a href={href} className={`group -mr-2 block rounded-r-md py-0.5 pr-2 transition-colors hover:border-foreground/40 hover:bg-surface/60 ${row}`}>
        <span className="text-foreground underline decoration-foreground/30 underline-offset-[3px] group-hover:decoration-foreground">{cited.cite}</span>
        {cited.rest}
        {note}
      </a>
    </li>
  );
}

function Names({ label, names, tone }: { label: string; names: readonly string[]; tone?: "warn" }) {
  if (names.length === 0) return null;
  const shown = names.slice(0, 12);

  return (
    <p className="text-sm leading-6 text-pretty text-muted-foreground">
      <span className={tone === "warn" ? "text-warn" : undefined}>{label}</span>{" "}
      <span className="font-mono text-[12.5px] text-foreground [overflow-wrap:anywhere]">{shown.join(", ")}</span>
      {names.length > shown.length && <span className="tabular-nums"> and {names.length - shown.length} more</span>}
    </p>
  );
}

function CapabilityRow({ c, name, version }: { c: Capability; name: string; version: string | null }) {
  const { name: title, detail } = capabilityParts(c.label);
  const mark = statusMark(c);
  const basis = basisNote(c);

  return (
    <li className="flex flex-col gap-2 px-4 py-4 sm:px-5">
      <div className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
        <span className="text-[15px] font-medium">{title}</span>
        {detail && <span className="text-[15px] text-muted-foreground">{detail}</span>}
        {(mark || basis) && (
          <span className="flex flex-wrap gap-1.5 sm:ml-auto">
            {mark && <span className={`inline-flex h-6 items-center rounded-full px-2.5 text-[13px] font-medium ${MARK_TONE[mark.tone]}`}>{mark.text}</span>}
            {basis && <span className="inline-flex h-6 items-center rounded-full border px-2.5 text-[13px] text-muted-foreground">{basis}</span>}
          </span>
        )}
      </div>
      {c.declared && c.declared !== "declared" && (
        <p className="text-sm leading-6 text-pretty text-muted-foreground">
          Declared as <span className="text-foreground">{c.declared}</span>
        </p>
      )}
      {c.id === "env" && <Names label="Reads" names={envNames(c.names)} />}
      {c.outside && <Names label="Not covered by the declaration:" names={c.outside} tone="warn" />}
      {c.evidence.length > 0 && (
        <ul className="flex flex-col gap-1.5">
          {c.evidence.slice(0, SHOWN).map((ev) => (
            <CapabilityEvidence key={ev} capability={c.id} evidence={ev} name={name} version={version} />
          ))}
        </ul>
      )}
    </li>
  );
}

/** Every capability of one version, or a line saying there are none. */
export function CapabilityList({ capabilities, declaration, name, version }: { capabilities: readonly Capability[]; declaration: Declaration | null | undefined; name: string; version: string | null }) {
  return (
    <div className="flex flex-col gap-4">
      <p className="text-[15px] leading-6 text-pretty text-muted-foreground">
        {capabilitiesIntro(declaration)}{" "}
        <a href="/docs#capabilities" className="text-foreground underline underline-offset-4">
          How to declare capabilities
        </a>
      </p>
      {declaration?.notes.map((n) => (
        <p key={n} className="rounded-xl bg-warn-soft px-4 py-3 text-sm leading-6 text-pretty">
          {n}
        </p>
      ))}
      {capabilities.length === 0 ? (
        <p className="rounded-xl bg-surface px-5 py-4 text-[15px] text-muted-foreground">No network, environment, filesystem, process, dynamic code, native code or install-script use found.</p>
      ) : (
        <ul className="divide-y rounded-xl border">
          {capabilities.map((c) => (
            <CapabilityRow key={c.id} c={c} name={name} version={version} />
          ))}
        </ul>
      )}
    </div>
  );
}
