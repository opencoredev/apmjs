// Runs Oxlint with oxlint.config.ts and compares the findings with lint-baseline.json.
//
//   bun run lint            fail on findings above the baseline, or on baseline entries
//                           that no longer occur (so fixed findings leave the list)
//   bun run lint:baseline   rewrite lint-baseline.json from the current findings
//
// The baseline counts findings per file and rule, like ESLint's bulk suppressions, so a new
// finding in a baselined file still fails. See docs/LINT.md.
import { z } from "zod";

const BASELINE_PATH = "lint-baseline.json";

const OxlintReport = z.object({
  diagnostics: z.array(
    z.object({
      code: z.string(),
      message: z.string(),
      filename: z.string(),
      labels: z.array(z.object({ span: z.object({ line: z.number(), column: z.number() }) })),
    }),
  ),
});

type Diagnostic = z.infer<typeof OxlintReport>["diagnostics"][number];

// file -> rule -> count
const Baseline = z.object({
  files: z.record(z.string(), z.record(z.string(), z.number().int().positive())),
});

type Baseline = z.infer<typeof Baseline>;

type Finding = { readonly file: string; readonly rule: string; readonly where: string; readonly message: string };

// Oxlint prints codes as "plugin(rule)"; the config and disable comments use "plugin/rule".
function ruleName(code: string): string {
  const match = /^([^(]+)\((.+)\)$/.exec(code);

  return match ? `${match[1]}/${match[2]}` : code;
}

function toFinding(diagnostic: Diagnostic): Finding {
  const span = diagnostic.labels[0]?.span;
  const where = span ? `${diagnostic.filename}:${span.line}:${span.column}` : diagnostic.filename;

  return { file: diagnostic.filename, rule: ruleName(diagnostic.code), where, message: diagnostic.message };
}

async function runOxlint(): Promise<Finding[]> {
  const proc = Bun.spawn(["node_modules/.bin/oxlint", "-c", "oxlint.config.ts", "-f", "json"], {
    stdout: "pipe",
    stderr: "pipe",
  });

  const [stdout, stderr] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text()]);

  await proc.exited;

  // A config that fails to load (for example a Node.js without TypeScript support) makes
  // oxlint print plain text instead of a report, so show its output rather than a parse error.
  try {
    return OxlintReport.parse(JSON.parse(stdout)).diagnostics.map(toFinding);
  } catch (cause) {
    console.error(`${stdout}${stderr}`);
    throw new Error("oxlint did not produce a JSON report; see its output above", { cause });
  }
}

function countFindings(findings: readonly Finding[]): Baseline {
  const files: Baseline["files"] = {};

  for (const finding of findings) {
    const rules = (files[finding.file] ??= {});

    rules[finding.rule] = (rules[finding.rule] ?? 0) + 1;
  }

  const sorted: Baseline["files"] = {};

  for (const file of Object.keys(files).sort()) {
    const rules = files[file] ?? {};

    sorted[file] = Object.fromEntries(Object.keys(rules).sort().map((rule) => [rule, rules[rule] ?? 0]));
  }

  return { files: sorted };
}

async function readBaseline(): Promise<Baseline> {
  const file = Bun.file(BASELINE_PATH);

  if (!(await file.exists())) return { files: {} };

  return Baseline.parse(await file.json());
}

function areaOf(file: string): string {
  const [top, name] = file.split("/");

  return (top === "packages" || top === "apps") && name ? `${top}/${name}` : (top ?? file);
}

function summarize(baseline: Baseline): string {
  const byArea = new Map<string, number>();

  for (const [file, rules] of Object.entries(baseline.files)) {
    const total = Object.values(rules).reduce((sum, count) => sum + count, 0);

    byArea.set(areaOf(file), (byArea.get(areaOf(file)) ?? 0) + total);
  }

  return [...byArea.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([area, count]) => `  ${area}: ${count}`)
    .join("\n");
}

const findings = await runOxlint();
const current = countFindings(findings);

if (process.argv.includes("--update")) {
  await Bun.write(BASELINE_PATH, `${JSON.stringify(current, null, 2)}\n`);
  console.log(`Wrote ${BASELINE_PATH} with ${findings.length} findings:\n${summarize(current)}`);
  process.exit(0);
}

const baseline = await readBaseline();
const failures: string[] = [];
const stale: string[] = [];

for (const [file, rules] of Object.entries(current.files)) {
  for (const [rule, count] of Object.entries(rules)) {
    const allowed = baseline.files[file]?.[rule] ?? 0;

    if (count <= allowed) continue;

    failures.push(`${file}  ${rule}: ${count} found, ${allowed} baselined`);

    for (const finding of findings) {
      if (finding.file === file && finding.rule === rule) failures.push(`  ${finding.where}  ${finding.message}`);
    }
  }
}

for (const [file, rules] of Object.entries(baseline.files)) {
  for (const [rule, allowed] of Object.entries(rules)) {
    const count = current.files[file]?.[rule] ?? 0;

    if (count < allowed) stale.push(`  ${file}  ${rule}: ${count} found, ${allowed} baselined`);
  }
}

if (failures.length > 0) {
  console.error(`New lint findings (fix them; see docs/LINT.md for exceptions):\n\n${failures.join("\n")}`);
}

if (stale.length > 0) {
  console.error(
    `\nThese baseline entries were fixed. Run \`bun run lint:baseline\` and commit lint-baseline.json:\n${stale.join("\n")}`,
  );
}

if (failures.length > 0 || stale.length > 0) process.exit(1);

console.log(`Lint passed. ${findings.length} findings, all in the baseline:\n${summarize(baseline)}`);
