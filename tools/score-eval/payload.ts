// Whether a malicious sample carries its payload in its own tarball. A fixed text rule, independent of any scorer, so
// the detection rate on samples with a payload cannot rise because the scorer under test sees more:
// - `self-contained`: a code file or an install hook names a network, process, code-running or credential primitive,
//   or carries obfuscator output or a long encoded blob (the payload is in the tarball, whether apm reads it or not);
// - `none`: nothing like that anywhere: a manifest that only declares dependencies, code that only hands values to a
//   dependency (`require('x').configure({ env: process.env })`), or a name squat with nothing in it.
import { z } from "zod";
import type { SampleFiles } from "../ai-review/samples.ts";

export type PayloadClass = "self-contained" | "none";

/** A manifest's script commands; a script that is not a string, or a `scripts` that is not an object, is none. */
const Scripts = z.record(z.string(), z.string().optional().catch(undefined)).catch({});

const CODE = /\.(?:[cm]?[jt]sx?|sh|bash|ps1|py|cmd|bat|vbs|node)$|(?:^|\/)[^./]+$/i;

const PRIMITIVE =
  /\bfetch\s*\(|\bhttps?\s*\.\s*(?:get|request)\b|\brequire\s*\(\s*['"`](?:node:)?(?:https?|net|tls|dgram|dns|child_process|vm|worker_threads|axios|node-fetch|got|request|ws)['"`]|\bfrom\s+['"`](?:node:)?(?:https?|net|tls|dgram|dns|child_process|vm|worker_threads|axios|node-fetch|got|ws)['"`]|\bXMLHttpRequest\b|\bWebSocket\b|\bsendBeacon\b|\b(?:exec|execSync|spawn|spawnSync|execFile|execFileSync|fork)\s*\(|\beval\s*\(|\bnew\s+Function\b|\bFunction\s*\(|\.npmrc\b|\.ssh\/|id_rsa|\.aws\/credentials|\bLogin Data\b|\bcurl\s|\bwget\s|\bpowershell\b|Invoke-WebRequest|\bprocess\s*\.\s*binding\b/;

const OBFUSCATED = /\b_0x[0-9a-f]{4,}\b|(?:\\x[0-9a-fA-F]{2}){12}|[A-Za-z0-9+/]{400,}={0,2}|\bString\.fromCharCode\s*\(|\batob\s*\(|['"](?:base64|hex)['"]\s*\)/;

export function payloadClass(s: SampleFiles): PayloadClass {
  const hooks = Object.values(Scripts.parse(s.manifest.scripts)).filter((h) => h !== undefined);

  if (hooks.some((h) => PRIMITIVE.test(h))) return "self-contained";

  for (const f of s.files) {
    if (f.path === "package.json" || !CODE.test(f.path) || f.data.length > 8 * 1024 * 1024) continue;
    const text = new TextDecoder().decode(f.data);

    if (PRIMITIVE.test(text) || OBFUSCATED.test(text)) return "self-contained";
  }

  return "none";
}
