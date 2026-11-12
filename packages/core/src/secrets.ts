// Finds secrets that should never ship in a package tarball. Pure: file list in, findings out.
export type FileLike = { path: string; data: Uint8Array };

export type SecretFinding = { path: string; kind: string; detail: string };

const SAFE_ENV_SUFFIX = /\.(example|sample|template|defaults?|dist)$/i;

const CONTENT_RULES: { kind: string; re: RegExp }[] = [
  { kind: "private key", re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----/ },
  { kind: "AWS access key", re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/ },
  { kind: "npm token", re: /\bnpm_[A-Za-z0-9]{36}\b/ },
  { kind: "GitHub token", re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b/ },
  { kind: "Stripe live key", re: /\b[sr]k_live_[0-9a-zA-Z]{20,}\b/ },
  { kind: "Slack token", re: /\bxox[abprs]-[0-9A-Za-z-]{10,}\b/ },
  { kind: "Google API key", re: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { kind: "OpenAI key", re: /\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b/ },
  { kind: "Anthropic key", re: /\bsk-ant-[A-Za-z0-9_-]{32,}\b/ },
  { kind: "registry auth token", re: /_authToken\s*=\s*[^\s$]{8,}/ },
];

function basename(p: string): string {
  const i = p.lastIndexOf("/");

  return i >= 0 ? p.slice(i + 1) : p;
}

function isText(data: Uint8Array): boolean {
  const n = Math.min(data.length, 4096);

  for (let i = 0; i < n; i++) if (data[i] === 0) return false;

  return true;
}

export function findSecrets(files: readonly FileLike[]): SecretFinding[] {
  const out: SecretFinding[] = [];

  for (const f of files) {
    const base = basename(f.path);

    if ((base === ".env" || base.startsWith(".env.")) && !SAFE_ENV_SUFFIX.test(base)) {
      out.push({ path: f.path, kind: "dotenv file", detail: `${f.path} is an environment file; these usually hold secrets` });
      continue;
    }

    if (/^id_(rsa|dsa|ecdsa|ed25519)$/.test(base)) {
      out.push({ path: f.path, kind: "SSH private key", detail: `${f.path} looks like an SSH private key` });
      continue;
    }

    if (f.data.length > 2_000_000 || !isText(f.data)) continue;
    const text = new TextDecoder().decode(f.data);

    for (const rule of CONTENT_RULES) {
      if (rule.re.test(text)) {
        out.push({ path: f.path, kind: rule.kind, detail: `${f.path} contains what looks like a ${rule.kind}` });
        break;
      }
    }
  }

  return out;
}
