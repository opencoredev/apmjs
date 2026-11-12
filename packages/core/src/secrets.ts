// Finds secrets that should never ship in a package tarball. Pure: file list in, findings out.
import { MAX_ANALYZED_FILE_BYTES, type SkippedFile } from "./limits.ts";

export type FileLike = { path: string; data: Uint8Array };

export type SecretFinding = { path: string; kind: string; detail: string };

/** What the scan found, and the files it could not read: a skipped file is unknown, not clean. */
export type SecretScan = { findings: SecretFinding[]; skipped: SkippedFile[] };

const SAFE_ENV_SUFFIX = /\.(example|sample|template|defaults?|dist)$/i;

// Key stores hold private keys in a binary format: the name is the finding, as with id_rsa.
const KEY_STORE = /\.(?:p12|pfx|jks|keystore|kdbx|ppk)$/i;

const CONTENT_RULES: { kind: string; re: RegExp }[] = [
  // PEM ("-----BEGIN RSA PRIVATE KEY-----", "ENCRYPTED", "OPENSSH", "PGP ... BLOCK") and SSH2 ("---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----")
  { kind: "private key", re: /-{4,5} ?BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)? ?-{4,5}/ },
  { kind: "PuTTY private key", re: /PuTTY-User-Key-File-\d+:/ },
  { kind: "AWS access key", re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/ },
  { kind: "npm token", re: /\bnpm_[A-Za-z0-9]{36}\b/ },
  { kind: "GitHub token", re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b/ },
  { kind: "Stripe live key", re: /\b[sr]k_live_[0-9a-zA-Z]{20,}\b/ },
  { kind: "Slack token", re: /\bxox[abprs]-[0-9A-Za-z-]{10,}\b/ },
  { kind: "Google API key", re: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { kind: "OpenAI key", re: /\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b/ },
  { kind: "Anthropic key", re: /\bsk-ant-[A-Za-z0-9_-]{32,}\b/ },
  { kind: "registry auth token", re: /_authToken\s*=\s*[^\s$]{8,}/ },
  // npm's basic auth: "//host/:_auth=base64(user:pass)" or ":_password=base64(pass)"
  { kind: "registry password", re: /\/\/[^\s:]+:_(?:auth|password)\s*=\s*[^\s$]{4,}/ },
  { kind: "Slack webhook", re: /https:\/\/hooks\.slack\.com\/(?:services|workflows|triggers)\/[A-Za-z0-9_/-]{20,}/ },
  { kind: "Discord webhook", re: /https:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]{20,}/ },
];

// In an .npmrc the auth keys need no registry prefix: "_auth=..." on its own line is a default credential.
const NPMRC_RULES: { kind: string; re: RegExp }[] = [{ kind: "registry password", re: /^\s*_(?:auth|password)\s*=\s*[^\s$]{4,}/m }];

// Magic bytes of archives whose contents the scan cannot read.
const ARCHIVES: readonly (readonly number[])[] = [
  [0x1f, 0x8b], // gzip
  [0x50, 0x4b, 0x03, 0x04], // zip, jar
  [0x42, 0x5a, 0x68], // bzip2
  [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00], // xz
  [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c], // 7z
  [0x28, 0xb5, 0x2f, 0xfd], // zstd
];

function isArchive(data: Uint8Array): boolean {
  return ARCHIVES.some((magic) => magic.length <= data.length && magic.every((b, i) => data[i] === b));
}

function basename(p: string): string {
  const i = p.lastIndexOf("/");

  return i >= 0 ? p.slice(i + 1) : p;
}

export function findSecrets(files: readonly FileLike[]): SecretScan {
  const out: SecretFinding[] = [];
  const skipped: SkippedFile[] = [];

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

    if (KEY_STORE.test(base)) {
      out.push({ path: f.path, kind: "key store", detail: `${f.path} is a key store; these hold private keys` });
      continue;
    }

    if (f.data.length > MAX_ANALYZED_FILE_BYTES) {
      skipped.push({ path: f.path, size: f.data.length, reason: "too-large" });
      continue;
    }

    if (isArchive(f.data)) {
      skipped.push({ path: f.path, size: f.data.length, reason: "compressed" });
      continue;
    }

    // every other file is read, NUL bytes and all: latin1 maps each byte to one character, so the ASCII
    // patterns match in text and binary files alike
    const text = Buffer.from(f.data.buffer, f.data.byteOffset, f.data.byteLength).toString("latin1");
    const rules = base === ".npmrc" || base === "npmrc" ? [...NPMRC_RULES, ...CONTENT_RULES] : CONTENT_RULES;

    for (const rule of rules) {
      if (rule.re.test(text)) {
        out.push({ path: f.path, kind: rule.kind, detail: `${f.path} contains what looks like a ${rule.kind}` });
        break;
      }
    }
  }

  return { findings: out, skipped };
}
