// SQLite storage for the registry. Rows are parsed into domain types here, at the storage boundary.
import { Database } from "bun:sqlite";
import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { z } from "zod";

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  name TEXT PRIMARY KEY,
  password_hash TEXT NOT NULL,
  email TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS tokens (
  token_hash TEXT PRIMARY KEY,
  user TEXT NOT NULL REFERENCES users(name),
  label TEXT NOT NULL,
  scope TEXT NOT NULL DEFAULT 'publish',
  created_at INTEGER NOT NULL,
  expires_at INTEGER,
  revoked_at INTEGER
);
CREATE TABLE IF NOT EXISTS packages (
  name TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL,
  modified_at INTEGER NOT NULL,
  dist_tags TEXT NOT NULL DEFAULT '{}',
  description TEXT NOT NULL DEFAULT '',
  keywords TEXT NOT NULL DEFAULT '[]',
  readme TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS owners (
  package TEXT NOT NULL REFERENCES packages(name),
  user TEXT NOT NULL REFERENCES users(name),
  PRIMARY KEY (package, user)
);
CREATE TABLE IF NOT EXISTS versions (
  package TEXT NOT NULL REFERENCES packages(name),
  version TEXT NOT NULL,
  manifest TEXT NOT NULL,
  shasum TEXT NOT NULL,
  integrity TEXT NOT NULL,
  size INTEGER NOT NULL,
  published_at INTEGER NOT NULL,
  published_by TEXT NOT NULL,
  deprecated TEXT,
  status TEXT NOT NULL DEFAULT 'active',
  status_reason TEXT,
  status_at INTEGER,
  status_by TEXT,
  score TEXT,
  PRIMARY KEY (package, version)
);
CREATE TABLE IF NOT EXISTS advisories (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  package TEXT NOT NULL,
  versions TEXT NOT NULL,
  severity TEXT NOT NULL,
  title TEXT NOT NULL,
  detail TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  created_by TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  package TEXT NOT NULL,
  kind TEXT NOT NULL,
  actor TEXT NOT NULL,
  at INTEGER NOT NULL,
  detail TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS events_pkg ON events(package, at);
CREATE TABLE IF NOT EXISTS upstream_analysis (
  package TEXT NOT NULL,
  version TEXT NOT NULL,
  analysis TEXT NOT NULL,
  PRIMARY KEY (package, version)
);
`;

export type VersionStatus = "active" | "yanked" | "revoke-pending" | "revoked";

const UserRow = z.object({ name: z.string(), password_hash: z.string(), email: z.string(), created_at: z.number() });
const TokenRow = z.object({
  token_hash: z.string(),
  user: z.string(),
  label: z.string(),
  scope: z.string(),
  created_at: z.number(),
  expires_at: z.number().nullable(),
  revoked_at: z.number().nullable(),
});
const PackageRow = z.object({
  name: z.string(),
  created_at: z.number(),
  modified_at: z.number(),
  dist_tags: z.string(),
  description: z.string(),
  keywords: z.string(),
  readme: z.string(),
});
const VersionRow = z.object({
  package: z.string(),
  version: z.string(),
  manifest: z.string(),
  shasum: z.string(),
  integrity: z.string(),
  size: z.number(),
  published_at: z.number(),
  published_by: z.string(),
  deprecated: z.string().nullable(),
  status: z.enum(["active", "yanked", "revoke-pending", "revoked"]),
  status_reason: z.string().nullable(),
  status_at: z.number().nullable(),
  status_by: z.string().nullable(),
  score: z.string().nullable(),
});
const AdvisoryRow = z.object({
  id: z.number(),
  package: z.string(),
  versions: z.string(),
  severity: z.string(),
  title: z.string(),
  detail: z.string(),
  created_at: z.number(),
  created_by: z.string(),
});
const EventRow = z.object({ id: z.number(), package: z.string(), kind: z.string(), actor: z.string(), at: z.number(), detail: z.string() });

export type User = z.infer<typeof UserRow>;
export type Token = z.infer<typeof TokenRow>;
export type PackageRecord = Omit<z.infer<typeof PackageRow>, "dist_tags" | "keywords"> & {
  distTags: Record<string, string>;
  keywords: string[];
};
export type VersionRecord = Omit<z.infer<typeof VersionRow>, "manifest" | "score"> & {
  manifest: Record<string, unknown>;
  score: unknown;
};
export type Advisory = Omit<z.infer<typeof AdvisoryRow>, "versions"> & { versions: string[] };
export type EventRecord = Omit<z.infer<typeof EventRow>, "detail"> & { detail: unknown };

const StringRecord = z.record(z.string(), z.string());
const JsonObject = z.record(z.string(), z.unknown());
const StringArray = z.array(z.string());

function parseJson(text: string): unknown {
  return JSON.parse(text);
}

export class Store {
  readonly db: Database;
  readonly tarballDir: string;

  constructor(dataDir: string) {
    mkdirSync(dataDir, { recursive: true });
    this.tarballDir = join(dataDir, "tarballs");
    mkdirSync(this.tarballDir, { recursive: true });
    this.db = new Database(join(dataDir, "registry.sqlite"), { create: true });
    this.db.exec("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;");
    this.db.exec(SCHEMA);
  }

  close(): void {
    this.db.close();
  }

  // users
  getUser(name: string): User | null {
    const row = this.db.query("SELECT * FROM users WHERE name = ?").get(name);
    return row ? UserRow.parse(row) : null;
  }
  createUser(u: User): void {
    this.db.query("INSERT INTO users (name, password_hash, email, created_at) VALUES (?, ?, ?, ?)").run(u.name, u.password_hash, u.email, u.created_at);
  }

  // tokens
  insertToken(t: Token): void {
    this.db
      .query("INSERT INTO tokens (token_hash, user, label, scope, created_at, expires_at, revoked_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
      .run(t.token_hash, t.user, t.label, t.scope, t.created_at, t.expires_at, t.revoked_at);
  }
  getToken(hash: string): Token | null {
    const row = this.db.query("SELECT * FROM tokens WHERE token_hash = ?").get(hash);
    return row ? TokenRow.parse(row) : null;
  }
  listTokens(user: string): Token[] {
    return this.db.query("SELECT * FROM tokens WHERE user = ? ORDER BY created_at DESC").all(user).map((r) => TokenRow.parse(r));
  }
  revokeTokensOf(user: string, at: number): number {
    return this.db.query("UPDATE tokens SET revoked_at = ? WHERE user = ? AND revoked_at IS NULL").run(at, user).changes;
  }

  // packages
  getPackage(name: string): PackageRecord | null {
    const row = this.db.query("SELECT * FROM packages WHERE name = ?").get(name);
    if (!row) return null;
    const p = PackageRow.parse(row);
    return { ...p, distTags: StringRecord.parse(parseJson(p.dist_tags)), keywords: StringArray.parse(parseJson(p.keywords)) };
  }
  listPackageNames(): string[] {
    return this.db.query("SELECT name FROM packages ORDER BY name").all().map((r) => z.object({ name: z.string() }).parse(r).name);
  }
  createPackage(name: string, at: number, owner: string): void {
    this.db.query("INSERT INTO packages (name, created_at, modified_at) VALUES (?, ?, ?)").run(name, at, at);
    this.db.query("INSERT INTO owners (package, user) VALUES (?, ?)").run(name, owner);
  }
  updatePackageMeta(name: string, meta: { modifiedAt: number; description?: string; keywords?: string[]; readme?: string }): void {
    const cur = this.getPackage(name);
    if (!cur) return;
    this.db
      .query("UPDATE packages SET modified_at = ?, description = ?, keywords = ?, readme = ? WHERE name = ?")
      .run(meta.modifiedAt, meta.description ?? cur.description, JSON.stringify(meta.keywords ?? cur.keywords), meta.readme ?? cur.readme, name);
  }
  setDistTags(name: string, tags: Record<string, string>, at: number): void {
    this.db.query("UPDATE packages SET dist_tags = ?, modified_at = ? WHERE name = ?").run(JSON.stringify(tags), at, name);
  }
  owners(name: string): string[] {
    return this.db.query("SELECT user FROM owners WHERE package = ? ORDER BY user").all(name).map((r) => z.object({ user: z.string() }).parse(r).user);
  }
  addOwner(name: string, user: string): void {
    this.db.query("INSERT OR IGNORE INTO owners (package, user) VALUES (?, ?)").run(name, user);
  }
  removeOwner(name: string, user: string): void {
    this.db.query("DELETE FROM owners WHERE package = ? AND user = ?").run(name, user);
  }

  // versions
  private toVersion(row: unknown): VersionRecord {
    const v = VersionRow.parse(row);
    return { ...v, manifest: JsonObject.parse(parseJson(v.manifest)), score: v.score ? parseJson(v.score) : null };
  }
  listVersions(name: string): VersionRecord[] {
    return this.db.query("SELECT * FROM versions WHERE package = ? ORDER BY published_at, rowid").all(name).map((r) => this.toVersion(r));
  }
  getVersion(name: string, version: string): VersionRecord | null {
    const row = this.db.query("SELECT * FROM versions WHERE package = ? AND version = ?").get(name, version);
    return row ? this.toVersion(row) : null;
  }
  insertVersion(v: Omit<VersionRecord, "status" | "status_reason" | "status_at" | "status_by" | "deprecated">): void {
    this.db
      .query(
        "INSERT INTO versions (package, version, manifest, shasum, integrity, size, published_at, published_by, score) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
      )
      .run(v.package, v.version, JSON.stringify(v.manifest), v.shasum, v.integrity, v.size, v.published_at, v.published_by, v.score === null ? null : JSON.stringify(v.score));
  }
  setDeprecated(name: string, version: string, message: string | null): void {
    this.db.query("UPDATE versions SET deprecated = ? WHERE package = ? AND version = ?").run(message, name, version);
  }
  setStatus(name: string, version: string, s: { status: VersionStatus; reason: string | null; at: number; by: string }): void {
    this.db
      .query("UPDATE versions SET status = ?, status_reason = ?, status_at = ?, status_by = ? WHERE package = ? AND version = ?")
      .run(s.status, s.reason, s.at, s.by, name, version);
  }
  setScore(name: string, version: string, score: unknown): void {
    this.db.query("UPDATE versions SET score = ? WHERE package = ? AND version = ?").run(JSON.stringify(score), name, version);
  }
  shaExists(shasum: string): VersionRecord | null {
    const row = this.db.query("SELECT * FROM versions WHERE shasum = ? LIMIT 1").get(shasum);
    return row ? this.toVersion(row) : null;
  }

  /** Pending revocations older than `cutoff` become final. Returns the versions that changed. */
  matureRevocations(cutoff: number): { package: string; version: string }[] {
    const rows = this.db
      .query("SELECT package, version FROM versions WHERE status = 'revoke-pending' AND status_at <= ?")
      .all(cutoff)
      .map((r) => z.object({ package: z.string(), version: z.string() }).parse(r));
    if (rows.length > 0) this.db.query("UPDATE versions SET status = 'revoked' WHERE status = 'revoke-pending' AND status_at <= ?").run(cutoff);
    return rows;
  }

  /** Names of local packages whose versions depend on `name`. */
  dependentsOf(name: string): string[] {
    const out = new Set<string>();
    for (const row of this.db.query("SELECT package, manifest FROM versions WHERE status = 'active'").all()) {
      const r = z.object({ package: z.string(), manifest: z.string() }).parse(row);
      if (r.package === name) continue;
      const m = JsonObject.parse(parseJson(r.manifest));
      for (const k of ["dependencies", "optionalDependencies", "peerDependencies"]) {
        const deps = m[k];
        if (typeof deps === "object" && deps !== null && name in deps) out.add(r.package);
      }
    }
    return [...out];
  }

  getUpstreamAnalysis(name: string, version: string): unknown {
    const row = this.db.query("SELECT analysis FROM upstream_analysis WHERE package = ? AND version = ?").get(name, version);
    if (!row) return null;
    return parseJson(z.object({ analysis: z.string() }).parse(row).analysis);
  }
  setUpstreamAnalysis(name: string, version: string, analysis: unknown): void {
    this.db.query("INSERT OR REPLACE INTO upstream_analysis (package, version, analysis) VALUES (?, ?, ?)").run(name, version, JSON.stringify(analysis));
  }

  // advisories
  deleteAdvisoriesFor(name: string, version: string): void {
    for (const a of this.advisoriesFor(name)) {
      if (a.versions.includes(version)) this.db.query("DELETE FROM advisories WHERE id = ?").run(a.id);
    }
  }
  addAdvisory(a: Omit<Advisory, "id">): number {
    const r = this.db
      .query("INSERT INTO advisories (package, versions, severity, title, detail, created_at, created_by) VALUES (?, ?, ?, ?, ?, ?, ?)")
      .run(a.package, JSON.stringify(a.versions), a.severity, a.title, a.detail, a.created_at, a.created_by);
    return Number(r.lastInsertRowid);
  }
  advisoriesFor(name: string): Advisory[] {
    return this.db
      .query("SELECT * FROM advisories WHERE package = ? ORDER BY id")
      .all(name)
      .map((r) => {
        const a = AdvisoryRow.parse(r);
        return { ...a, versions: StringArray.parse(parseJson(a.versions)) };
      });
  }

  // events
  addEvent(e: { package: string; kind: string; actor: string; at: number; detail?: unknown }): void {
    this.db.query("INSERT INTO events (package, kind, actor, at, detail) VALUES (?, ?, ?, ?, ?)").run(e.package, e.kind, e.actor, e.at, JSON.stringify(e.detail ?? {}));
  }
  eventsFor(name: string): EventRecord[] {
    return this.db
      .query("SELECT * FROM events WHERE package = ? ORDER BY at DESC, id DESC")
      .all(name)
      .map((r) => {
        const e = EventRow.parse(r);
        return { ...e, detail: parseJson(e.detail) };
      });
  }

  tx<T>(fn: () => T): T {
    return this.db.transaction(fn)();
  }
}
