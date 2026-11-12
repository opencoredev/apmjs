// SQLite storage for the registry. Rows are parsed into domain types here, at the storage boundary.
import { Database } from "bun:sqlite";
import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { z } from "zod";
import { dependencySpecs, isRegistryDependency, SCORER } from "@apm/core";

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
CREATE TABLE IF NOT EXISTS staged (
  id TEXT PRIMARY KEY,
  package TEXT NOT NULL,
  version TEXT NOT NULL,
  manifest TEXT NOT NULL,
  shasum TEXT NOT NULL,
  integrity TEXT NOT NULL,
  size INTEGER NOT NULL,
  tag TEXT NOT NULL,
  readme TEXT,
  score TEXT,
  staged_by TEXT NOT NULL,
  staged_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  decided_at INTEGER,
  decided_by TEXT
);
CREATE INDEX IF NOT EXISTS staged_pkg ON staged(package, version);
CREATE TABLE IF NOT EXISTS password_failures (
  user TEXT PRIMARY KEY,
  count INTEGER NOT NULL,
  since INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS github_profiles (
  github_id TEXT PRIMARY KEY,
  login TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS upstream_analysis (
  package TEXT NOT NULL,
  version TEXT NOT NULL,
  analysis TEXT NOT NULL,
  PRIMARY KEY (package, version)
);
CREATE TABLE IF NOT EXISTS upstream_analysis_v2 (
  package TEXT NOT NULL,
  version TEXT NOT NULL,
  digest TEXT NOT NULL,
  scorer TEXT NOT NULL,
  analysis TEXT NOT NULL,
  analyzed_at INTEGER NOT NULL,
  PRIMARY KEY (package, version, digest, scorer)
);
`;

/** Columns added after the first schema; each is added once to an existing database. */
const ADDED_COLUMNS: { table: string; column: string; decl: string }[] = [
  { table: "users", column: "auth_user_id", decl: "TEXT" },
  { table: "users", column: "github_id", decl: "TEXT" },
  { table: "users", column: "github_login", decl: "TEXT" },
];

export type VersionStatus = "active" | "yanked" | "revoke-pending" | "revoked";

const UserRow = z.object({
  name: z.string(),
  password_hash: z.string(),
  email: z.string(),
  created_at: z.number(),
  auth_user_id: z.string().nullable(),
  github_id: z.string().nullable(),
  github_login: z.string().nullable(),
});
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
export type StagedStatus = "pending" | "approved" | "rejected" | "expired";

/** What is waiting for approval: versions and bytes one user staged, and versions waiting for one package. */
export type StagedLoad = { byUser: number; bytesByUser: number; byPackage: number };

/** Most versions waiting per account and per package, and most bytes (tarballs plus metadata) per account. */
export type StageLimits = { perUser: number; perPackage: number; bytesPerUser: number };

/** How an atomic staged insert went: stored, already waiting for this name@version, or over a quota. */
export type StageInsert = { kind: "staged" } | { kind: "duplicate"; id: string } | { kind: "over"; quota: "package" | "user" | "bytes"; load: StagedLoad };

// Bytes a staged row holds: the tarball plus the metadata kept in the database (manifest, readme, score).
const STAGED_BYTES = "size + length(CAST(manifest AS BLOB)) + COALESCE(length(CAST(readme AS BLOB)), 0) + COALESCE(length(CAST(score AS BLOB)), 0)";

/** What a staged upload charges against the byte quota, computed the way the database counts it. */
export function stagedBytes(s: Pick<NewStaged, "size" | "manifest" | "readme" | "score">): number {
  const bytes = (t: string): number => Buffer.byteLength(t, "utf8");

  return s.size + bytes(JSON.stringify(s.manifest)) + (s.readme === null ? 0 : bytes(s.readme)) + (s.score === null ? 0 : bytes(JSON.stringify(s.score)));
}
const StagedRow = z.object({
  id: z.string(),
  package: z.string(),
  version: z.string(),
  manifest: z.string(),
  shasum: z.string(),
  integrity: z.string(),
  size: z.number(),
  tag: z.string(),
  readme: z.string().nullable(),
  score: z.string().nullable(),
  staged_by: z.string(),
  staged_at: z.number(),
  expires_at: z.number(),
  status: z.enum(["pending", "approved", "rejected", "expired"]),
  decided_at: z.number().nullable(),
  decided_by: z.string().nullable(),
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
export type StagedRecord = Omit<z.infer<typeof StagedRow>, "manifest" | "score"> & { manifest: Record<string, unknown>; score: unknown };
export type NewStaged = Omit<StagedRecord, "status" | "decided_at" | "decided_by">;
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
    for (const c of ADDED_COLUMNS) {
      const cols = this.db.query(`PRAGMA table_info(${c.table})`).all().map((r) => z.object({ name: z.string() }).parse(r).name);
      if (!cols.includes(c.column)) this.db.exec(`ALTER TABLE ${c.table} ADD COLUMN ${c.column} ${c.decl}`);
    }
    this.db.exec("CREATE UNIQUE INDEX IF NOT EXISTS users_auth_user ON users(auth_user_id) WHERE auth_user_id IS NOT NULL");
    // Tokens from npm's password login predate sign-in; mark them so they lose direct publish when legacy auth is off.
    this.db.exec("UPDATE tokens SET scope = 'legacy' WHERE scope = 'publish' AND label = 'cli login'");
    // Uploads rejected or expired before payloads were purged on decision: keep only their audit fields.
    this.db.exec("UPDATE staged SET manifest = '{}', readme = NULL, score = NULL WHERE status IN ('rejected', 'expired') AND (manifest != '{}' OR readme IS NOT NULL OR score IS NOT NULL)");
  }

  close(): void {
    this.db.close();
  }

  // users
  getUser(name: string): User | null {
    const row = this.db.query("SELECT * FROM users WHERE name = ?").get(name);
    return row ? UserRow.parse(row) : null;
  }
  getUserByAuthId(authUserId: string): User | null {
    const row = this.db.query("SELECT * FROM users WHERE auth_user_id = ?").get(authUserId);
    return row ? UserRow.parse(row) : null;
  }
  createUser(u: Pick<User, "name" | "password_hash" | "email" | "created_at"> & Partial<Pick<User, "auth_user_id" | "github_id" | "github_login">>): void {
    this.db
      .query("INSERT INTO users (name, password_hash, email, created_at, auth_user_id, github_id, github_login) VALUES (?, ?, ?, ?, ?, ?, ?)")
      .run(u.name, u.password_hash, u.email, u.created_at, u.auth_user_id ?? null, u.github_id ?? null, u.github_login ?? null);
  }
  /** Binds an existing name to a signed-in account and its GitHub identity. */
  bindUser(name: string, link: { authUserId: string; githubId: string; githubLogin: string }): void {
    this.db.query("UPDATE users SET auth_user_id = ?, github_id = ?, github_login = ? WHERE name = ?").run(link.authUserId, link.githubId, link.githubLogin, name);
  }

  /** The GitHub login shown for a name, refreshed after a GitHub rename. The name itself never changes. */
  setGitHubLogin(name: string, login: string): void {
    this.db.query("UPDATE users SET github_login = ? WHERE name = ?").run(login, name);
  }
  // GitHub logins seen at sign-in, by GitHub's numeric id
  setGitHubProfile(githubId: string, login: string, at: number): void {
    this.db.query("INSERT OR REPLACE INTO github_profiles (github_id, login, updated_at) VALUES (?, ?, ?)").run(githubId, login, at);
  }
  gitHubLogin(githubId: string): string | null {
    const row = this.db.query("SELECT login FROM github_profiles WHERE github_id = ?").get(githubId);
    return row ? z.object({ login: z.string() }).parse(row).login : null;
  }

  /** Wrong passwords for `user` in the current window: the count and when the window started. */
  passwordFailures(user: string): { count: number; since: number } | null {
    const row = this.db.query("SELECT count, since FROM password_failures WHERE user = ?").get(user);

    return row ? z.object({ count: z.number(), since: z.number() }).parse(row) : null;
  }
  setPasswordFailures(user: string, f: { count: number; since: number } | null): void {
    if (f === null) this.db.query("DELETE FROM password_failures WHERE user = ?").run(user);
    else this.db.query("INSERT OR REPLACE INTO password_failures (user, count, since) VALUES (?, ?, ?)").run(user, f.count, f.since);
  }

  // staged versions: uploaded with a login token, waiting for a person to approve
  private toStaged(row: unknown): StagedRecord {
    const r = StagedRow.parse(row);
    return { ...r, manifest: JsonObject.parse(parseJson(r.manifest)), score: r.score ? parseJson(r.score) : null };
  }
  /**
   * Stores a staged upload only if nothing else waits for the same name@version and the quotas still allow
   * it, all in one write transaction: two concurrent uploads cannot both pass the checks.
   */
  insertStagedWithin(s: NewStaged, limits: StageLimits): StageInsert {
    return this.db
      .transaction((): StageInsert => {
        const now = s.staged_at;
        const waiting = this.db.query("SELECT id FROM staged WHERE package = ? AND version = ? AND status = 'pending' AND expires_at > ? LIMIT 1").get(s.package, s.version, now);

        if (waiting) return { kind: "duplicate", id: z.object({ id: z.string() }).parse(waiting).id };
        const load = this.pendingStagedLoad({ user: s.staged_by, name: s.package, now });

        if (load.byPackage >= limits.perPackage) return { kind: "over", quota: "package", load };

        if (load.byUser >= limits.perUser) return { kind: "over", quota: "user", load };

        if (load.bytesByUser + stagedBytes(s) > limits.bytesPerUser) return { kind: "over", quota: "bytes", load };
        this.insertStaged(s);

        return { kind: "staged" };
      })
      .immediate();
  }
  insertStaged(s: NewStaged): void {
    this.db
      .query(
        "INSERT INTO staged (id, package, version, manifest, shasum, integrity, size, tag, readme, score, staged_by, staged_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
      )
      .run(s.id, s.package, s.version, JSON.stringify(s.manifest), s.shasum, s.integrity, s.size, s.tag, s.readme, s.score === null ? null : JSON.stringify(s.score), s.staged_by, s.staged_at, s.expires_at);
  }
  getStaged(id: string): StagedRecord | null {
    const row = this.db.query("SELECT * FROM staged WHERE id = ?").get(id);
    return row ? this.toStaged(row) : null;
  }
  pendingStaged(name: string, version: string): StagedRecord | null {
    const row = this.db.query("SELECT * FROM staged WHERE package = ? AND version = ? AND status = 'pending' ORDER BY staged_at DESC LIMIT 1").get(name, version);
    return row ? this.toStaged(row) : null;
  }
  /** Pending versions this user staged or may approve as an owner, newest first. */
  pendingFor(user: string): StagedRecord[] {
    return this.db
      .query(
        "SELECT * FROM staged WHERE status = 'pending' AND (staged_by = ? OR package IN (SELECT package FROM owners WHERE user = ?)) ORDER BY staged_at DESC LIMIT 100",
      )
      .all(user, user)
      .map((r) => this.toStaged(r));
  }
  /** Records a decision. A rejected upload keeps only its audit fields: the manifest, readme and score go. */
  decideStaged(id: string, d: { status: Exclude<StagedStatus, "pending">; at: number; by: string }): void {
    const purge = d.status === "rejected" || d.status === "expired" ? ", manifest = '{}', readme = NULL, score = NULL" : "";

    this.db.query(`UPDATE staged SET status = ?, decided_at = ?, decided_by = ?${purge} WHERE id = ? AND status = 'pending'`).run(d.status, d.at, d.by, id);
  }
  /**
   * Versions still waiting for approval (not expired at `now`): how many and how many bytes `user` staged, and
   * how many wait for `name`. Bytes count the tarball and the metadata the row keeps.
   */
  pendingStagedLoad(input: { user: string; name: string; now: number }): StagedLoad {
    const Load = z.object({ n: z.number(), bytes: z.number().nullable() });
    const mine = Load.parse(this.db.query(`SELECT COUNT(*) AS n, SUM(${STAGED_BYTES}) AS bytes FROM staged WHERE status = 'pending' AND expires_at > ? AND staged_by = ?`).get(input.now, input.user));
    const pkg = Load.parse(this.db.query("SELECT COUNT(*) AS n, NULL AS bytes FROM staged WHERE status = 'pending' AND expires_at > ? AND package = ?").get(input.now, input.name));

    return { byUser: mine.n, bytesByUser: mine.bytes ?? 0, byPackage: pkg.n };
  }
  /** Marks pending versions past their deadline as expired and drops their manifest, readme and score; returns their ids. */
  expireStaged(now: number): string[] {
    const ids = this.db
      .query("SELECT id FROM staged WHERE status = 'pending' AND expires_at <= ?")
      .all(now)
      .map((r) => z.object({ id: z.string() }).parse(r).id);
    if (ids.length > 0) {
      this.db
        .query("UPDATE staged SET status = 'expired', decided_at = ?, decided_by = 'registry', manifest = '{}', readme = NULL, score = NULL WHERE status = 'pending' AND expires_at <= ?")
        .run(now, now);
    }
    return ids;
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
  revokeToken(hash: string, at: number): void {
    this.db.query("UPDATE tokens SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL").run(at, hash);
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
  /** Removes an owner unless that would leave the package with none. Atomic: the count is read in the same transaction. */
  removeOwner(name: string, user: string): "removed" | "not-owner" | "last-owner" {
    return this.tx(() => {
      const owners = this.owners(name);
      if (!owners.includes(user)) return "not-owner";
      if (owners.length <= 1) return "last-owner";
      this.db.query("DELETE FROM owners WHERE package = ? AND user = ?").run(name, user);
      return "removed";
    });
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
  /** Whether any version's tarball is the blob with this integrity. */
  integrityInUse(integrity: string): boolean {
    return this.db.query("SELECT 1 FROM versions WHERE integrity = ? LIMIT 1").get(integrity) !== null;
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
      // npm: aliases count under the package they install, not under their key
      if (dependencySpecs(m).some((d) => isRegistryDependency(d) && d.name === name)) out.add(r.package);
      const peers = m.peerDependencies;
      if (typeof peers === "object" && peers !== null && name in peers) out.add(r.package);
    }
    return [...out];
  }

  /** The current scorer's analysis of exactly these bytes (`digest` names the tarball), or null. */
  getUpstreamAnalysis(name: string, version: string, digest: string): unknown {
    const row = this.db.query("SELECT analysis FROM upstream_analysis_v2 WHERE package = ? AND version = ? AND digest = ? AND scorer = ?").get(name, version, digest, SCORER);
    if (!row) return null;
    return parseJson(z.object({ analysis: z.string() }).parse(row).analysis);
  }
  /** For display where the tarball digest is not known (search hits): the newest current-scorer analysis. */
  latestUpstreamAnalysis(name: string, version: string): unknown {
    const row = this.db.query("SELECT analysis FROM upstream_analysis_v2 WHERE package = ? AND version = ? AND scorer = ? ORDER BY analyzed_at DESC LIMIT 1").get(name, version, SCORER);
    if (!row) return null;
    return parseJson(z.object({ analysis: z.string() }).parse(row).analysis);
  }
  setUpstreamAnalysis(input: { name: string; version: string; digest: string; analysis: unknown; at: number }): void {
    this.db
      .query("INSERT OR REPLACE INTO upstream_analysis_v2 (package, version, digest, scorer, analysis, analyzed_at) VALUES (?, ?, ?, ?, ?, ?)")
      .run(input.name, input.version, input.digest, SCORER, JSON.stringify(input.analysis), input.at);
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

  /** Newest events of the given kinds across all packages. */
  recentEvents(kinds: string[], limit: number): EventRecord[] {
    if (kinds.length === 0) return [];
    return this.db
      .query(`SELECT * FROM events WHERE kind IN (${kinds.map(() => "?").join(", ")}) ORDER BY at DESC, id DESC LIMIT ?`)
      .all(...kinds, limit)
      .map((r) => {
        const e = EventRow.parse(r);
        return { ...e, detail: parseJson(e.detail) };
      });
  }

  tx<T>(fn: () => T): T {
    return this.db.transaction(fn)();
  }
}
