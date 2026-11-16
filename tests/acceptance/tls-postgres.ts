// A throwaway Postgres that speaks TLS (a self-signed certificate), for the tests that check what the registry's
// database guard does on a TLS connection. Clients reach it with sslmode=require; the tests that use it accept the
// self-signed certificate for their own run.
import { chmodSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { findInitdb } from "./postgres.ts";

export type TlsPostgres = { url: string; stop: () => void };

export function startTlsPostgres(): TlsPostgres {
  const initdb = findInitdb();

  if (!initdb) throw new Error("these tests need Postgres: initdb on PATH or under /usr/lib/postgresql");
  const dir = mkdtempSync(join(tmpdir(), "apm-pg-tls-"));
  const data = join(dir, "data");
  const init = spawnSync(initdb, ["-D", data, "-U", "postgres", "--auth=trust", "-E", "UTF8", "--no-sync"], { encoding: "utf8" });

  if (init.status !== 0) throw new Error(`initdb failed: ${init.stderr}`);
  const cert = spawnSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", join(data, "server.key"), "-out", join(data, "server.crt"), "-days", "1", "-subj", "/CN=127.0.0.1"], { encoding: "utf8" });

  if (cert.status !== 0) throw new Error(`openssl failed: ${cert.stderr}`);
  chmodSync(join(data, "server.key"), 0o600);
  const port = 20000 + Math.floor(Math.random() * 20000);
  const opts = `-p ${port} -c unix_socket_directories='' -c listen_addresses=127.0.0.1 -c fsync=off -c ssl=on -c ssl_cert_file=server.crt -c ssl_key_file=server.key`;
  const start = spawnSync(join(initdb, "..", "pg_ctl"), ["-D", data, "-o", opts, "-l", join(dir, "log"), "-w", "start"], { encoding: "utf8" });

  if (start.status !== 0) throw new Error(`pg_ctl start failed: ${start.stderr}${start.stdout}`);
  const pid = Number(readFileSync(join(data, "postmaster.pid"), "utf8").split("\n")[0]);

  return {
    url: `postgres://postgres:postgres@127.0.0.1:${port}/postgres?sslmode=require`,
    stop: () => {
      try {
        process.kill(pid, "SIGQUIT");
      } catch {
        // already gone
      }

      rmSync(dir, { recursive: true, force: true });
    },
  };
}
