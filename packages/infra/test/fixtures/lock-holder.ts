// A stand-in for deploy.ts in release-lock.test.ts: takes the release lock (APM_RELEASE_LOCK) or exits 6, says so,
// optionally starts a child that holds the lock with it (as Alchemy's upload does), and waits.
//
//   bun lock-holder.ts <stage> <seconds> [child]
import { BUSY_CODE, lockedSpawn, takeReleaseLock } from "../../release-lock.ts";

const [stage = "test", seconds = "30", child] = process.argv.slice(2);
const taken = takeReleaseLock({ script: import.meta.path, argv: process.argv.slice(2), stage });

if (taken.kind === "busy") {
  process.stdout.write(`${taken.text}\n`);
  process.exit(BUSY_CODE);
}

if (child === "child") {
  const sleeper = lockedSpawn(taken.lock, ["sleep", "60"], { cwd: import.meta.dir, env: { PATH: process.env.PATH }, stdout: "ignore", stderr: "ignore", stdin: "ignore" });

  process.stdout.write(`inside ${process.pid} child ${sleeper.pid}\n`);
} else process.stdout.write(`inside ${process.pid}\n`);

await Bun.sleep(Number(seconds) * 1000);
