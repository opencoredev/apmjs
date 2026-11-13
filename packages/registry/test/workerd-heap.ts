// Runs a module inside workerd (Miniflare) and lets it measure its own memory. workerd starts with V8's --expose-gc,
// so the module can force a full collection; it then asks the test process, through the HEAP service binding, for the
// isolate's memory, which the test process reads over the inspector (Runtime.getHeapUsage): the JS heap, the
// embedder's heap and ArrayBuffer backing stores, which live outside the JS heap (a Uint8Array's bytes) and count
// toward a Worker's memory all the same. The module is idle on
// that fetch while it is measured, so what it holds at that point is counted and nothing it has let go is.
//
// HeapProfiler.collectGarbage is not used: workerd answers it only the next time the isolate runs, which it cannot
// while it waits on the measurement.
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import cloudflareRolldown from "@alchemy.run/cloudflare-runtime/rolldown";
import { Miniflare } from "miniflare";
import { rolldown } from "rolldown";
import { z } from "zod";
import { COMPATIBILITY_DATE, COMPATIBILITY_FLAGS } from "../scripts/compat.ts";

const Target = z.array(z.object({ id: z.string(), webSocketDebuggerUrl: z.string() }));
const Reply = z.object({ id: z.number(), result: z.unknown().optional(), error: z.unknown().optional() });
const HeapUsage = z.object({ usedSize: z.number(), embedderHeapUsedSize: z.number().default(0), backingStorageSize: z.number().default(0) });

/**
 * Module source for the worker side: `measure(env)` collects garbage and gives the memory in use, in bytes. Paste it
 * into the entry passed to startWorkerdHeap.
 */
export const MEASURE = `
const measure = async (env) => {
  globalThis.gc();
  globalThis.gc();
  return Number(await (await env.HEAP.fetch("http://heap.invalid/")).text());
};
`;

/** A free TCP port on the loopback interface, for the inspector. */
async function freePort(): Promise<number> {
  const server = Bun.serve({ port: 0, hostname: "127.0.0.1", fetch: () => new Response(null, { status: 404 }) });
  const { port } = server;
  await server.stop(true);

  if (port === undefined) throw new Error("no free port");

  return port;
}

class Inspector {
  private next = 1;
  private readonly waiting = new Map<number, (reply: z.infer<typeof Reply>) => void>();
  private readonly socket: WebSocket;

  private constructor(socket: WebSocket) {
    this.socket = socket;
    socket.addEventListener("message", (event) => {
      const parsed = Reply.safeParse(JSON.parse(String(event.data)));

      if (!parsed.success) return;
      this.waiting.get(parsed.data.id)?.(parsed.data);
      this.waiting.delete(parsed.data.id);
    });
  }

  static async connect(port: number): Promise<Inspector> {
    const targets = Target.parse(await (await fetch(`http://127.0.0.1:${port}/json`)).json());
    // the user's worker; Miniflare's own (entry, cache, outbound) are listed beside it
    const url = targets.find((t) => t.id === "core:user:")?.webSocketDebuggerUrl;

    if (!url) throw new Error("workerd has no inspector target for the worker");
    const socket = new WebSocket(url);

    await new Promise<void>((resolve, reject) => {
      socket.addEventListener("open", () => resolve());
      socket.addEventListener("error", () => reject(new Error("the inspector socket failed")));
    });

    return new Inspector(socket);
  }

  /** Sends `method` and parses its result with `schema`. */
  async send<T>(method: string, schema: z.ZodType<T>): Promise<T> {
    const id = this.next++;
    const reply = new Promise<z.infer<typeof Reply>>((resolve) => this.waiting.set(id, resolve));
    this.socket.send(JSON.stringify({ id, method }));
    const got = await reply;

    if (got.error !== undefined) throw new Error(`${method}: ${JSON.stringify(got.error)}`);

    return schema.parse(got.result);
  }

  close(): void {
    this.socket.close();
  }
}

export type WorkerdHeap = {
  readonly dispatch: (path: string, init?: Parameters<Miniflare["dispatchFetch"]>[1]) => ReturnType<Miniflare["dispatchFetch"]>;
  readonly dispose: () => Promise<void>;
};

/**
 * Starts workerd with `entry` (module source; it may import repository files by absolute path) bundled as its only
 * module. Its fetch handler gets `env.HEAP`, a service whose fetch answers the isolate's memory in use, in bytes.
 */
export async function startWorkerdHeap(entry: string): Promise<WorkerdHeap> {
  const dir = mkdtempSync(join(tmpdir(), "apm-workerd-heap-"));
  const entryPath = join(dir, "entry.js");

  await Bun.write(entryPath, entry);
  // bundled as the deploy bundles the Worker (scripts/build.ts), so an entry can import the routes and their auth and
  // Postgres modules
  const bundle = await rolldown({ input: entryPath, external: ["lightningcss", "fsevents"], plugins: [cloudflareRolldown({ compatibilityDate: COMPATIBILITY_DATE, compatibilityFlags: [...COMPATIBILITY_FLAGS] })] });

  await bundle.write({ dir, format: "esm", entryFileNames: "worker.js", codeSplitting: false, minify: false, sourcemap: false });
  await bundle.close();
  const port = await freePort();
  let inspector: Inspector | null = null;
  // Miniflare reads workerd's V8 flags from the environment when it starts workerd
  const flags = process.env.MINIFLARE_WORKERD_V8_FLAGS;
  process.env.MINIFLARE_WORKERD_V8_FLAGS = "--expose-gc";

  const mf = new Miniflare({
    modulesRoot: dir,
    modules: [{ type: "ESModule", path: join(dir, "worker.js"), contents: await Bun.file(join(dir, "worker.js")).text() }],
    compatibilityDate: COMPATIBILITY_DATE,
    compatibilityFlags: [...COMPATIBILITY_FLAGS],
    inspectorPort: port,
    serviceBindings: {
      HEAP: async () => {
        if (!inspector) throw new Error("the inspector is not connected");

        const usage = await inspector.send("Runtime.getHeapUsage", HeapUsage);

        return new Response(String(usage.usedSize + usage.embedderHeapUsedSize + usage.backingStorageSize));
      },
    },
  });

  try {
    await mf.ready;
  } finally {
    if (flags === undefined) delete process.env.MINIFLARE_WORKERD_V8_FLAGS;
    else process.env.MINIFLARE_WORKERD_V8_FLAGS = flags;
  }

  inspector = await Inspector.connect(port);

  return {
    dispatch: (path, init) => mf.dispatchFetch(`http://heap.invalid${path}`, init),
    dispose: async () => {
      inspector?.close();
      await mf.dispose();
      rmSync(dir, { recursive: true, force: true });
    },
  };
}
