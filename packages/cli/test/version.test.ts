// The version apm --version prints is the one packages/cli/package.json names, and the one a CLI release publishes.
import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { z } from "zod";
import { CLI_VERSION } from "../src/version.ts";

test("CLI_VERSION matches packages/cli/package.json", () => {
  const pkg = z.object({ version: z.string() }).parse(JSON.parse(readFileSync(join(import.meta.dir, "..", "package.json"), "utf8")));

  expect(CLI_VERSION).toBe(pkg.version);
});
