import { startRegistry } from "./index.ts";
import { legacyAuthRefusal } from "./startup.ts";

const env = process.env;
const refusal = legacyAuthRefusal(env);

if (refusal !== null) {
  process.stderr.write(`apm registry refused to start: ${refusal}\n`);
  process.exit(1);
}

const port = Number(env.APM_PORT ?? 4873);
const dataDir = env.APM_DATA_DIR ?? ".data";
const upstream = env.APM_UPSTREAM ?? "https://registry.npmjs.org/";
const on = (v: string | undefined): boolean => v === "1" || v === "true" || v === "on";
const pair = (id: string | undefined, secret: string | undefined): { clientId: string; clientSecret: string } | null =>
  id && secret ? { clientId: id, clientSecret: secret } : null;

const github = pair(env.APM_GITHUB_CLIENT_ID, env.APM_GITHUB_CLIENT_SECRET);
const vercel = pair(env.APM_VERCEL_CLIENT_ID, env.APM_VERCEL_CLIENT_SECRET);
const namePolicy = env.APM_NAME_POLICY === "open" ? "open" : "scoped";

const { url } = await startRegistry({
  dataDir,
  port,
  hostname: env.APM_HOST ?? "127.0.0.1",
  ...(upstream === "off" ? {} : { upstream }),
  // The website's public origin: sign-in callbacks, approval links and the device page.
  ...(env.APM_PUBLIC_URL ? { webUrl: env.APM_PUBLIC_URL } : {}),
  // Where tarballs are fetched from, when it differs from the server's own address.
  ...(env.APM_REGISTRY_URL ? { publicUrl: env.APM_REGISTRY_URL } : {}),
  legacyAuth: on(env.APM_LEGACY_AUTH),
  namePolicy,
  auth: {
    ...(env.APM_AUTH_SECRET ? { secret: env.APM_AUTH_SECRET } : {}),
    ...(github ? { github } : {}),
    ...(vercel ? { vercel } : {}),
  },
});
process.stdout.write(
  `apm registry listening on ${url} (sign-in: ${[github ? "GitHub" : null, vercel ? "Vercel" : null].filter(Boolean).join(", ") || "no OAuth apps configured"}; legacy auth ${on(env.APM_LEGACY_AUTH) ? "on" : "off"}; names ${namePolicy})\n`,
);
