// Checks on the environment before the registry starts. Pure: environment in, a refusal or null out.

const on = (v: string | undefined): boolean => v === "1" || v === "true" || v === "on";

/** Whether a public URL is a production address: https, and not a loopback host. */
export function isPublicHttps(url: string): boolean {
  let u: URL;

  try {
    u = new URL(url);
  } catch {
    return false;
  }

  if (u.protocol !== "https:") return false;
  const host = u.hostname.replace(/^\[|\]$/g, "");

  return !(host === "localhost" || host.endsWith(".localhost") || host === "::1" || host.startsWith('127.'));
}

/**
 * Why the registry must not start, or null. Password accounts (npm's adduser) on a public https registry
 * let anyone with a password publish without a second factor, so they need an explicit override.
 */
export function legacyAuthRefusal(env: Record<string, string | undefined>): string | null {
  if (!on(env.APM_LEGACY_AUTH)) return null;
  const url = env.APM_PUBLIC_URL;

  if (url === undefined || !isPublicHttps(url)) return null;

  if (on(env.APM_ALLOW_LEGACY_IN_PROD)) return null;

  return `APM_LEGACY_AUTH is on and APM_PUBLIC_URL (${url}) is a public https address. Password accounts skip GitHub sign-in and publish approval. Turn APM_LEGACY_AUTH off, or set APM_ALLOW_LEGACY_IN_PROD=1 if you really mean it.`;
}
