// Response headers for every route, and the cache policy for per-user routes proxied to the registry.
// Used by next.config.ts; kept here so the tests can check the exact values.

type Header = { key: string; value: string };

/**
 * The Content-Security-Policy. Scripts need 'unsafe-inline': with Cache Components the page shell is
 * prerendered, so Next.js can't put a per-request nonce on its inline bootstrap and flight scripts
 * (node_modules/next/dist/docs/01-app/02-guides/content-security-policy.md). The policy still blocks
 * framing, plugins, <base> hijacking, off-site form posts and scripts or fetches from other origins.
 * Avatars come from the OAuth providers, so images may load from any https origin.
 */
export function contentSecurityPolicy(dev: boolean): string {
  const directives = [
    "default-src 'self'",
    `script-src 'self' 'unsafe-inline'${dev ? " 'unsafe-eval'" : ""}`,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob: https:",
    "font-src 'self'",
    // The dev server's hot reload uses a WebSocket on the same host.
    `connect-src 'self'${dev ? " ws: wss:" : ""}`,
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ];

  return directives.join("; ");
}

// Passkeys need the WebAuthn features on this origin; nothing on the site uses the others.
export const PERMISSIONS_POLICY = "camera=(), microphone=(), geolocation=(), payment=(), usb=(), publickey-credentials-get=(self), publickey-credentials-create=(self)";

export function securityHeaders(dev: boolean): Header[] {
  return [
    { key: "Content-Security-Policy", value: contentSecurityPolicy(dev) },
    { key: "X-Frame-Options", value: "DENY" },
    { key: "X-Content-Type-Options", value: "nosniff" },
    { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
    { key: "Permissions-Policy", value: PERMISSIONS_POLICY },
  ];
}

/** For responses that belong to one signed-in user: never store them in a shared cache. */
export const PRIVATE_HEADERS: Header[] = [
  { key: "Cache-Control", value: "private, no-store" },
  { key: "Vary", value: "Cookie" },
];
