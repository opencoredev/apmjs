// Where the registry is, and how a package name goes into one of its paths.

export const REGISTRY = (process.env.APM_REGISTRY ?? "http://127.0.0.1:4873/").replace(/\/?$/, "/");

export function encodeName(name: string): string {
  return name.startsWith("@") ? `@${encodeURIComponent(name.slice(1))}` : encodeURIComponent(name);
}
