// Where the registry is, and how a package name goes into one of its paths.

export const REGISTRY = (process.env.APM_REGISTRY ?? "http://127.0.0.1:4873/").replace(/\/?$/, "/");

export function encodeName(name: string): string {
  return name.startsWith("@") ? `@${encodeURIComponent(name.slice(1))}` : encodeURIComponent(name);
}

/** The registry path for one file of one version (GET /-/apm/v1/file/<name>/<version>?path=...). */
export function fileApiPath(input: { name: string; version: string; path: string }): string {
  return `-/apm/v1/file/${encodeName(input.name)}/${encodeURIComponent(input.version)}?path=${encodeURIComponent(input.path)}`;
}
