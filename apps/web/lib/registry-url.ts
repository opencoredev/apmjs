// Where the registry is, and how a package name goes into one of its paths.

export const REGISTRY = (process.env.APM_REGISTRY ?? "http://127.0.0.1:4873/").replace(/\/?$/, "/");

export function encodeName(name: string): string {
  return name.startsWith("@") ? `@${encodeURIComponent(name.slice(1))}` : encodeURIComponent(name);
}

/** The registry path of a package's answer (GET), and of whether the package exists (HEAD, proxy.ts). */
export function packageApiPath(name: string): string {
  return `-/apm/v1/packages/${encodeName(name)}`;
}

/** The registry path for one file of one version (GET /-/apm/v1/file/<name>/<version>?path=...). */
export function fileApiPath(input: { name: string; version: string; path: string }): string {
  return `-/apm/v1/file/${encodeName(input.name)}/${encodeURIComponent(input.version)}?path=${encodeURIComponent(input.path)}`;
}

/** The registry path for lines `line - context` to `line + context` of one file of a version, any size. */
export function excerptApiPath(input: { name: string; version: string; path: string; line: number; context: number }): string {
  return `${fileApiPath(input)}&line=${input.line}&context=${input.context}`;
}

/** The registry path for the README npm would pick from a version's tarball. */
export function readmeApiPath(input: { name: string; version: string }): string {
  return `-/apm/v1/readme/${encodeName(input.name)}/${encodeURIComponent(input.version)}`;
}
