/** "3d ago" style age of an ISO timestamp, coarse on purpose. */
export function ago(iso: string, now = Date.now()): string {
  const ms = now - Date.parse(iso);
  const d = Math.floor(ms / 86_400_000);

  if (d >= 365) return `${Math.floor(d / 365)}y ago`;

  if (d >= 30) return `${Math.floor(d / 30)}mo ago`;

  if (d >= 1) return `${d}d ago`;
  const h = Math.floor(ms / 3_600_000);

  if (h >= 1) return `${h}h ago`;
  const m = Math.floor(ms / 60_000);

  return m >= 1 ? `${m}m ago` : "just now";
}

/** Bytes as "812 B", "4.2 kB" or "1.3 MB". */
export function formatSize(n: number): string {
  if (n < 1024) return `${n} B`;

  return n < 1048576 ? `${(n / 1024).toFixed(1)} kB` : `${(n / 1048576).toFixed(1)} MB`;
}
