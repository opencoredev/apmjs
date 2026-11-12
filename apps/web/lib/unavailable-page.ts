// The 503 page proxy.ts sends when the registry can't be read for a package page. It is a complete
// HTML document because a rewrite to an app page can't carry a 503: the page render resets it to 200.
// Colours are the light and dark --background/--foreground/--surface/--muted-foreground of globals.css.

function escapeHtml(text: string): string {
  return text.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
}

/** `retryPath` must be a same-site path; `name` is shown as text. */
export function unavailablePage({ name, retryPath }: { name: string; retryPath: string }): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>Registry unavailable · apm</title>
<style>
:root{color-scheme:light dark;--bg:#ffffff;--fg:#171717;--surface:#f4f4f2;--muted:#696965;--primary:#171717;--on-primary:#fafafa}
@media (prefers-color-scheme:dark){:root{--bg:#111111;--fg:#eeeeee;--surface:#1b1b1b;--muted:#a3a39e;--primary:#eeeeee;--on-primary:#171717}}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;background:var(--bg);color:var(--fg);font:16px/1.5 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;-webkit-font-smoothing:antialiased}
header{max-width:72rem;margin:0 auto;padding:16px}
header a{color:var(--fg);font-weight:600;font-size:22px;letter-spacing:-.02em;text-decoration:none}
main{max-width:72rem;margin:0 auto;padding:24px 16px 96px}
.card{max-width:36rem;background:var(--surface);border-radius:16px;padding:24px 20px}
h1{margin:0 0 8px;font-size:24px;font-weight:500;letter-spacing:-.01em}
p{margin:0 0 16px;color:var(--muted);font-size:15px;line-height:24px}
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--fg);overflow-wrap:anywhere}
.actions{display:flex;flex-wrap:wrap;gap:12px;align-items:center}
.btn{display:inline-flex;align-items:center;height:36px;padding:0 12px;border-radius:8px;background:var(--primary);color:var(--on-primary);font-size:14px;font-weight:500;text-decoration:none}
.link{color:var(--fg);font-size:14px;text-underline-offset:4px}
</style>
</head>
<body>
<header><a href="/" aria-label="apm home">apm</a></header>
<main>
<div class="card" role="alert">
<h1>The registry did not answer</h1>
<p>We couldn&#39;t load <code>${escapeHtml(name)}</code> just now. This is a problem on our side, not a sign that the package is gone. Try again in a moment.</p>
<div class="actions"><a class="btn" href="${escapeHtml(retryPath)}">Try again</a><a class="link" href="/">Search packages</a></div>
</div>
</main>
</body>
</html>
`;
}
