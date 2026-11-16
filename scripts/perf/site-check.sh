#!/usr/bin/env bash
# The site-speed climb's check: builds the website as the deploy does, then runs the site bench. Prints the bench's
# score (modeled ms over every page, cold and warm; lower is better) as the last line.
set -euo pipefail
cd "$(dirname "$0")/../.."
log="${TMPDIR:-/tmp}/apm-site-build.log"
bun packages/infra/build-web.ts > "$log" 2>&1 || { tail -40 "$log"; exit 1; }
bun scripts/perf/site-bench.ts 2> >(grep -v '^    at \|^  digest\|^}$\|^Error: Expected the resume\|cannot guarantee that Cache\|report a github issue' >&2)
