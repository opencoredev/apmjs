// Line diff for the review input: Myers O(ND) with a cap on edits, grouped into hunks with context.
// Every line that exists in the new file carries its 1-based new-file line number, so the model can
// cite it and the citation check can find it.

export type DiffLine = { kind: " " | "+" | "-"; text: string; newLine: number | null };

export type Hunk = { newStart: number; lines: DiffLine[] };

type Op = "=" | "+" | "-";

/** Context lines kept around each change. */
const CONTEXT = 3;

/** Beyond this many edits a file is shown as a rewrite instead of aligned. */
const MAX_EDITS = 3000;

/** Edit script between two id arrays, or null when more than `maxD` edits are needed. */
function myers(a: Int32Array, b: Int32Array, maxD: number): Op[] | null {
  const n = a.length;
  const m = b.length;
  const off = maxD + 1;
  const v = new Int32Array(2 * maxD + 3);
  const trace: Int32Array[] = [];
  let found = -1;

  for (let d = 0; d <= maxD; d++) {
    trace.push(v.slice());

    for (let k = -d; k <= d; k += 2) {
      const down = k === -d || (k !== d && (v[off + k - 1] ?? 0) < (v[off + k + 1] ?? 0));
      let x = down ? (v[off + k + 1] ?? 0) : (v[off + k - 1] ?? 0) + 1;
      let y = x - k;

      while (x < n && y < m && a[x] === b[y]) {
        x++;
        y++;
      }

      v[off + k] = x;

      if (x >= n && y >= m) {
        found = d;
        break;
      }
    }

    if (found >= 0) break;
  }

  if (found < 0) return null;
  const ops: Op[] = [];
  let x = n;
  let y = m;

  for (let d = found; d > 0; d--) {
    const vd = trace[d] ?? v;
    const k = x - y;
    const prevK = k === -d || (k !== d && (vd[off + k - 1] ?? 0) < (vd[off + k + 1] ?? 0)) ? k + 1 : k - 1;
    const prevX = vd[off + prevK] ?? 0;
    const prevY = prevX - prevK;

    while (x > prevX && y > prevY) {
      ops.push("=");
      x--;
      y--;
    }

    ops.push(x === prevX ? "+" : "-");
    x = prevX;
    y = prevY;
  }

  while (x > 0 && y > 0) {
    ops.push("=");
    x--;
    y--;
  }

  return ops.reverse();
}

/** Line diff with CONTEXT lines around each change. */
export function diffLines(a: readonly string[], b: readonly string[]): Hunk[] {
  let pre = 0;

  while (pre < a.length && pre < b.length && a[pre] === b[pre]) pre++;
  let suf = 0;

  while (suf < a.length - pre && suf < b.length - pre && a[a.length - 1 - suf] === b[b.length - 1 - suf]) suf++;
  const am = a.slice(pre, a.length - suf);
  const bm = b.slice(pre, b.length - suf);
  const ops: DiffLine[] = [];

  for (let i = 0; i < pre; i++) ops.push({ kind: " ", text: a[i] ?? "", newLine: i + 1 });
  const ids = new Map<string, number>();

  const idOf = (t: string): number => {
    let id = ids.get(t);

    if (id === undefined) {
      id = ids.size;
      ids.set(t, id);
    }

    return id;
  };

  const script = myers(Int32Array.from(am, idOf), Int32Array.from(bm, idOf), MAX_EDITS);

  if (script) {
    let i = 0;
    let j = 0;

    for (const s of script) {
      if (s === "=") ops.push({ kind: " ", text: bm[j++] ?? "", newLine: pre + j });
      else if (s === "+") ops.push({ kind: "+", text: bm[j++] ?? "", newLine: pre + j });
      else ops.push({ kind: "-", text: am[i] ?? "", newLine: null });

      if (s !== "+") i++;
    }
  } else {
    for (const t of am) ops.push({ kind: "-", text: t, newLine: null });

    bm.forEach((t, j) => ops.push({ kind: "+", text: t, newLine: pre + j + 1 }));
  }

  for (let k = 0; k < suf; k++) ops.push({ kind: " ", text: b[b.length - suf + k] ?? "", newLine: b.length - suf + k + 1 });

  return groupHunks(ops);
}

function groupHunks(ops: readonly DiffLine[]): Hunk[] {
  const hunks: { hunk: Hunk; lastIdx: number }[] = [];
  let lastChange = Number.NEGATIVE_INFINITY;

  ops.forEach((op, idx) => {
    if (op.kind === " ") return;
    const from = Math.max(0, idx - CONTEXT);
    const cur = hunks.at(-1);

    if (!cur || from > lastChange + CONTEXT + 1) {
      const hunk: Hunk = { newStart: 0, lines: ops.slice(from, idx) };
      hunks.push({ hunk, lastIdx: idx });
      hunk.lines.push(op);
    } else {
      cur.hunk.lines.push(...ops.slice(lastChange + 1, idx), op);
      cur.lastIdx = idx;
    }

    lastChange = idx;
  });

  return hunks.map(({ hunk, lastIdx }) => {
    for (let k = lastIdx + 1; k < Math.min(ops.length, lastIdx + 1 + CONTEXT); k++) {
      const o = ops[k];

      if (!o || o.kind !== " ") break;
      hunk.lines.push(o);
    }

    hunk.newStart = hunk.lines.find((l) => l.newLine !== null)?.newLine ?? 0;

    return hunk;
  });
}
