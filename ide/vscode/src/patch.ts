/** Applying eVal fix proposals locally. No VS Code imports, so it can be unit-tested under plain Node. */

export class PatchError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PatchError";
  }
}

interface Hunk {
  oldStart: number;
  /** Lines of the original file the hunk replaces, and their replacement; each keeps its line ending. */
  before: string[];
  after: string[];
}

/** Split text into lines that keep their "\n" (the last line may have none). */
function lines(text: string): string[] {
  const out = text.split("\n").map((l) => `${l}\n`);
  const last = out.pop()!;
  if (last !== "\n") out.push(last.slice(0, -1));
  return out;
}

/** Parse the hunks of a single-file unified diff (as eVal produces it: difflib, with "\ No newline" markers). */
export function parseHunks(diff: string): Hunk[] {
  const hunks: Hunk[] = [];
  let cur: Hunk | undefined;
  let lastSide: "before" | "after" | "both" | undefined;
  for (const raw of diff.split("\n")) {
    const head = /^@@ -(\d+)(?:,\d+)? \+\d+(?:,\d+)? @@/.exec(raw);
    if (head) {
      cur = { oldStart: Number(head[1]), before: [], after: [] };
      hunks.push(cur);
      lastSide = undefined;
      continue;
    }
    if (!cur || raw === "") continue; // file headers before the first hunk; the split's trailing ""
    const text = `${raw.slice(1)}\n`;
    switch (raw[0]) {
      case " ": cur.before.push(text); cur.after.push(text); lastSide = "both"; break;
      case "-": cur.before.push(text); lastSide = "before"; break;
      case "+": cur.after.push(text); lastSide = "after"; break;
      case "\\": { // "\ No newline at end of file": the previous line has no line ending
        const trim = (side: string[]) => { side[side.length - 1] = side[side.length - 1].slice(0, -1); };
        if (lastSide === "before" || lastSide === "both") trim(cur.before);
        if (lastSide === "after" || lastSide === "both") trim(cur.after);
        break;
      }
      default: throw new PatchError(`Unexpected diff line: ${raw.slice(0, 40)}`);
    }
  }
  if (!hunks.length) throw new PatchError("The diff has no changes.");
  return hunks;
}

function matchesAt(file: string[], block: string[], at: number): boolean {
  if (at < 0 || at + block.length > file.length) return false;
  return block.every((l, i) => file[at + i] === l);
}

/**
 * Apply a single-file unified diff to ``original``. Every hunk must match the file exactly (context and removed
 * lines); it may sit at a different line than in the audited commit, as long as hunks stay in order. Files checked
 * out with CRLF line endings are patched with LF diffs and keep their CRLF endings.
 */
export function applyPatch(original: string, diff: string): string {
  const crlf = original.includes("\r\n") && !diff.includes("\r\n");
  const file = lines(crlf ? original.replace(/\r\n/g, "\n") : original);
  const out: string[] = [];
  let pos = 0; // first line of ``file`` not yet copied to ``out``
  let delta = 0; // how far the file has drifted from the audited commit, from earlier hunks
  parseHunks(diff).forEach((h, n) => {
    const expected = Math.max(h.oldStart - 1 + delta, pos);
    let at = -1;
    for (let d = 0; at < 0 && (expected - d >= pos || expected + d <= file.length); d++) {
      if (matchesAt(file, h.before, expected - d) && expected - d >= pos) at = expected - d;
      else if (matchesAt(file, h.before, expected + d)) at = expected + d;
    }
    if (at < 0) {
      throw new PatchError(`change ${n + 1} (line ${h.oldStart} in the audited commit) no longer matches this file`);
    }
    out.push(...file.slice(pos, at), ...h.after);
    pos = at + h.before.length;
    delta = at - (h.oldStart - 1);
  });
  out.push(...file.slice(pos));
  const text = out.join("");
  return crlf ? text.replace(/\n/g, "\r\n") : text;
}

const UUID = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i;

/** A fix id from what a person pastes: the id itself, or a fix page link (…/fixes/<id>). */
export function parseFixRef(input: string): string | undefined {
  const text = input.trim();
  const inLink = /\/fixes\/([0-9a-f-]{36})(?:[/?#.]|$)/i.exec(text);
  if (inLink && UUID.test(inLink[1])) return inLink[1].toLowerCase();
  return new RegExp(`^${UUID.source}$`, "i").test(text) ? text.toLowerCase() : undefined;
}
