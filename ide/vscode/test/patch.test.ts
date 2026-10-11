import * as assert from "node:assert/strict";
import { test } from "node:test";

import { PatchError, applyPatch, parseFixRef } from "../src/patch";

const SRC = [
  "import sqlite3",
  "",
  "",
  "def find(conn, name):",
  "    rows = conn.execute(f\"SELECT * FROM users WHERE name = '{name}'\")",
  "    return rows.fetchall()",
  "",
].join("\n");

// As eVal's difflib-based unified_diff writes it.
const DIFF = [
  "diff --git a/app.py b/app.py",
  "--- a/app.py",
  "+++ b/app.py",
  "@@ -2,5 +2,5 @@",
  " ",
  " ",
  " def find(conn, name):",
  "-    rows = conn.execute(f\"SELECT * FROM users WHERE name = '{name}'\")",
  "+    rows = conn.execute(\"SELECT * FROM users WHERE name = ?\", (name,))",
  "     return rows.fetchall()",
  "",
].join("\n");

const FIXED = SRC.replace("f\"SELECT * FROM users WHERE name = '{name}'\")", "\"SELECT * FROM users WHERE name = ?\", (name,))");

test("applies a diff to the audited file", () => {
  assert.equal(applyPatch(SRC, DIFF), FIXED);
});

test("finds a hunk that moved since the audit", () => {
  const moved = `"""Users."""\n# extra line\n${SRC}`;
  assert.equal(applyPatch(moved, DIFF), `"""Users."""\n# extra line\n${FIXED}`);
});

test("refuses a file whose code changed since the audit", () => {
  const changed = SRC.replace("return rows.fetchall()", "return list(rows)");
  assert.throws(() => applyPatch(changed, DIFF), (err: unknown) =>
    err instanceof PatchError && /change 1 \(line 2 in the audited commit\) no longer matches/.test(err.message));
});

test("an already applied fix does not apply twice", () => {
  assert.throws(() => applyPatch(FIXED, DIFF), PatchError);
});

test("keeps CRLF line endings of the working copy", () => {
  const crlf = SRC.replace(/\n/g, "\r\n");
  assert.equal(applyPatch(crlf, DIFF), FIXED.replace(/\n/g, "\r\n"));
});

test("handles a missing newline at the end of the file", () => {
  const src = "a = 1\nb = 2";
  const diff = "--- a/x.py\n+++ b/x.py\n@@ -1,2 +1,2 @@\n a = 1\n-b = 2\n\\ No newline at end of file\n+b = 3\n";
  assert.equal(applyPatch(src, diff), "a = 1\nb = 3\n");
});

test("applies several hunks in order", () => {
  const src = Array.from({ length: 30 }, (_, i) => `line ${i + 1}`).join("\n") + "\n";
  const diff = [
    "--- a/f\n+++ b/f",
    "@@ -1,4 +1,4 @@", "-line 1", "+LINE 1", " line 2", " line 3", " line 4",
    "@@ -27,4 +27,5 @@", " line 27", " line 28", " line 29", "-line 30", "+line 30", "+line 31", "",
  ].join("\n");
  const out = applyPatch(src, diff).split("\n");
  assert.equal(out[0], "LINE 1");
  assert.deepEqual(out.slice(-3), ["line 30", "line 31", ""]);
});

test("a diff without hunks is an error", () => {
  assert.throws(() => applyPatch(SRC, "--- a/app.py\n+++ b/app.py\n"), PatchError);
});

test("fix references from links and ids", () => {
  const id = "0b9a6c52-3f1e-4f6e-9d55-0c2a1f2b7e10";
  assert.equal(parseFixRef(id), id);
  assert.equal(parseFixRef(` ${id.toUpperCase()} `), id);
  assert.equal(parseFixRef(`https://eval.example.com/o/acme/fixes/${id}`), id);
  assert.equal(parseFixRef(`https://eval.example.com/o/acme/fixes/${id}.patch`), id);
  assert.equal(parseFixRef("https://eval.example.com/o/acme/audits/123"), undefined);
  assert.equal(parseFixRef("not-an-id"), undefined);
});
