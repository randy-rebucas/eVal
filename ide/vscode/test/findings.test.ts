import * as assert from "node:assert/strict";
import { test } from "node:test";

import type { Finding } from "../src/api";
import {
  diagnosticMessage, fullNameFromRemote, fullNameFromWorkspaceUri, groupByFile, hoverMarkdown, isoDateAfter, levelFor, lineSpan, meetsMinimum,
  normalizePath,
} from "../src/findings";

export function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "f1", rule_id: "bandit:B608", fingerprint: "fp", title: "SQL built from user input", category: "security",
    severity: "high", confidence: "medium", kind: "potential", description: "String-built SQL query.",
    remediation: "Use parameterised queries.", file_path: "app.py", line_start: 16, line_end: 16, evidence: "",
    sources: ["bandit"], references: ["https://cwe.mitre.org/data/definitions/89.html"], lifecycle: "new",
    triage_status: "open", ai_explanation: {}, ...overrides,
  };
}

test("severity maps to diagnostic level", () => {
  assert.equal(levelFor("critical"), "error");
  assert.equal(levelFor("high"), "error");
  assert.equal(levelFor("medium"), "warning");
  assert.equal(levelFor("low"), "information");
  assert.equal(levelFor("info"), "hint");
});

test("minimum severity filter", () => {
  assert.ok(meetsMinimum("critical", "high"));
  assert.ok(meetsMinimum("high", "high"));
  assert.ok(!meetsMinimum("medium", "high"));
  assert.ok(meetsMinimum("info", "info"));
});

test("line span is zero-based and tolerates missing or inverted lines", () => {
  assert.deepEqual(lineSpan({ line_start: 16, line_end: 18 }), { start: 15, end: 17 });
  assert.deepEqual(lineSpan({ line_start: 16, line_end: null }), { start: 15, end: 15 });
  assert.deepEqual(lineSpan({ line_start: null, line_end: null }), { start: 0, end: 0 });
  assert.deepEqual(lineSpan({ line_start: 0, line_end: 0 }), { start: 0, end: 0 });
  assert.deepEqual(lineSpan({ line_start: 10, line_end: 4 }), { start: 9, end: 9 });
});

test("paths are normalised to repository-relative POSIX", () => {
  assert.equal(normalizePath("./src/app.py"), "src/app.py");
  assert.equal(normalizePath("src\\app.py"), "src/app.py");
  assert.equal(normalizePath("/src/app.py"), "src/app.py");
  assert.equal(normalizePath(""), null);
  assert.equal(normalizePath(null), null);
});

test("grouping filters by severity and separates repository-level findings", () => {
  const groups = groupByFile([
    finding({ id: "a", file_path: "app.py" }),
    finding({ id: "b", file_path: "./app.py", severity: "low" }),
    finding({ id: "c", file_path: null, severity: "critical" }),
    finding({ id: "d", file_path: "lib/x.py", severity: "info" }),
  ], "low");
  assert.deepEqual(groups.get("app.py")!.map((f) => f.id), ["a", "b"]);
  assert.deepEqual(groups.get(null)!.map((f) => f.id), ["c"]);
  assert.equal(groups.has("lib/x.py"), false);
});

test("diagnostic message names severity and non-confirmed kind", () => {
  assert.equal(diagnosticMessage(finding()), "SQL built from user input (high, potential)");
  assert.equal(diagnosticMessage(finding({ kind: "confirmed" })), "SQL built from user input (high)");
});

test("GitHub owner/name is parsed from every remote style", () => {
  for (const url of [
    "https://github.com/acme/shop.git", "https://github.com/acme/shop", "https://user@github.com/acme/shop/",
    "git@github.com:acme/shop.git", "ssh://git@github.com/acme/shop.git", "ssh://git@github.com:22/acme/shop",
  ]) {
    assert.equal(fullNameFromRemote(url), "acme/shop", url);
  }
  assert.equal(fullNameFromRemote("not a url"), null);
  assert.equal(fullNameFromRemote("https://github.com/acme"), null);
});

test("owner/name is read from vscode.dev / github.dev virtual workspace URIs", () => {
  assert.equal(fullNameFromWorkspaceUri({ scheme: "vscode-vfs", authority: "github", path: "/acme/shop" }), "acme/shop");
  assert.equal(fullNameFromWorkspaceUri({ scheme: "vscode-vfs", authority: "github+7b2276223a317d", path: "/acme/shop/src" }),
    "acme/shop");
  assert.equal(fullNameFromWorkspaceUri({ scheme: "vscode-vfs", authority: "azurerepos", path: "/acme/shop" }), null);
  assert.equal(fullNameFromWorkspaceUri({ scheme: "file", authority: "", path: "/c:/code/shop" }), null);
  assert.equal(fullNameFromWorkspaceUri({ scheme: "vscode-vfs", authority: "github", path: "/acme" }), null);
});

test("hover escapes finding text and includes AI explanation and link", () => {
  const md = hoverMarkdown(finding({
    title: "Use of `eval` <script>", ai_explanation: { explanation: "User input reaches *eval*.", model: "m",
      remediation_steps: ["Remove eval"], suggested_patch: "- eval(x)\n+ json.loads(x)" },
    compliance: { cwe: ["CWE-95"], owasp: ["A03:2021"] },
  }), "https://eval.example.com/o/acme/findings/f1");
  assert.ok(md.includes("Use of \\`eval\\` \\<script\\>"));
  assert.ok(md.includes("User input reaches \\*eval\\*"));
  assert.ok(md.includes("1\\. Remove eval") || md.includes("1. Remove eval"));
  assert.ok(md.includes("```\n- eval(x)\n+ json.loads(x)\n```"));
  assert.ok(md.includes("CWE-95"));
  assert.ok(md.includes("[Open in eVal](https://eval.example.com/o/acme/findings/f1)"));
});

test("default review date", () => {
  assert.equal(isoDateAfter(90, new Date(Date.UTC(2026, 9, 10))), "2027-01-08");
});
