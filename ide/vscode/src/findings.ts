/** Pure mapping from eVal findings to editor concepts. No VS Code imports, so it is unit-testable under plain Node. */

import type { Finding, Severity } from "./api";

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

export type Level = "error" | "warning" | "information" | "hint";

const LEVELS: Record<Severity, Level> = {
  critical: "error", high: "error", medium: "warning", low: "information", info: "hint",
};

export function levelFor(severity: Severity): Level {
  return LEVELS[severity] ?? "information";
}

/** True when ``severity`` is at or above ``minimum`` (critical is highest). */
export function meetsMinimum(severity: Severity, minimum: Severity): boolean {
  const rank = SEVERITIES.indexOf(severity);
  return rank !== -1 && rank <= SEVERITIES.indexOf(minimum);
}

/** Zero-based, inclusive line span. Findings without a line anchor to the first line of the file. */
export function lineSpan(f: Pick<Finding, "line_start" | "line_end">): { start: number; end: number } {
  const start = f.line_start && f.line_start > 0 ? f.line_start - 1 : 0;
  const end = f.line_end && f.line_end > 0 ? Math.max(f.line_end - 1, start) : start;
  return { start, end };
}

/** Repository-relative POSIX path, or null for repository-level findings. */
export function normalizePath(filePath: string | null | undefined): string | null {
  if (!filePath) return null;
  const p = filePath.replace(/\\/g, "/").replace(/^(\.\/)+/, "").replace(/^\/+/, "");
  return p || null;
}

export function diagnosticMessage(f: Finding): string {
  const kind = f.kind && f.kind !== "confirmed" ? `, ${f.kind}` : "";
  return `${f.title} (${f.severity}${kind})`;
}

/** Group findings by file, dropping those below ``minimum``. Repository-level findings go under ``null``. */
export function groupByFile(findings: Finding[], minimum: Severity): Map<string | null, Finding[]> {
  const out = new Map<string | null, Finding[]>();
  for (const f of findings) {
    if (!meetsMinimum(f.severity, minimum)) continue;
    const key = normalizePath(f.file_path);
    const list = out.get(key);
    if (list) list.push(f);
    else out.set(key, [f]);
  }
  return out;
}

/** "owner/name" from a git remote URL (https, ssh or scp-style), or null. */
export function fullNameFromRemote(url: string): string | null {
  const m = url.trim().match(/^(?:[a-z+]+:\/\/)?(?:[^@/]+@)?[^/:]+[:/](.+?)(?:\.git)?\/*$/i);
  if (!m) return null;
  const parts = m[1].split("/").filter(Boolean);
  if (parts.length < 2) return null;
  return `${parts[parts.length - 2]}/${parts[parts.length - 1]}`;
}

/**
 * "owner/name" of a virtual GitHub workspace (vscode.dev / github.dev open ``vscode-vfs://github[+ref]/owner/name``),
 * or null for any other workspace.
 */
export function fullNameFromWorkspaceUri(uri: { scheme: string; authority: string; path: string }): string | null {
  if (uri.scheme !== "vscode-vfs" || !/^github(\+|$)/.test(uri.authority)) return null;
  const parts = uri.path.split("/").filter(Boolean);
  return parts.length >= 2 ? `${parts[0]}/${parts[1]}` : null;
}

function escapeMd(text: string): string {
  return text.replace(/([\\`*_[\]#|<>~])/g, "\\$1");
}

function fence(text: string): string {
  const ticks = text.includes("```") ? "````" : "```";
  return `${ticks}\n${text}\n${ticks}`;
}

/** Markdown for the hover card. ``webUrl`` links the finding page in eVal. */
export function hoverMarkdown(f: Finding, webUrl: string): string {
  const parts: string[] = [];
  parts.push(`**eVal · ${escapeMd(f.title)}**`);
  const meta = [f.severity, f.category, f.kind, `confidence ${f.confidence}`, f.lifecycle].filter(Boolean);
  parts.push(`\`${f.rule_id}\` · ${meta.map(escapeMd).join(" · ")}`);
  if (f.description) parts.push(escapeMd(f.description));
  const ai = f.ai_explanation || {};
  if (ai.explanation) {
    parts.push(`**AI explanation**${ai.model ? ` (${escapeMd(ai.model)})` : ""}: ${escapeMd(ai.explanation)}`);
  }
  if (f.remediation) parts.push(`**Fix:** ${escapeMd(f.remediation)}`);
  if (ai.remediation_steps?.length) {
    parts.push(ai.remediation_steps.map((s, i) => `${i + 1}. ${escapeMd(s)}`).join("\n"));
  }
  if (ai.suggested_patch) parts.push(`**Suggested patch** (review before applying):\n\n${fence(ai.suggested_patch)}`);
  if (f.reachability) parts.push(`**Reachability:** ${escapeMd(f.reachability)}`);
  const cwe = f.compliance?.cwe;
  const owasp = f.compliance?.owasp;
  const tags = [cwe, owasp].flat().filter((t): t is string => typeof t === "string" && t.length > 0);
  if (tags.length) parts.push(`**Mapped to:** ${tags.map(escapeMd).join(", ")}`);
  const links = [`[Open in eVal](${webUrl})`, ...(f.references || []).slice(0, 3).map((r, i) => `[ref ${i + 1}](${r})`)];
  parts.push(links.join(" · "));
  return parts.join("\n\n");
}

/** ISO date ``days`` from ``from``, for the default accepted-risk review date. */
export function isoDateAfter(days: number, from: Date = new Date()): string {
  const d = new Date(Date.UTC(from.getUTCFullYear(), from.getUTCMonth(), from.getUTCDate() + days));
  return d.toISOString().slice(0, 10);
}
