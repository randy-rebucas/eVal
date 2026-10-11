/** eVal for VS Code: findings as diagnostics, hover details, triage quick fixes, and audits of the current branch. */

import * as vscode from "vscode";

import {
  ApiError, Audit, EvalClient, Finding, FixSummary, Repository, Severity, TERMINAL_STATUSES, TriageStatus, pickAudit,
} from "./api";
import { PatchError, applyPatch, parseFixRef } from "./patch";
import {
  SEVERITIES, diagnosticMessage, fullNameFromRemote, fullNameFromWorkspaceUri, groupByFile, hoverMarkdown, isoDateAfter, levelFor, lineSpan,
} from "./findings";
import { GitApi, GitRepository, getGitApi, remoteUrls } from "./git";

const SOURCE = "eVal";
const LINK_KEY = "eval.link";
const POLL_MS = 3000;
/** Local files, Remote/Codespaces documents, and vscode.dev / github.dev virtual workspaces. */
const SELECTOR: vscode.DocumentSelector = [{ scheme: "file" }, { scheme: "vscode-remote" }, { scheme: "vscode-vfs" }];

interface Link {
  repoId: string;
  name: string;
  fullName: string;
  source: Repository["source"];
  root: string; // URI string of the directory finding paths are relative to
}

type View =
  | { kind: "signedOut" }
  | { kind: "unlinked" }
  | { kind: "loading" }
  | { kind: "noAudit" }
  | { kind: "error"; message: string }
  | { kind: "loaded" };

const SEVERITY_LEVEL: Record<string, vscode.DiagnosticSeverity> = {
  error: vscode.DiagnosticSeverity.Error,
  warning: vscode.DiagnosticSeverity.Warning,
  information: vscode.DiagnosticSeverity.Information,
  hint: vscode.DiagnosticSeverity.Hint,
};

export function activate(context: vscode.ExtensionContext): void {
  const ext = new EvalExtension(context);
  context.subscriptions.push(ext);
  void ext.start();
}

export function deactivate(): void {}

class EvalExtension implements vscode.Disposable {
  private readonly diagnostics = vscode.languages.createDiagnosticCollection("eval");
  private readonly status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 50);
  private readonly output = vscode.window.createOutputChannel("eVal");
  private readonly disposables: vscode.Disposable[] = [];

  private git: GitApi | undefined;
  private audit: Audit | undefined;
  private findings: Finding[] = [];
  /** Findings shown in the editor, keyed by document URI string. */
  private byUri = new Map<string, Finding[]>();
  private repoLevel: Finding[] = [];
  private view: View = { kind: "signedOut" };
  private loadSeq = 0;
  private lastHead: string | undefined;
  private headTimer: ReturnType<typeof setTimeout> | undefined;

  constructor(private readonly context: vscode.ExtensionContext) {
    this.status.command = "eval.menu";
    this.disposables.push(
      this.diagnostics, this.status, this.output,
      vscode.commands.registerCommand("eval.signIn", () => this.run(() => this.signIn())),
      vscode.commands.registerCommand("eval.signOut", () => this.run(() => this.signOut())),
      vscode.commands.registerCommand("eval.linkRepository", () => this.run(async () => {
        if (await this.linkRepository(true)) await this.refresh(true);
      })),
      vscode.commands.registerCommand("eval.refresh", () => this.run(() => this.refresh(true))),
      vscode.commands.registerCommand("eval.runAudit", () => this.run(() => this.runAudit())),
      vscode.commands.registerCommand("eval.openAudit", () => this.run(() => this.openAudit())),
      vscode.commands.registerCommand("eval.clear", () => this.clear()),
      vscode.commands.registerCommand("eval.menu", () => this.run(() => this.menu())),
      vscode.commands.registerCommand("eval.triage", (id: string, status: TriageStatus) =>
        this.run(() => this.triage(id, status))),
      vscode.commands.registerCommand("eval.openFinding", (id: string) => this.run(() => this.openFinding(id))),
      vscode.commands.registerCommand("eval.applyFix", (ref?: string) => this.run(() => this.applyFix(ref))),
      // vscode://randy-rebucas.eval-auditor/applyFix?id=<fix id> (the "Apply in VS Code" link on a fix page).
      vscode.window.registerUriHandler({
        handleUri: (uri) => {
          const id = new URLSearchParams(uri.query).get("id");
          if (uri.path === "/applyFix" && id) void this.run(() => this.applyFix(id));
        },
      }),
      vscode.languages.registerHoverProvider(SELECTOR, { provideHover: (d, p) => this.hover(d, p) }),
      vscode.languages.registerCodeActionsProvider(SELECTOR,
        { provideCodeActions: (d, r, c) => this.codeActions(d, r, c) },
        { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }),
      vscode.workspace.onDidChangeConfiguration((e) => {
        if (e.affectsConfiguration("eval.minimumSeverity")) this.render();
        if (e.affectsConfiguration("eval.serverUrl")) void this.run(() => this.refresh(false));
      }),
    );
  }

  dispose(): void {
    if (this.headTimer) clearTimeout(this.headTimer);
    this.disposables.forEach((d) => d.dispose());
  }

  async start(): Promise<void> {
    this.git = await getGitApi();
    this.setView(await this.token() ? { kind: "unlinked" } : { kind: "signedOut" });
    this.status.show();
    this.watchHead();
    if (!this.config().get<boolean>("refreshOnStartup", true) || !(await this.token())) return;
    await this.run(async () => {
      if (this.link() || await this.linkRepository(false)) await this.refresh(false);
    }, false);
  }

  // ------------------------------------------------------------------------------------------- plumbing

  private config(): vscode.WorkspaceConfiguration {
    return vscode.workspace.getConfiguration("eval");
  }

  private serverUrl(): string {
    return (this.config().get<string>("serverUrl") || "").trim().replace(/\/+$/, "");
  }

  private secretKey(): string {
    return `eval.token:${this.serverUrl()}`;
  }

  private async token(): Promise<string | undefined> {
    return this.serverUrl() ? this.context.secrets.get(this.secretKey()) : undefined;
  }

  private async client(interactive: boolean): Promise<EvalClient | undefined> {
    let token = await this.token();
    if (!token && interactive) {
      await this.signIn();
      token = await this.token();
    }
    if (!token) {
      this.setView({ kind: "signedOut" });
      return undefined;
    }
    return new EvalClient(this.serverUrl(), token);
  }

  private link(): Link | undefined {
    return this.context.workspaceState.get<Link>(LINK_KEY);
  }

  /** Run a command body, reporting failures in a notification (interactive) or the status bar (background). */
  private async run(body: () => Promise<unknown>, interactive = true): Promise<void> {
    try {
      await body();
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      this.output.appendLine(`[error] ${message}`);
      if (err instanceof ApiError && err.status === 401) this.setView({ kind: "signedOut" });
      else this.setView({ kind: "error", message });
      if (interactive) {
        const pick = await vscode.window.showErrorMessage(`eVal: ${message}`,
          ...(err instanceof ApiError && err.status === 401 ? ["Sign In"] : []));
        if (pick === "Sign In") await this.run(() => this.signIn());
      }
    }
  }

  private gitRepoFor(root?: vscode.Uri): GitRepository | undefined {
    if (!this.git) return undefined;
    if (root) return this.git.getRepository(root) ?? undefined;
    const active = vscode.window.activeTextEditor?.document.uri;
    return (active && this.git.getRepository(active)) || this.git.repositories[0];
  }

  private head(): { branch?: string; commit?: string; ahead?: number } {
    const link = this.link();
    const head = this.gitRepoFor(link ? vscode.Uri.parse(link.root) : undefined)?.state.HEAD;
    return { branch: head?.name, commit: head?.commit, ahead: head?.ahead };
  }

  /** Reload findings when the checked-out commit changes (branch switch, pull, commit). */
  private watchHead(): void {
    if (!this.git) return;
    const hook = (repo: GitRepository) => this.disposables.push(repo.state.onDidChange(() => {
      const link = this.link();
      if (!link || repo.rootUri.toString() !== link.root) return;
      const head = `${repo.state.HEAD?.name}@${repo.state.HEAD?.commit}`;
      if (head === this.lastHead) return;
      const first = this.lastHead === undefined;
      this.lastHead = head;
      if (first || !this.config().get<boolean>("refreshOnStartup", true)) return;
      if (this.headTimer) clearTimeout(this.headTimer);
      this.headTimer = setTimeout(() => void this.run(() => this.refresh(false), false), 1500);
    }));
    this.git.repositories.forEach(hook);
    this.disposables.push(this.git.onDidOpenRepository(hook));
  }

  // ------------------------------------------------------------------------------------------- commands

  private async signIn(): Promise<void> {
    const url = await vscode.window.showInputBox({
      title: "eVal: Sign In (1/2)", prompt: "eVal server URL", value: this.serverUrl() || "http://localhost:8000",
      ignoreFocusOut: true,
      validateInput: (v) => /^https?:\/\/\S+$/.test(v.trim()) ? undefined : "Enter an http(s) URL",
    });
    if (!url) return;
    const serverUrl = url.trim().replace(/\/+$/, "");
    const token = await vscode.window.showInputBox({
      title: "eVal: Sign In (2/2)", prompt: "API token (create one under Settings → API tokens in eVal)",
      password: true, ignoreFocusOut: true, placeHolder: "evl_…",
      validateInput: (v) => v.trim().startsWith("evl_") ? undefined : "eVal API tokens start with evl_",
    });
    if (!token) return;
    const me = await new EvalClient(serverUrl, token.trim()).me();
    if (serverUrl !== this.serverUrl()) {
      await this.config().update("serverUrl", serverUrl, vscode.ConfigurationTarget.Global);
    }
    await this.context.secrets.store(this.secretKey(), token.trim());
    this.setView({ kind: "unlinked" });
    void vscode.window.showInformationMessage(
      `eVal: signed in as ${me.user.email} in ${me.organization.name} (${me.role}).`);
    if (this.link() || await this.linkRepository(true)) await this.refresh(true);
  }

  private async signOut(): Promise<void> {
    await this.context.secrets.delete(this.secretKey());
    this.clear();
    this.setView({ kind: "signedOut" });
    void vscode.window.showInformationMessage("eVal: signed out. The API token was removed from this machine.");
  }

  /** Link the workspace to an eVal repository, matching git remotes against GitHub ``owner/name``. */
  private async linkRepository(interactive: boolean): Promise<boolean> {
    const client = await this.client(interactive);
    if (!client) return false;
    const gitRepo = this.gitRepoFor();
    const folder = vscode.workspace.workspaceFolders?.[0]?.uri;
    const root = gitRepo?.rootUri ?? folder;
    if (!root) {
      if (interactive) void vscode.window.showWarningMessage("eVal: open a folder first.");
      return false;
    }
    // Git remotes when the git extension is available; the workspace URI itself in vscode.dev / github.dev.
    const names = [...(gitRepo ? remoteUrls(gitRepo).map(fullNameFromRemote) : []),
      folder ? fullNameFromWorkspaceUri(folder) : null];
    const remotes = new Set(names.filter((n): n is string => !!n).map((n) => n.toLowerCase()));
    const repos = (await client.projects()).flatMap((p) => p.repositories.map((r) => ({ project: p.name, repo: r })));
    const matches = repos.filter(({ repo }) => repo.source === "github" && remotes.has(repo.full_name.toLowerCase()));

    let chosen: Repository | undefined;
    if (!interactive) {
      if (matches.length !== 1) {
        this.setView({ kind: "unlinked" });
        return false;
      }
      chosen = matches[0].repo;
    } else {
      if (!repos.length) {
        void vscode.window.showWarningMessage("eVal: this organization has no repositories yet. Connect one in eVal first.");
        return false;
      }
      const matched = new Set(matches.map((m) => m.repo.id));
      const items = [...repos].sort((a, b) => Number(matched.has(b.repo.id)) - Number(matched.has(a.repo.id)))
        .map(({ project, repo }) => ({
          label: `${matched.has(repo.id) ? "$(check) " : ""}${repo.name}`,
          description: repo.source === "github" ? repo.full_name : "uploaded archive",
          detail: `Project: ${project}${matched.has(repo.id) ? " · matches this workspace's git remote" : ""}`,
          repo,
        }));
      const pick = await vscode.window.showQuickPick(items, {
        title: "eVal: Link this workspace to a repository", matchOnDescription: true, ignoreFocusOut: true,
      });
      chosen = pick?.repo;
    }
    if (!chosen) return false;
    await this.context.workspaceState.update(LINK_KEY, {
      repoId: chosen.id, name: chosen.name, fullName: chosen.full_name, source: chosen.source, root: root.toString(),
    } satisfies Link);
    this.output.appendLine(`Linked ${root.fsPath} to eVal repository ${chosen.name} (${chosen.id}).`);
    return true;
  }

  private async requireLink(): Promise<{ client: EvalClient; link: Link } | undefined> {
    const client = await this.client(true);
    if (!client) return undefined;
    if (!this.link() && !(await this.linkRepository(true))) return undefined;
    return { client, link: this.link()! };
  }

  /** Load the audit that best matches the checked-out commit and show its open findings. */
  private async refresh(interactive: boolean): Promise<void> {
    const ctx = interactive ? await this.requireLink() : await this.silentContext();
    if (!ctx) return;
    const seq = ++this.loadSeq;
    this.setView({ kind: "loading" });
    const { branch, commit } = this.head();
    const { repository, audits } = await ctx.client.repository(ctx.link.repoId);
    // Without git (virtual workspaces) the branch is unknown; prefer the default branch's audits.
    const chosen = pickAudit(audits, branch ?? repository.default_branch, commit);
    if (seq !== this.loadSeq) return;
    if (!chosen) {
      this.clear();
      this.setView({ kind: "noAudit" });
      if (interactive) {
        const pick = await vscode.window.showInformationMessage(
          `eVal: ${ctx.link.name} has no finished audit yet.`, "Run Audit");
        if (pick === "Run Audit") await this.runAudit();
      }
      return;
    }
    await this.load(ctx.client, chosen.id, seq);
    if (interactive && chosen.commit_sha !== commit && commit) {
      void vscode.window.showInformationMessage(
        `eVal: showing the audit of ${chosen.branch}@${chosen.commit_sha.slice(0, 7)}; your checkout is at ` +
        `${commit.slice(0, 7)}, so some line numbers may be off.`, "Run Audit").then((p) => {
        if (p === "Run Audit") void this.run(() => this.runAudit());
      });
    }
  }

  private async silentContext(): Promise<{ client: EvalClient; link: Link } | undefined> {
    const client = await this.client(false);
    const link = this.link();
    if (!client) return undefined;
    if (!link) {
      this.setView({ kind: "unlinked" });
      return undefined;
    }
    return { client, link };
  }

  private async load(client: EvalClient, auditId: string, seq = ++this.loadSeq): Promise<void> {
    this.setView({ kind: "loading" });
    const [audit, findings] = await Promise.all([client.audit(auditId), client.findings(auditId)]);
    if (seq !== this.loadSeq) return;
    this.audit = audit;
    this.findings = findings;
    this.render();
    this.output.appendLine(`Loaded audit ${audit.id} (${audit.branch}@${audit.commit_sha.slice(0, 7)}): ` +
      `${findings.length} open finding(s).`);
    if (this.repoLevel.length) {
      this.output.appendLine("Repository-level findings (no file):");
      for (const f of this.repoLevel) this.output.appendLine(`  [${f.severity}] ${f.title} — ${this.findingUrl(f.id)}`);
    }
  }

  private async runAudit(): Promise<void> {
    const ctx = await this.requireLink();
    if (!ctx) return;
    if (ctx.link.source !== "github") {
      void vscode.window.showWarningMessage(
        `eVal: ${ctx.link.name} is an uploaded repository. Upload a new archive from the eVal web UI or CLI.`);
      return;
    }
    const { branch, commit, ahead } = this.head();
    const ref = branch || commit || "";
    if (ahead && ahead > 0) {
      const go = await vscode.window.showWarningMessage(
        `eVal audits what is on GitHub. ${ahead} local commit(s) on ${branch} are not pushed and will not be audited.`,
        { modal: true }, "Audit Anyway");
      if (go !== "Audit Anyway") return;
    }
    const started = await ctx.client.startAudit(ctx.link.repoId, ref);
    this.output.appendLine(`Started audit ${started.id} of ${ctx.link.name}@${ref || "default branch"}.`);
    const final = await vscode.window.withProgress({
      location: vscode.ProgressLocation.Notification, cancellable: true,
      title: `eVal: auditing ${ctx.link.name}${ref ? `@${ref}` : ""}`,
    }, async (progress, token) => {
      let audit = started;
      let shown = 0;
      while (!TERMINAL_STATUSES.has(audit.status)) {
        if (token.isCancellationRequested) return undefined;
        await new Promise((r) => setTimeout(r, POLL_MS));
        audit = await ctx.client.audit(audit.id);
        const pct = Math.max(0, Math.min(100, audit.progress || 0));
        progress.report({ increment: Math.max(0, pct - shown), message: `${audit.stage || audit.status} (${pct}%)` });
        shown = Math.max(shown, pct);
      }
      return audit;
    });
    if (!final) {
      const pick = await vscode.window.showInformationMessage(
        "eVal: stopped watching. The audit keeps running on the server; use 'eVal: Load Latest Findings' later.",
        "Open in Browser");
      if (pick) await vscode.env.openExternal(vscode.Uri.parse(started.url));
      return;
    }
    if (final.status !== "succeeded") {
      const pick = await vscode.window.showErrorMessage(
        `eVal: audit ${final.status}${final.error ? `: ${final.error}` : ""}.`, "Open in Browser");
      if (pick) await vscode.env.openExternal(vscode.Uri.parse(final.url));
      return;
    }
    await this.load(ctx.client, final.id);
    const counts = SEVERITIES.map((s) => `${final.severity_counts?.[s] ?? 0} ${s}`).join(", ");
    const pick = await vscode.window.showInformationMessage(
      `eVal: score ${final.overall_score ?? "–"} (${final.risk_level ?? "n/a"}). ${counts}.`, "Open in Browser");
    if (pick) await vscode.env.openExternal(vscode.Uri.parse(final.url));
  }

  private async openAudit(): Promise<void> {
    if (!this.audit) {
      void vscode.window.showInformationMessage("eVal: no audit loaded. Run 'eVal: Load Latest Findings' first.");
      return;
    }
    await vscode.env.openExternal(vscode.Uri.parse(this.audit.url));
  }

  private findingUrl(id: string): string {
    return this.audit ? this.audit.url.replace(/\/audits\/[^/?#]+.*$/, `/findings/${encodeURIComponent(id)}`) : "";
  }

  private async openFinding(id: string): Promise<void> {
    const url = this.findingUrl(id);
    if (url) await vscode.env.openExternal(vscode.Uri.parse(url));
  }

  /** Pick one of the repository's fix proposals, or take the id from a pasted fix link. */
  private async chooseFix(client: EvalClient, link: Link): Promise<string | undefined> {
    const fixes = (await client.fixes(link.repoId)).filter((f) => f.status === "ready" || f.status === "pr_opened");
    const verdicts: Record<string, string> = {
      passed: "verified by re-audit", partial: "partially verified", regressed: "re-audit found new problems",
      incomplete: "verification incomplete", error: "not verified",
    };
    const describe = (f: FixSummary) => [
      `${f.fixed} finding(s) fixed`, f.verdict ? verdicts[f.verdict] ?? f.verdict : "not verified",
      f.edited ? `edited by hand (revision ${f.revision})` : "", f.status === "pr_opened" ? "pull request opened" : "",
    ].filter(Boolean).join(" · ");
    const items = [
      ...fixes.map((f) => ({
        label: `$(sparkle) ${f.files.join(", ")}`, description: `${f.branch}@${f.commit_sha.slice(0, 7)}`,
        detail: `${describe(f)} · ${new Date(f.created_at).toLocaleString()}`, id: f.id,
      })),
      { label: "$(link) Paste a fix link…", description: "", detail: "From the fix page in eVal", id: "" },
    ];
    const pick = await vscode.window.showQuickPick(items, {
      title: `eVal: Apply a fix proposal to ${link.name}`, matchOnDescription: true, matchOnDetail: true,
      placeHolder: fixes.length ? "Newest first" : "No generated fixes for this repository yet",
    });
    if (!pick) return undefined;
    if (pick.id) return pick.id;
    const pasted = await vscode.window.showInputBox({
      title: "eVal: Apply Fix Proposal", prompt: "Fix link from eVal (…/fixes/<id>) or the fix id", ignoreFocusOut: true,
      validateInput: (v) => parseFixRef(v) ? undefined : "Paste the link of an eVal fix page",
    });
    return pasted ? parseFixRef(pasted) : undefined;
  }

  /**
   * Apply an eVal fix proposal to the working tree. All files are patched or none: each change must still match the
   * local file. VS Code's refactor preview shows the edits before anything is written, and nothing is saved.
   */
  private async applyFix(ref?: string): Promise<void> {
    const ctx = await this.requireLink();
    if (!ctx) return;
    const id = ref ? parseFixRef(ref) : await this.chooseFix(ctx.client, ctx.link);
    if (ref && !id) throw new Error("That is not an eVal fix link or id.");
    if (!id) return;
    const fix = await ctx.client.fix(id);
    const openInEval = async (message: string, error = true) => {
      const text = `eVal: ${message}`;
      const pick = error ? await vscode.window.showErrorMessage(text, "Open Fix in eVal")
        : await vscode.window.showInformationMessage(text, "Open Fix in eVal");
      if (pick) await vscode.env.openExternal(vscode.Uri.parse(fix.url));
    };
    if (fix.repository_id !== ctx.link.repoId) {
      return openInEval(`this fix belongs to another repository than ${ctx.link.name}. Open that repository first.`);
    }
    if (fix.status !== "ready" && fix.status !== "pr_opened") {
      return openInEval(fix.status === "verifying" ? "this fix is being re-audited. Try again in a moment."
        : `this fix is ${fix.status}${fix.error ? `: ${fix.error}` : ""}.`);
    }
    const { branch } = this.head();
    if (fix.fix_branch && branch === fix.fix_branch) {
      return openInEval(`the checked-out branch ${branch} already contains this fix.`, false);
    }
    if (fix.verdict === "regressed") {
      const go = await vscode.window.showWarningMessage(
        "eVal's re-audit found new problems in this fix. Apply it anyway?", { modal: true }, "Apply Anyway");
      if (go !== "Apply Anyway") return;
    }

    const root = vscode.Uri.parse(ctx.link.root);
    const edit = new vscode.WorkspaceEdit();
    const problems: string[] = [];
    for (const p of fix.patches) {
      const uri = vscode.Uri.joinPath(root, ...p.path.split("/"));
      let doc: vscode.TextDocument;
      try {
        doc = await vscode.workspace.openTextDocument(uri);
      } catch {
        problems.push(`${p.path}: not found in this workspace`);
        continue;
      }
      try {
        const before = doc.getText();
        edit.replace(uri, new vscode.Range(doc.positionAt(0), doc.positionAt(before.length)), applyPatch(before, p.diff),
          { needsConfirmation: true, label: `eVal fix: ${p.path}` });
      } catch (err) {
        if (!(err instanceof PatchError)) throw err;
        problems.push(`${p.path}: ${err.message}`);
      }
    }
    if (problems.length) {
      problems.forEach((p) => this.output.appendLine(`[apply fix ${fix.id}] ${p}`));
      return openInEval(`the fix does not apply to your checkout (${problems[0]}` +
        `${problems.length > 1 ? `, and ${problems.length - 1} more; see the eVal log` : ""}). It was made for ` +
        `${fix.branch}@${fix.commit_sha.slice(0, 7)}; nothing was changed.`);
    }
    if (!(await vscode.workspace.applyEdit(edit))) return; // discarded in the preview
    this.output.appendLine(`Applied fix ${fix.id} (revision ${fix.revision}) to ${fix.patches.length} file(s).`);
    const virtual = root.scheme === "vscode-vfs"; // vscode.dev / github.dev: an editor without a terminal
    const pick = await vscode.window.showInformationMessage(
      `eVal: applied the fix to ${fix.patches.length} file(s); they are not saved yet. ` +
      (virtual ? "This editor has no terminal: commit to a branch and let CI (or a codespace) run your tests."
        : "Save, run your tests in the terminal, then commit."),
      ...(virtual ? [] : ["Open Terminal"]), "Open Fix in eVal");
    if (pick === "Open Terminal") await vscode.commands.executeCommand("workbench.action.terminal.new");
    else if (pick) await vscode.env.openExternal(vscode.Uri.parse(fix.url));
  }

  private async triage(id: string, status: TriageStatus): Promise<void> {
    const finding = this.findings.find((f) => f.id === id);
    const client = await this.client(true);
    if (!finding || !client) return;
    let decision: { status: TriageStatus; reason?: string; owner?: string; expires_on?: string } = { status };
    if (status === "false_positive" || status === "accepted_risk") {
      const accepted = status === "accepted_risk";
      const reason = await vscode.window.showInputBox({
        title: `${accepted ? "Accept risk" : "False positive"}: ${finding.title}`, ignoreFocusOut: true,
        prompt: accepted ? "Why is this risk acceptable for now?" : "Why is this not a real issue?",
        validateInput: (v) => v.trim().length >= (accepted ? 10 : 1) ? undefined
          : accepted ? "At least 10 characters" : "A reason is required",
      });
      if (!reason) return;
      decision = { ...decision, reason: reason.trim() };
      if (accepted) {
        const owner = await vscode.window.showInputBox({
          title: "Accept risk: owner", prompt: "Team or vendor that owns the fix", ignoreFocusOut: true,
          validateInput: (v) => v.trim() ? undefined : "An owner is required",
        });
        if (!owner) return;
        const expires = await vscode.window.showInputBox({
          title: "Accept risk: review date", prompt: "Date the finding reopens (YYYY-MM-DD, at most a year out)",
          value: isoDateAfter(90), ignoreFocusOut: true,
          validateInput: (v) => /^\d{4}-\d{2}-\d{2}$/.test(v.trim()) ? undefined : "Use YYYY-MM-DD",
        });
        if (!expires) return;
        decision = { ...decision, owner: owner.trim(), expires_on: expires.trim() };
      }
    }
    await client.triage(id, decision);
    this.findings = this.findings.filter((f) => f.id !== id);
    this.render();
    const label = { accepted_risk: "accepted risk", false_positive: "false positive", fixed: "fixed", open: "open" }[status];
    const pick = await vscode.window.showInformationMessage(`eVal: marked "${finding.title}" as ${label}.`, "Undo");
    if (pick === "Undo") {
      await client.triage(id, { status: "open" });
      this.findings.push(finding);
      this.render();
    }
  }

  private clear(): void {
    this.loadSeq++;
    this.audit = undefined;
    this.findings = [];
    this.render();
    if (this.view.kind === "loaded") this.setView({ kind: "noAudit" });
  }

  private async menu(): Promise<void> {
    const signedIn = !!(await this.token());
    const items: Array<vscode.QuickPickItem & { command: string }> = signedIn ? [
      { label: "$(refresh) Load latest findings", command: "eval.refresh" },
      { label: "$(play) Run audit on current branch", command: "eval.runAudit" },
      ...(this.audit ? [{ label: "$(link-external) Open audit in browser", command: "eval.openAudit" }] : []),
      { label: "$(sparkle) Apply fix proposal…", command: "eval.applyFix" },
      { label: "$(repo) Link workspace to repository…", command: "eval.linkRepository",
        description: this.link()?.name },
      { label: "$(clear-all) Clear findings", command: "eval.clear" },
      { label: "$(output) Show log", command: "eval.showLog" },
      { label: "$(sign-out) Sign out", command: "eval.signOut", description: this.serverUrl() },
    ] : [{ label: "$(sign-in) Sign in…", command: "eval.signIn" }];
    const pick = await vscode.window.showQuickPick(items, { title: "eVal" });
    if (pick?.command === "eval.showLog") this.output.show();
    else if (pick) await vscode.commands.executeCommand(pick.command);
  }

  // ------------------------------------------------------------------------------------------- rendering

  private render(): void {
    this.diagnostics.clear();
    this.byUri.clear();
    this.repoLevel = [];
    const link = this.link();
    if (!this.audit || !link) return;
    const root = vscode.Uri.parse(link.root);
    const minimum = this.config().get<Severity>("minimumSeverity", "info");
    for (const [path, items] of groupByFile(this.findings, minimum)) {
      if (path === null) {
        this.repoLevel = items;
        continue;
      }
      const uri = vscode.Uri.joinPath(root, ...path.split("/"));
      this.byUri.set(uri.toString(), items);
      this.diagnostics.set(uri, items.map((f) => this.toDiagnostic(f)));
    }
    this.setView({ kind: "loaded" });
  }

  private toDiagnostic(f: Finding): vscode.Diagnostic {
    const { start, end } = lineSpan(f);
    const d = new vscode.Diagnostic(new vscode.Range(start, 0, end, Number.MAX_SAFE_INTEGER), diagnosticMessage(f),
      SEVERITY_LEVEL[levelFor(f.severity)]);
    d.source = SOURCE;
    const url = this.findingUrl(f.id);
    d.code = url ? { value: f.rule_id, target: vscode.Uri.parse(url) } : f.rule_id;
    return d;
  }

  private findingsAt(doc: vscode.TextDocument, from: number, to: number): Finding[] {
    return (this.byUri.get(doc.uri.toString()) || []).filter((f) => {
      const { start, end } = lineSpan(f);
      return start <= to && end >= from;
    });
  }

  private hover(doc: vscode.TextDocument, pos: vscode.Position): vscode.Hover | undefined {
    const items = this.findingsAt(doc, pos.line, pos.line);
    if (!items.length) return undefined;
    const md = new vscode.MarkdownString(items.map((f) => hoverMarkdown(f, this.findingUrl(f.id))).join("\n\n---\n\n"));
    return new vscode.Hover(md);
  }

  private codeActions(doc: vscode.TextDocument, range: vscode.Range | vscode.Selection,
    context: vscode.CodeActionContext): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];
    for (const f of this.findingsAt(doc, range.start.line, range.end.line)) {
      const related = context.diagnostics.filter((d) => d.source === SOURCE && d.range.start.line === lineSpan(f).start);
      const add = (title: string, command: string, args: unknown[], preferred = false) => {
        const a = new vscode.CodeAction(title, vscode.CodeActionKind.QuickFix);
        a.command = { title, command, arguments: args };
        a.diagnostics = related;
        a.isPreferred = preferred;
        actions.push(a);
      };
      const short = f.title.length > 60 ? `${f.title.slice(0, 57)}…` : f.title;
      add(`eVal: Open "${short}" in eVal`, "eval.openFinding", [f.id]);
      add(`eVal: Mark "${short}" as fixed`, "eval.triage", [f.id, "fixed"]);
      add(`eVal: Mark "${short}" as false positive…`, "eval.triage", [f.id, "false_positive"]);
      add(`eVal: Accept risk for "${short}"…`, "eval.triage", [f.id, "accepted_risk"]);
    }
    return actions;
  }

  private setView(view: View): void {
    this.view = view;
    const s = this.status;
    s.backgroundColor = undefined;
    switch (view.kind) {
      case "signedOut":
        s.text = "$(shield) eVal: Sign in";
        s.tooltip = "Sign in to eVal with an API token";
        break;
      case "unlinked":
        s.text = "$(shield) eVal: Link repository";
        s.tooltip = "Link this workspace to an eVal repository";
        break;
      case "loading":
        s.text = "$(sync~spin) eVal";
        s.tooltip = "Loading findings…";
        break;
      case "noAudit":
        s.text = "$(shield) eVal: no audit";
        s.tooltip = `No finished audit for ${this.link()?.name ?? "this repository"}. Click to run one.`;
        break;
      case "error":
        s.text = "$(error) eVal";
        s.tooltip = view.message;
        s.backgroundColor = new vscode.ThemeColor("statusBarItem.errorBackground");
        break;
      case "loaded": {
        const a = this.audit!;
        const { commit } = this.head();
        const stale = !!commit && a.commit_sha !== commit;
        s.text = `$(shield) eVal ${a.overall_score ?? "–"}${a.risk_level ? ` · ${a.risk_level}` : ""}` +
          `${stale ? " $(history)" : ""}`;
        const md = new vscode.MarkdownString();
        md.appendMarkdown(`**eVal · ${this.link()?.name}**\n\n`);
        md.appendMarkdown(`Audit of \`${a.branch}@${a.commit_sha.slice(0, 7)}\`` +
          `${a.finished_at ? `, ${new Date(a.finished_at).toLocaleString()}` : ""}\n\n`);
        if (stale) md.appendMarkdown(`$(history) Your checkout is at \`${commit!.slice(0, 7)}\`; lines may be off.\n\n`);
        md.appendMarkdown(SEVERITIES.map((sev) => `${sev}: ${a.severity_counts?.[sev] ?? 0}`).join(" · ") + "\n\n");
        md.appendMarkdown(`${this.findings.length} open finding(s) shown` +
          `${this.repoLevel.length ? `, ${this.repoLevel.length} repository-level (see the eVal log)` : ""}.`);
        if (a.gate) md.appendMarkdown(`\n\nGate: ${a.gate.passed ? "passed" : `**failed**: ${a.gate.reasons.join("; ")}`}`);
        md.supportThemeIcons = true;
        s.tooltip = md;
        break;
      }
    }
  }
}
