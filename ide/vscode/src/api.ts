/** Client for the eVal JSON API v1 (docs/API.md). No VS Code imports, so it can be unit-tested under plain Node. */

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type TriageStatus = "open" | "accepted_risk" | "false_positive" | "fixed";

export interface Me {
  organization: { id: string; slug: string; name: string };
  user: { id: string; email: string };
  role: string;
  token: { name: string; prefix: string };
}

export interface Repository {
  id: string;
  project_id: string;
  name: string;
  source: "github" | "upload";
  full_name: string;
  default_branch: string;
  has_credential: boolean;
}

export interface Project {
  id: string;
  name: string;
  slug: string;
  repositories: Repository[];
}

export interface Audit {
  id: string;
  repository_id: string;
  status: "queued" | "running" | "succeeded" | "failed" | "cancelled" | string;
  stage: string;
  progress: number;
  error: string;
  branch: string;
  commit_sha: string;
  pr_number: number | null;
  overall_score: number | null;
  risk_level: string | null;
  severity_counts: Partial<Record<Severity, number>>;
  created_at: string;
  finished_at: string | null;
  url: string;
  gate?: { passed: boolean; fail_on: string; blocking: number; reasons: string[] };
}

export interface AiExplanation {
  explanation?: string;
  remediation_steps?: string[];
  suggested_patch?: string;
  false_positive_likelihood?: string;
  model?: string;
}

export interface Finding {
  id: string;
  rule_id: string;
  fingerprint: string;
  title: string;
  category: string;
  severity: Severity;
  confidence: string;
  kind: string;
  description: string;
  remediation: string;
  file_path: string | null;
  line_start: number | null;
  line_end: number | null;
  evidence: string;
  sources: string[];
  references: string[];
  lifecycle: string;
  triage_status: TriageStatus;
  ai_explanation: AiExplanation;
  compliance?: Record<string, string[] | string>;
  reachability?: string | null;
}

export interface TriageDecision {
  status: TriageStatus;
  reason?: string;
  owner?: string;
  expires_on?: string;
}

export const TERMINAL_STATUSES = new Set(["succeeded", "failed", "cancelled"]);

/** Upper bound on pages fetched for one audit (50 findings per page server-side). */
const MAX_PAGES = 100;

export class ApiError extends Error {
  constructor(public readonly status: number, message: string) {
    super(message);
    this.name = "ApiError";
  }
}

type FetchLike = (url: string, init?: RequestInit) => Promise<Response>;

export class EvalClient {
  readonly baseUrl: string;

  // The default wraps the global so it is not called with the client as `this` (an "Illegal invocation" in browsers).
  constructor(baseUrl: string, private readonly token: string,
    private readonly fetchImpl: FetchLike = (url, init) => fetch(url, init)) {
    this.baseUrl = baseUrl.replace(/\/+$/, "");
  }

  private async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    const headers: Record<string, string> = { Authorization: `Bearer ${this.token}`, Accept: "application/json" };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    let res: Response;
    try {
      res = await this.fetchImpl(`${this.baseUrl}/api/v1${path}`, {
        method, headers, body: body === undefined ? undefined : JSON.stringify(body),
      });
    } catch (err) {
      throw new ApiError(0, `Cannot reach eVal at ${this.baseUrl}: ${(err as Error).message}`);
    }
    const text = await res.text();
    let data: any;
    try {
      data = text ? JSON.parse(text) : {};
    } catch {
      data = undefined;
    }
    if (!res.ok) throw new ApiError(res.status, data?.error ?? describeStatus(res.status));
    if (data === undefined) throw new ApiError(res.status, "eVal returned a non-JSON response. Check eval.serverUrl.");
    return data as T;
  }

  me(): Promise<Me> {
    return this.request<Me>("GET", "/me");
  }

  async projects(): Promise<Project[]> {
    return (await this.request<{ projects: Project[] }>("GET", "/projects")).projects;
  }

  repository(repoId: string): Promise<{ repository: Repository; audits: Audit[] }> {
    return this.request("GET", `/repositories/${encodeURIComponent(repoId)}`);
  }

  async startAudit(repoId: string, ref: string): Promise<Audit> {
    return (await this.request<{ audit: Audit }>("POST", `/repositories/${encodeURIComponent(repoId)}/audits`,
      { ref })).audit;
  }

  async audit(auditId: string): Promise<Audit> {
    return (await this.request<{ audit: Audit }>("GET", `/audits/${encodeURIComponent(auditId)}`)).audit;
  }

  /** All open findings of a succeeded audit, across pages. */
  async findings(auditId: string): Promise<Finding[]> {
    const all: Finding[] = [];
    for (let page = 1; page <= MAX_PAGES; page++) {
      const res = await this.request<{ findings: Finding[]; page: number; pages: number }>(
        "GET", `/audits/${encodeURIComponent(auditId)}/findings?triage=open&page=${page}`);
      all.push(...res.findings);
      if (page >= res.pages) break;
    }
    return all;
  }

  async triage(findingId: string, decision: TriageDecision): Promise<Finding> {
    return (await this.request<{ finding: Finding }>("POST", `/findings/${encodeURIComponent(findingId)}/triage`,
      decision)).finding;
  }
}

function describeStatus(status: number): string {
  switch (status) {
    case 401: return "eVal rejected the API token (missing, revoked, or no longer a member). Run 'eVal: Sign In'.";
    case 403: return "Your role in this organization does not allow this action (member role required).";
    case 404: return "Not found in this token's organization.";
    case 409: return "The audit has not finished.";
    case 429: return "Rate limited by eVal. Try again in a minute.";
    default: return `eVal request failed (HTTP ${status}).`;
  }
}

/**
 * Pick the audit whose findings best describe the working tree: a succeeded audit of the checked-out commit, else
 * the newest succeeded audit of the branch, else the newest succeeded audit of any branch. ``audits`` is newest first.
 */
export function pickAudit(audits: Audit[], branch: string | undefined, commit: string | undefined): Audit | undefined {
  const done = audits.filter((a) => a.status === "succeeded");
  const full = done.filter((a) => !a.pr_number);
  return (commit && done.find((a) => a.commit_sha === commit))
    || (branch && full.find((a) => a.branch === branch))
    || full[0];
}
