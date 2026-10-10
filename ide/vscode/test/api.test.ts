import * as assert from "node:assert/strict";
import { test } from "node:test";

import { ApiError, Audit, EvalClient, pickAudit } from "../src/api";

type Call = { url: string; init?: RequestInit };

function fakeFetch(responses: Array<{ status: number; body: unknown }>, calls: Call[]) {
  return async (url: string, init?: RequestInit) => {
    calls.push({ url, init });
    const r = responses.shift()!;
    return new Response(typeof r.body === "string" ? r.body : JSON.stringify(r.body), { status: r.status });
  };
}

test("sends the bearer token and walks every findings page", async () => {
  const calls: Call[] = [];
  const client = new EvalClient("https://eval.example.com/", "evl_x", fakeFetch([
    { status: 200, body: { findings: [{ id: "a" }], page: 1, pages: 2, total: 2 } },
    { status: 200, body: { findings: [{ id: "b" }], page: 2, pages: 2, total: 2 } },
  ], calls));
  const items = await client.findings("A1");
  assert.deepEqual(items.map((f) => f.id), ["a", "b"]);
  assert.equal(calls[0].url, "https://eval.example.com/api/v1/audits/A1/findings?triage=open&page=1");
  assert.equal(calls[1].url, "https://eval.example.com/api/v1/audits/A1/findings?triage=open&page=2");
  assert.equal((calls[0].init!.headers as Record<string, string>).Authorization, "Bearer evl_x");
});

test("triage posts JSON", async () => {
  const calls: Call[] = [];
  const client = new EvalClient("http://h", "evl_x", fakeFetch([{ status: 200, body: { finding: { id: "f" } } }], calls));
  await client.triage("f", { status: "false_positive", reason: "test fixture" });
  assert.equal(calls[0].init!.method, "POST");
  assert.equal(calls[0].url, "http://h/api/v1/findings/f/triage");
  assert.deepEqual(JSON.parse(calls[0].init!.body as string), { status: "false_positive", reason: "test fixture" });
});

test("server errors surface the JSON error message and status", async () => {
  const client = new EvalClient("http://h", "evl_x", fakeFetch([{ status: 422, body: { error: "Reason too short." } }], []));
  await assert.rejects(client.triage("f", { status: "accepted_risk" }),
    (e: unknown) => e instanceof ApiError && e.status === 422 && e.message === "Reason too short.");
});

test("401 without a body gets a sign-in hint; HTML responses are rejected", async () => {
  const client = new EvalClient("http://h", "evl_x", fakeFetch([
    { status: 401, body: "" }, { status: 200, body: "<html>login</html>" },
  ], []));
  await assert.rejects(client.me(), (e: unknown) => e instanceof ApiError && /Sign In/.test(e.message));
  await assert.rejects(client.me(), (e: unknown) => e instanceof ApiError && /non-JSON/.test(e.message));
});

test("network failures become ApiError status 0", async () => {
  const client = new EvalClient("http://h", "evl_x", async () => { throw new Error("ECONNREFUSED"); });
  await assert.rejects(client.me(), (e: unknown) => e instanceof ApiError && e.status === 0);
});

test("default fetch is not invoked as a method of the client (browser 'Illegal invocation')", async () => {
  const original = globalThis.fetch;
  globalThis.fetch = function (this: unknown) {
    if (this !== undefined && this !== globalThis) throw new TypeError("Illegal invocation");
    return Promise.resolve(new Response(JSON.stringify({ projects: [] }), { status: 200 }));
  } as typeof fetch;
  try {
    assert.deepEqual(await new EvalClient("http://h", "evl_x").projects(), []);
  } finally {
    globalThis.fetch = original;
  }
});

function audit(id: string, o: Partial<Audit>): Audit {
  return { id, status: "succeeded", branch: "main", commit_sha: `sha-${id}`, pr_number: null, ...o } as Audit;
}

test("pickAudit prefers the checked-out commit, then branch, then newest", () => {
  const audits = [
    audit("running", { status: "running", branch: "feat", commit_sha: "HEAD" }),
    audit("pr", { branch: "feat", pr_number: 5, commit_sha: "pr-head" }),
    audit("main2", { branch: "main" }),
    audit("feat1", { branch: "feat", commit_sha: "old" }),
    audit("exact", { branch: "feat", commit_sha: "HEAD" }),
  ];
  assert.equal(pickAudit(audits, "feat", "HEAD")!.id, "exact");
  assert.equal(pickAudit(audits, "feat", "pr-head")!.id, "pr");
  assert.equal(pickAudit(audits, "feat", "unknown")!.id, "feat1");
  assert.equal(pickAudit(audits, "other", undefined)!.id, "main2");
  assert.equal(pickAudit([audit("x", { status: "failed" })], "main", undefined), undefined);
});
