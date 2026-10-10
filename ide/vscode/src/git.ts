/** Minimal typing of the built-in vscode.git extension API (v1) — only what eVal uses. */

import * as vscode from "vscode";

export interface GitRepository {
  readonly rootUri: vscode.Uri;
  readonly state: {
    readonly HEAD: { readonly name?: string; readonly commit?: string; readonly ahead?: number } | undefined;
    readonly remotes: ReadonlyArray<{ readonly name: string; readonly fetchUrl?: string; readonly pushUrl?: string }>;
    readonly onDidChange: vscode.Event<void>;
  };
}

export interface GitApi {
  readonly repositories: GitRepository[];
  getRepository(uri: vscode.Uri): GitRepository | null;
  readonly onDidOpenRepository: vscode.Event<GitRepository>;
}

export async function getGitApi(): Promise<GitApi | undefined> {
  const ext = vscode.extensions.getExtension<{ getAPI(version: 1): GitApi }>("vscode.git");
  if (!ext) return undefined;
  try {
    const exports = ext.isActive ? ext.exports : await ext.activate();
    return exports.getAPI(1);
  } catch {
    return undefined;
  }
}

/** Remote URLs, ``origin`` first. */
export function remoteUrls(repo: GitRepository): string[] {
  const remotes = [...repo.state.remotes].sort((a, b) => Number(b.name === "origin") - Number(a.name === "origin"));
  return remotes.flatMap((r) => [r.fetchUrl, r.pushUrl]).filter((u): u is string => !!u);
}
