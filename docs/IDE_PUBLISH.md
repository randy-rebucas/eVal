# Publish the VS Code extension: step-by-step

This guide takes the extension in `ide/vscode` from the repository to the two public extension registries, so
anyone can install `randy-rebucas.eval-auditor` by name in VS Code, Codespaces, Gitpod, code-server and
vscode.dev. The first release takes about 45 minutes, most of it account setup. After that, a release is a version
bump and a git tag.

What the extension does and how it works in each IDE is in [ide/vscode/README.md](../ide/vscode/README.md).

## What you will end up with

| Where | Listing | Used by |
|---|---|---|
| Visual Studio Marketplace | `marketplace.visualstudio.com/items?itemName=randy-rebucas.eval-auditor` | VS Code desktop, GitHub Codespaces, vscode.dev / github.dev, Dev Containers |
| Open VSX | `open-vsx.org/extension/randy-rebucas/eval-auditor` | Gitpod, code-server, VSCodium, Eclipse Theia |
| GitHub Releases | `vscode-v<version>` release with the `.vsix` attached | Manual installs, air-gapped machines |

Publishing is done by the GitHub Actions workflow
[.github/workflows/release-vscode.yml](../.github/workflows/release-vscode.yml). It runs when you push a tag named
`vscode-v<version>`. It checks that the tag matches the version in `package.json`, runs the extension tests,
builds the `.vsix`, publishes it to both registries, and creates the GitHub release.

| Fixed value | Where it is set |
|---|---|
| Publisher / namespace `randy-rebucas` | `ide/vscode/package.json` → `publisher` |
| Extension name `eval-auditor` | `ide/vscode/package.json` → `name` |
| License: proprietary, free to use | `ide/vscode/LICENSE.md` |

The extension ID `randy-rebucas.eval-auditor` is permanent. Changing the publisher or name later creates a
different extension; existing users do not move over.

## Before you start

- [ ] Admin access to the GitHub repository `randy-rebucas/eVal` (to add environments and secrets)
- [ ] A Microsoft account (personal or work) for the Marketplace
- [ ] A GitHub account for Open VSX (it signs in with GitHub)
- [ ] Node.js 18 or later on your computer, for one command in step 3 and for local checks
- [ ] 45 minutes

---

## One-time setup

### Step 1: Create the Marketplace publisher

1. Go to https://marketplace.visualstudio.com/manage and sign in with your Microsoft account.
2. Click **Create publisher**.
3. Set **ID** to `randy-rebucas` and **Name** to how you want to appear on the listing (for example
   `Randy Rebucas`). The ID cannot be changed later.
4. Click **Create**.

If the ID `randy-rebucas` is taken, choose another, then change `"publisher"` in `ide/vscode/package.json` and
the extension ID in `ide/vscode/README.md` to match before you release.

### Step 2: Create the Marketplace token (`VSCE_PAT`)

The Marketplace accepts Azure DevOps personal access tokens.

1. Go to https://dev.azure.com and sign in with the **same** Microsoft account as in step 1. If you have no Azure
   DevOps organization, it asks you to create one; any name works, and it costs nothing.
2. Open **User settings** (the person icon, top right) → **Personal access tokens** → **New Token**.
3. Fill in:

   | Field | Value |
   |---|---|
   | Name | `eval-vscode-marketplace` |
   | Organization | **All accessible organizations** (a single organization does not work for the Marketplace) |
   | Expiration | Custom, up to one year. Write the date in your calendar |
   | Scopes | **Custom defined** → **Show all scopes** → **Marketplace** → tick **Manage** |

4. Click **Create** and copy the token. It is shown once.

### Step 3: Create the Open VSX namespace and token (`OVSX_PAT`)

1. Go to https://open-vsx.org and click **Log in** (top right) to sign in with GitHub.
2. Open your profile → **Settings**. Link an Eclipse account when asked, and sign the
   **Eclipse Foundation Open VSX Publisher Agreement**. Publishing fails until it is signed.
3. Go to **Settings → Access Tokens** → **Generate New Token**, describe it as `eval-vscode-release`, and copy
   it. It is shown once.
4. Create the namespace once, from a terminal:

   ```bash
   npx --yes ovsx create-namespace randy-rebucas -p <OVSX token>
   ```

   `Created namespace randy-rebucas` means it worked. If it says the namespace exists, it is either already yours
   (fine) or someone else's (pick another publisher ID, as in step 1).

5. Optional: ask for ownership of the namespace so the listing is not flagged as unverified. Open
   https://github.com/EclipseFdn/open-vsx.org/issues and file a **Claim namespace ownership** issue.

### Step 4: Store the tokens in GitHub

The workflow reads the tokens from a GitHub **environment** named `vscode-marketplace`. An environment keeps them
out of every other workflow and can require your approval before each publish.

1. In GitHub, open the repository → **Settings → Environments → New environment**, name it
   `vscode-marketplace`, and click **Configure environment**.
2. Optional but recommended: tick **Required reviewers** and add yourself. Every release then waits for your
   click before anything is published.
3. Optional: under **Deployment branches and tags**, choose **Selected branches and tags** and add the tag rule
   `vscode-v*`.
4. Under **Environment secrets**, add:

   | Name | Value |
   |---|---|
   | `VSCE_PAT` | the Azure DevOps token from step 2 |
   | `OVSX_PAT` | the Open VSX token from step 3 |

Setup is done. You do not repeat steps 1–4 for later releases, except to replace an expired token
(see [Rotating tokens](#rotating-tokens)).

---

## Each release

### Step 5: Bump the version and changelog

Each version can be published only once per registry; a version cannot be reused, even after unpublishing.

1. In `ide/vscode/package.json`, raise `"version"`, using `MAJOR.MINOR.PATCH`:
   - patch (`0.1.0` → `0.1.1`): fixes only
   - minor (`0.1.1` → `0.2.0`): new features, existing settings still work
   - major: removed or renamed settings or commands
2. Add a section at the top of `ide/vscode/CHANGELOG.md` for the new version. The Marketplace shows it on the
   **Changelog** tab, and the GitHub release uses the whole file as its notes.

For the very first release, `0.1.0` and its changelog are already in place; skip this step.

### Step 6: Check it locally

From `ide/vscode`:

```bash
npm ci
npm test          # type-checks and runs the unit tests
npm run package   # builds eval-auditor.vsix; must finish with "DONE" and no WARNING lines
code --install-extension eval-auditor.vsix --force
```

Reload VS Code and try the extension: sign in, load findings, hover a finding, run a quick fix. For the browser
build, press F5 in the repository and choose **eVal extension (web worker)**.

### Step 7: Push the changes to `main`

The workflow builds from the tagged commit, so everything it needs must be committed and pushed:

```bash
git add ide/vscode .github/workflows/release-vscode.yml
git commit -m "VS Code extension 0.1.1"
git push origin main
```

On the first release, also make sure the server-side CORS support (`eval_app/api/cors.py` and its wiring) is on
`main` and deployed. Without it, the extension cannot call eVal from vscode.dev or github.dev.

### Step 8: Tag the release

The tag must be `vscode-v` followed by exactly the version in `package.json`:

```bash
git tag vscode-v0.1.1
git push origin vscode-v0.1.1
```

### Step 9: Watch the workflow

1. Open the repository's **Actions** tab → **Release VS Code extension** → the run for your tag.
2. If you set required reviewers in step 4, click **Review deployments** → **Approve and deploy**.
3. The run takes about two minutes. Every step must be green.

If a step fails, see [Troubleshooting](#troubleshooting). Fix the cause, then re-run the failed jobs from the run
page. If the fix needs a code change, delete the tag (`git push --delete origin vscode-v0.1.1` and
`git tag -d vscode-v0.1.1`), commit, and tag again. If the Marketplace step already succeeded, bump to the next
patch version instead.

### Step 10: Verify the listings

Allow 5–10 minutes for the Marketplace to verify and index a new version.

- [ ] https://marketplace.visualstudio.com/items?itemName=randy-rebucas.eval-auditor shows the new version,
      the `>_` icon, the README and the changelog
- [ ] https://open-vsx.org/extension/randy-rebucas/eval-auditor shows the new version
- [ ] The GitHub **Releases** page has `vscode-v<version>` with `eval-auditor.vsix` attached
- [ ] In VS Code, the Extensions view search `randy-rebucas.eval-auditor` finds it and **Install** works
- [ ] In vscode.dev, open a repository that is connected to eVal, install the extension, sign in against your
      **HTTPS** eVal server, and confirm findings load. If the browser console shows a CORS error, add the
      origin it names to `EVAL_API_CORS_ORIGINS` on the server

Installed copies update themselves automatically within a day.

---

## Manual publish (without GitHub Actions)

Use this if Actions is unavailable. From `ide/vscode`, with the tokens from steps 2 and 3:

```bash
npm ci && npm test && npm run package
VSCE_PAT=<Azure DevOps token> npm run publish:marketplace
OVSX_PAT=<Open VSX token> npm run publish:openvsx
```

Then create the GitHub release by hand and attach `eval-auditor.vsix`. Tag the commit as in step 8 so the next
automated release starts from the right place.

## Rotating tokens

Azure DevOps tokens expire after at most one year; Open VSX tokens do not expire but can be revoked. A release
with an expired token fails at the publish step with HTTP 401.

1. Create a new token: step 2 for the Marketplace, or step 3 sub-step 3 for Open VSX (the namespace already
   exists).
2. Replace the secret in **Settings → Environments → vscode-marketplace**.
3. Revoke the old token where you created it.
4. Re-run the failed release job.

Revoke a token right away, and replace it as above, if it may have leaked.

## Taking a version down

- **Bad version:** publish a fixed version with a higher number. Installed copies update automatically. This is
  almost always the right answer.
- **Remove the extension from the Marketplace:** https://marketplace.visualstudio.com/manage → the extension →
  **…** → **Unpublish** (hidden, can be restored) or **Remove** (permanent). From the command line:
  `npx @vscode/vsce unpublish randy-rebucas.eval-auditor`.
- **Open VSX:** a single version cannot be deleted by the publisher. File an issue at
  https://github.com/EclipseFdn/open-vsx.org/issues to ask for removal, and publish a fixed version meanwhile.

Version numbers stay used after removal on both registries.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `Tag vscode-v0.1.1 does not match vscode-v0.1.0` | Tag and `package.json` version differ | Delete the tag (step 9), fix the version or the tag, tag again (step 8) |
| vsce: `401` or `Access Denied` | Token expired, or created for one organization or without **Marketplace → Manage** | New token with **All accessible organizations** and **Marketplace → Manage** (step 2), update `VSCE_PAT` |
| vsce: `The publisher 'randy-rebucas' ... not found` or `... not the owner` | Publisher not created, or created under a different Microsoft account than the token | Step 1 with the account that made the token |
| vsce: `... version 0.1.1 already exists` | That version was published before | Bump the version (step 5) and tag again |
| ovsx: `Unknown publisher` / `must sign the Publisher Agreement` | Step 3 sub-step 2 not done | Sign the agreement at open-vsx.org → Settings |
| ovsx: `Insufficient access rights for namespace` | Namespace missing, or owned by someone else | Run `create-namespace` (step 3); if taken, change publisher |
| `gh release create` fails: release exists | A release with that tag was created by hand | Delete the release on GitHub or attach the `.vsix` to it manually; the registries are already updated |
| The job waits forever | Required reviewers are on and nobody approved | Approve under **Review deployments** (step 9) |
| Works on desktop, fails on vscode.dev with a network or CORS error | eVal is on http, or the editor's origin is not allowed | Serve eVal over HTTPS; add the origin from the browser console to `EVAL_API_CORS_ORIGINS` ([SECURITY.md § 4](SECURITY.md#4-web-application)) |

## Reference

| File | Purpose |
|---|---|
| `ide/vscode/package.json` | ID, version, icon, listing metadata, build and publish scripts |
| `ide/vscode/README.md` | Marketplace / Open VSX listing page |
| `ide/vscode/CHANGELOG.md` | Changelog tab and GitHub release notes |
| `ide/vscode/LICENSE.md` | License shown on the listing |
| `ide/vscode/media/icon.png` | 128×128 listing icon |
| `.github/workflows/release-vscode.yml` | Tag-triggered publish to both registries |
| `.github/workflows/ci.yml` (`vscode-extension` job) | Tests and bundles the extension on every push and pull request |
