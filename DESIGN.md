---
name: eVal
description: AI generates code. eVal verifies it. An operator's console for checking code — dark slate panes, one monospace typeface set like a shell, colour reserved for meaning.
themes: [dark (default), light]
colors:
  dark:
    bg: "#0a0d10"
    bg-2: "#0d1115"      # sidebar
    panel: "#11161b"
    panel-2: "#161c22"   # pane bars, hover
    panel-3: "#1d242b"
    line: "#232b33"
    line-2: "#323d47"
    fg: "#dbe2e8"
    fg-2: "#a3afba"
    fg-3: "#808d99"      # ≥4.5:1 on panel
    accent: "#5ccfe6"    # links, focus, primary action
    ok: "#5fd38d"
    warn: "#e8b65a"      # moderate / medium
    high: "#ff9157"
    crit: "#ff6b6d"
    crit-solid: "#e5484d"
    violet: "#b8a6ff"    # AI-generated content only
  light:
    bg: "#eef1f4"
    panel: "#ffffff"
    line: "#dce2e7"
    fg: "#11171d"
    fg-2: "#46525e"
    fg-3: "#5b6875"
    accent: "#086e93"
    ok: "#157a45"
    warn: "#8a5a00"
    high: "#b2440c"
    crit: "#c4232a"
    violet: "#5b3fc4"
  terminal:              # identical in both themes
    term-bg: "#07090c"
    term-bar: "#0f1419"
    term-line: "#1d252d"
    term-fg: "#d4dde5"
    term-dim: "#7f8d99"
typography:
  family: "IBM Plex Mono (self-hosted 400/600), ui-monospace, SFMono-Regular, Menlo, Consolas, monospace"
  features: "zero (slashed zero)"
  body: { size: "0.875rem", lineHeight: 1.55 }
  label: { size: "0.62–0.72rem", weight: 600, letterSpacing: "0.08em", transform: uppercase }
  page-title: { size: "clamp(1.25rem, 1.05rem + .6vw, 1.6rem)", weight: 600, letterSpacing: "-0.025em" }
  directive: { size: "clamp(1.25rem, 1rem + .9vw, 1.75rem)", weight: 600 }
  landing-title: { size: "clamp(2rem, 1rem + 2.4vw, 2.85rem)", weight: 600, letterSpacing: "-0.045em" }
radius: { pane: 6px, control: 4px, terminal: 8px }
---

# Design System: eVal

## Overview

eVal is a static-analysis console. The interface reads like a well-kept terminal session: everything is set in one
monospace face, labels are lowercase-shell or small uppercase, and every surface is a ruled **pane**. Dark is the
default; a light theme is one click away (sidebar or guest bar) and is remembered per browser. Print always renders a
light report with no chrome.

The product principles in PRODUCT.md drive the visual rules: evidence before verdict, never overclaim, severity can't be
averaged away. Concretely that means colour is spent only on meaning, "not assessed" is always drawn (hatched), and the
disclaimer "scores are risk indicators, not guarantees of production readiness" survives on every page.

## Colour

- **Accent (cyan)** — links, focus rings, primary buttons, the active nav item, the blinking cursor. Never a risk signal.
- **Risk scale** — `crit` (Critical, solid fill), `high` (orange, outlined wash), `warn` (Moderate/Medium, amber),
  `ok` (Low / clean / succeeded, green). The word is always written; colour only reinforces it.
- **Hatch** — 45° lines in `fg-3`: a category or result that could not be assessed. Never shown as a score.
- **Violet** — AI-generated content (badges, AI panes). Signals "verify before trusting".
- **Terminal tokens** — code, evidence, command snippets and the sample audit stay dark in both themes.

Theme tokens live on `:root[data-bs-theme="dark|light"]` in `app.css`; Bootstrap's own variables are re-pointed at them,
so any Bootstrap component inherits the console look.

## Typography

One family: IBM Plex Mono, served from `static/fonts` (CSP allows only self-hosted fonts). Slashed zero is on so `0`/`O`
never confuse when reading hashes and code. Hierarchy comes from weight (400/600), size and letter-spaced uppercase
labels — not from a second typeface.

## Layout

- **Signed-in shell** — a 15rem sidebar (brand, org switcher with role, `// workspace` and `// settings` nav, account,
  theme toggle) and a sticky top bar with a shell breadcrumb: `$ cd ~/<org>/<section>▍`. Below 960px the sidebar is an
  off-canvas drawer opened by the Menu button (Esc or outside click closes it); without JS it simply stacks.
- **Guest shell** — a slim sticky bar (brand, Log in, Register, theme toggle) over a faint dot grid.
- **Pages** — `.page` stacks a `.page-head` (trail, title, meta/lede, actions) and panes. `.split` gives a main column
  with a 19–24rem aside; `.split-even` and `.split-lead` are the two-column variants.

## Components

| Component | Class | Notes |
|---|---|---|
| Pane | `.pane` > `.pane-bar` + `.pane-body` | Bar title gets a cyan `▸` unless it carries an icon. Variants: `.is-ai`, `.is-pr`, `.is-alert`. |
| Terminal window | `.term` > `.term-bar` (traffic-light dots, centered title) + `.term-body` | `.term-prompt` `$`, `.term-path`, `.term-flag`, `.term-str`, `.term-cmt`. |
| Primary button | `.btn-ink` | Cyan fill. Links get a trailing `→`; form buttons don't. `.is-block` for full width. |
| Secondary button | `.act` | Outlined. `.act-danger` for destructive actions (always with `data-confirm`). |
| Risk mark | `.rmark-{level}` | Dot + uppercase word. Not assessed is dashed and hatched. |
| Severity / risk / kind badges | `.sev-*`, `.risk-*`, `.kind-*` | Critical solid; others outlined washes. |
| Status | `.st .st-{status}` | Dot + lowercase word; running pulses. |
| Coverage cells | `.cov`, `.cov-cell.cov-{level}` | Nine cells, one per category, coded SE AR TE DB AP DE PE OP MA. |
| Risk rail | `.rail` | Portfolio counts per level, each a filter; coloured underline per level. |
| Register | `.register` in `.register-wrap` | Dense ruled table; stacks into labelled cards under 760px (uses `data-label`). |
| Directive | `.directive` | "next action" headline; red edge when it names a finding. |
| Status line | `.status-line` | key/value strip: what a view covers and what checked it. |
| Filter bar | `.filter-bar` | Small uppercase labels above compact selects. |
| Category tile | `.cat` (`.is-na` hatched) | Score, findings link, bar, ceiling reason. |
| Key/value | `.kv` | Label column in small caps. |
| Flash | `.alert-*` | Log-style prefix: `[ok]`, `[warn]`, `[error]`, `[info]`. |
| Confirm dialog | `.confirm-note` (native `<dialog>`, built by app.js) | Required for queue/delete/revoke. |
| Empty state | `.empty` | `∅` prefix, plain sentence, link to the next step. |

## Motion

Short and functional: the cursor blink, a pulse on running audits, the landing sample audit replaying analyzer by
analyzer. All of it stops under `prefers-reduced-motion`.

## Accessibility

- Focus is a 2px cyan outline everywhere; touch targets grow to 2.75rem on coarse pointers.
- Risk is never colour-only; every mark writes its word.
- Secondary text meets 4.5:1 on panels in both themes.
- CSP forbids inline styles and scripts: widths go through `data-width`, theme through `static/theme.js` (loaded in
  `<head>` to avoid a flash).

## Do's and Don'ts

**Do**
- Put code, paths, evidence and commands in terminal surfaces or `.mono`.
- Write the risk word next to every risk colour; hatch what wasn't assessed.
- Label sample data as sample and keep the disclaimer in the footer.
- Use the accent for action and navigation only.

**Don't**
- Introduce a second typeface or colour a risk with the accent.
- Show "Not assessed" as 100, or let an average hide a Critical.
- Fabricate customers, testimonials, benchmarks or pricing on the landing page.
- Add inline `style=` or `<script>` — the CSP will block them.
