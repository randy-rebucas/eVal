# Scoring and risk classification

> Scores are **risk indicators** derived from automated static analysis. They are not a guarantee of security or
> production readiness, and a high score does not mean the absence of vulnerabilities.

Implementation: `eval_engine/scoring.py` (`SCORING_VERSION = "1"`). This document and the code must change
together. Scoring is deterministic: the same findings always produce the same scores, regardless of order.

## 1. Which findings count

| Finding kind | Meaning | Kind factor |
|---|---|---|
| `confirmed` | A tool matched a concrete, verifiable pattern | 1.0 |
| `potential` | Heuristic risk that needs human review | 0.75 |
| `estimate` | Static performance/scale estimate — nothing was measured | 0.5 |
| `ai_observation` | Produced by an AI model | **0 (never scored)** |

Triage decisions (false positive, accepted risk) do **not** change scores; they only hide findings from default
views and reports. This keeps scores comparable across audits and prevents gaming.

Accepted risks need a reason, an owner (the team or vendor responsible for the fix) and a review date at most
`EVAL_ACCEPTED_RISK_MAX_DAYS` (default 365) away; false positives need a reason. Decisions carry over to later
audits by fingerprint. On the review date the finding reopens: it counts as open again in views, reports and
the PR/CI gate until someone re-accepts it.

## 2. Per-finding penalty

```
penalty = severity_weight × confidence_factor × kind_factor
```

| Severity | Weight | | Confidence | Factor |
|---|---:|---|---|---:|
| critical | 40 | | high | 1.0 |
| high | 15 | | medium | 0.7 |
| medium | 6 | | low | 0.4 |
| low | 2 | | | |
| info | 0 | | | |

## 3. Category score

For each of the nine categories (security, architecture, testing, database, API, dependencies, performance,
DevOps, maintainability):

1. **Coverage.** A category is *assessed* only if at least one analyzer covering it finished with status `ok`.
   Otherwise it is reported as **Not assessed** with no score — never as 100. Skipped analyzers (tool not
   installed, no matching language) and failed analyzers are listed in the audit's coverage table.
2. **Per-rule cap.** The penalties of one rule are summed but capped at `3 × weight(severity)`, so 200 unused
   imports cannot outweigh one SQL injection.
3. **Score** = `max(0, 100 − Σ capped rule penalties)`.
4. **Severity ceilings.** One serious finding bounds the category regardless of everything else:

| Finding in category | Ceiling | Resulting risk |
|---|---:|---|
| critical, confirmed, high confidence | 35 | Critical |
| critical, other (confidence ≥ medium) | 55 | High |
| high, confirmed, high confidence | 65 | Moderate |
| high, other (confidence ≥ medium) | 75 | Moderate |

Low-confidence findings never set a ceiling. The reason for an applied ceiling is shown on the dashboard.

## 4. Risk levels

| Score | Risk |
|---|---|
| ≥ 80 | Low |
| 60 – 79.9 | Moderate |
| 40 – 59.9 | High |
| < 40 | Critical |

## 5. Overall score and risk

`overall = Σ(category_score × weight) / Σ(weight)` over **assessed** categories only.

| Category | Weight |
|---|---:|
| Security | 3.0 |
| Dependencies, API | 2.0 |
| Database, Testing, DevOps | 1.5 |
| Architecture, Performance, Maintainability | 1.0 |

An average must not hide a severe problem, so the overall risk is escalated:

* it is **at least** the risk of any assessed *critical category* (security, API, dependencies, database);
* it is at most one level better than any other assessed category.

Example: a repository with a committed AWS key (security = 35, Critical) and otherwise clean code has an overall
score in the 80s but an overall risk of **Critical**.

## 6. Lifecycle (audit-to-audit)

Each finding has a fingerprint: `sha256(rule family | file | normalized flagged source line | occurrence)`.
It survives unrelated edits that shift line numbers. Equivalent rules from different tools share a *family*
(e.g. Bandit B608 and eVal's SQL-string rule) and merge into one finding with multiple sources.

| Lifecycle | Definition |
|---|---|
| new | never seen in an earlier successful audit of this repository |
| existing | present in the baseline audit |
| recurring | absent from the baseline but seen in an earlier audit (a regression) |
| resolved | present in the baseline, absent now |

The baseline is the latest successful audit of the **same branch** (falling back to any branch); for pull-request
audits it is the latest audit of the PR's **base branch**. Pull-request audits never become a baseline.
