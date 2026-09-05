# VulnIntel AI

**Enterprise vulnerability and cyber-risk intelligence platform.**

Turns fragmented vulnerability data into a short, defensible list of what to fix
first — and shows its working for every number on that list.

The interesting claim is not that it uses an LLM. It is where the LLM is *not*
used: risk scores, version comparisons, affected/not-affected verdicts and
remediation deadlines are computed by deterministic functions. The model plans
the investigation, reads evidence and writes the answer. It cannot change a
number.

That boundary is demonstrable rather than asserted. During development the
Anthropic API ran out of credit mid-run and **all seven agents failed**. The
system still produced a correct, ranked, cited answer — because the ranking was
never the model's contribution.

---

## The problem

A vulnerability feed ranks by technical severity. It knows nothing about your
business. A CVSS 9.8 on a decommissioned test box outranks a CVSS 6.5 that is
being actively exploited on your payments gateway.

Against a real corpus this platform triages **386,750 CVEs** into:

| | |
|---|---|
| Confirmed affecting the estate | 813,271 findings |
| Distinct vulnerabilities | 393 |
| Need action this week | **13** |
| Need action today | **3** |
| Per asset, needing action | **1.2** |

The headline is three issues, not eight hundred thousand findings.

---

## Quick start

```bash
git clone https://github.com/isayan58/Cyber_Intel_Vuln.git
cd Cyber_Intel_Vuln

make install-dev     # venv + dependencies
make bootstrap       # synthetic estate, feeds, policy corpus, match, score
make serve           # http://127.0.0.1:8000
```

`make bootstrap` takes about five minutes and needs no API key: the mock LLM
provider runs the entire agent graph offline and deterministically.

For real synthesis, add a key and switch provider:

```bash
cp .env.example .env      # add ANTHROPIC_API_KEY
make serve
```

Full NVD (386k CVEs, ~30 minutes) is a separate step, faster with a
[free NVD key](https://nvd.nist.gov/developers/request-an-api-key):

```bash
make ingest-nvd
```

**See it work with no model at all:**

```bash
make rank            # ranked, explained, deterministic
make mcp-demo        # both MCP servers over real stdio protocol
make eval            # retrieval, risk, tool and end-to-end suites
```

---

## Architecture

Three reasoning modes, deliberately not collapsed into one:

```
                     ┌──────────────────────┐
   question  ───────▶│ Supervisor / Planner │  decides what evidence is needed
                     └──────────┬───────────┘
                                │  (only the agents the question needs)
        ┌───────────────┬───────┴───────┬────────────────┐
        ▼               ▼               ▼                ▼
  Asset Exposure  Vulnerability   Threat Intel     Policy RAG
   SQL / CMDB      NVD · OSV      KEV·EPSS·ATT&CK  hybrid retrieval
        └───────────────┴───────┬───────┴────────────────┘
                                ▼
                     ┌──────────────────────┐
                     │  Risk & Remediation  │  ← deterministic scoring
                     └──────────┬───────────┘
                                ▼
                     ┌──────────────────────┐
                     │ Critic / Verification│  assertions, then optional audit
                     └──────────┬───────────┘
                         pass ◀─┴─▶ targeted re-plan (bounded)
                                ▼
                            Response
```

| Layer | Choice | Why |
|---|---|---|
| Orchestration | LangGraph | Real parallel nodes, conditional routing, a bounded cycle for re-planning |
| Tool boundary | MCP (2 servers, 15 tools) | Typed contracts, reusable by any MCP client, one place for auth and audit |
| Structured state | DuckDB / PostgreSQL | SQL joins for enterprise facts; one schema rendered per dialect |
| Raw history | Parquet + manifests | The warehouse rebuilds from bronze with **no network call** |
| Knowledge | BM25 + vector, RRF fusion | Policy prose needs both exact wording and meaning |
| Scoring | Plain Python | Reproducible, auditable, testable — and free |

**SQL for enterprise state, retrieval for policy, the model only for ambiguity
and synthesis.**

---

## What makes it defensible

**Deterministic scoring.** A documented, project-specific model — explicitly not
an industry standard:

```
score = 100 × (0.20·cvss + 0.25·epss + 0.20·kev
             + 0.15·criticality + 0.10·exposure + 0.10·sensitivity)
```

Components, weights and model version are persisted per finding, so *"why was A
above B?"* is a `SELECT`, and re-weighting is a diffable experiment.

**`unknown` is a first-class verdict.** When a version cannot be compared —
an unparseable string, a wildcard CPE, a missing package version — the finding
is reported as unconfirmed, never as affected. 50,498 findings currently sit
there rather than inflating the numbers.

**Policy that cannot drift.** The Vulnerability Management Standard is
*generated from* the same rule table the scorer reads. A quoted SLA and a
computed deadline cannot disagree.

**Least privilege, enforced.** Each agent is constructed with only the tools its
role needs; calling outside the allowlist raises. Every tool call is persisted
with arguments, row count, latency and outcome.

**Degradation is visible.** If an agent loses its model pass, the answer says so
on its face rather than looking complete.

---

## Cost and performance

Measured against Claude Opus 5, same question, like-for-like:

| | Baseline | Optimised |
|---|---|---|
| Cost per investigation | $0.795 | **$0.094** |
| Wall clock | 537s | **87s** |

Achieved by routing each step to the cheapest model that can do its job (Haiku
for extraction and presentation, Sonnet for synthesis, Opus reserved for
verification), gating the audit on deterministic outcomes, tuning effort, and
trimming payloads. `make report` regenerates the full analysis with attribution
that reconciles to the measured delta.

---

## Testing and evaluation

```bash
make test       # 125 tests
make eval       # four suites, evaluated separately so failures are diagnosable
```

| Suite | Checks |
|---|---|
| `risk` | Scoring reproducibility, monotonicity, bounds, SLA selection, version comparison |
| `tools` | Tool schemas, graceful failure, **allowlist enforcement**, audit trail |
| `retrieval` | Recall@k, MRR, plus adversarial: superseded policy, out-of-scope, injection |
| `end_to_end` | Full graph runs asserting on the *trace*: no invented scores, no invented CVEs |

The end-to-end suite runs on the mock provider deliberately. With a stub that
cannot reason, every factual claim must still be correct.

---

## Known limitations

Stated plainly, because a portfolio project that claims to be finished is less
credible than one that knows what it isn't.

- **Synthetic inventory.** Assets, applications and ownership are generated from
  a fixed seed. The software names are real, so matching runs against genuine
  advisories, but the estate is not.
- **The vendor fallback is untested in anger.** NVD lists eleven vendors for
  `http_server`; the resolution logic is unit-tested but no real CMDB has
  exercised it, because the generator's vendor names happen to match exactly.
- **In-memory rate limiting.** Correct for one process, wrong for several.
  A multi-process deployment needs Redis.
- **Hash embeddings by default.** Real retrieval quality needs
  `pip install -e ".[embeddings]"`; the out-of-scope adversarial case passes
  uncomfortably close to its floor without it.
- **DuckDB permits one writer.** Ingestion and serving cannot run concurrently.
  Postgres removes this — `make up`.
- **No multi-tenancy**, and no authorisation model beyond a single API key.

---

## Command reference

```
make bootstrap      everything, in dependency order
make status         what is loaded and what is missing
make ingest         KEV, EPSS, OSV, ATT&CK
make ingest-nvd     full NVD backfill (~30 min)
make rank           ranked findings, no model involved
make ask Q="..."    a full multi-agent investigation
make eval           all evaluation suites
make mcp-demo       MCP servers over stdio
make up / down      Postgres + app in containers
make clean-osx      remove macOS AppleDouble sidecars
```

---

## Data sources

All public, all read-only. NVD (CVE, CVSS, CWE, CPE), CISA KEV, FIRST EPSS,
OSV / GitHub Advisory, MITRE ATT&CK, plus NIST and OWASP guidance for the
knowledge corpus. Review each publisher's terms before large-scale use.

**Defensive use only.** No exploit generation, no scanning of arbitrary targets,
no autonomous changes to production systems. Every tool is read-only.

---

## Licence

MIT.
