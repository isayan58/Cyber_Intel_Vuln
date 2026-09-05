"""VulnIntel AI command line.

    vulnintel status                 what is loaded, what is missing
    vulnintel db init | reset        create or drop the schema
    vulnintel generate               synthetic estate from a fixed seed
    vulnintel ingest <feed>...       feeds -> bronze -> warehouse
    vulnintel rag build              policy corpus -> chunks -> embeddings
    vulnintel match                  inventory x advisories -> findings
    vulnintel score                  deterministic enterprise priority scoring
    vulnintel bootstrap              everything above, in order
    vulnintel rank                   ranked findings, no model involved
    vulnintel ask "<question>"       full multi-agent investigation
    vulnintel eval <suite>           run an evaluation suite
    vulnintel serve                  FastAPI + HTMX UI
    vulnintel mcp <server>           run an MCP server over stdio
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from vulnintel import __version__
from vulnintel.logging_setup import get_logger, setup_logging

log = get_logger(__name__)

FEEDS = ("kev", "epss", "nvd", "osv", "attack")


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


def _table(rows: list[dict[str, Any]], columns: list[str] | None = None) -> str:
    if not rows:
        return "  (no rows)"
    columns = columns or list(rows[0].keys())
    widths = {
        c: max(len(str(c)), max(len(_fmt(r.get(c))) for r in rows)) for c in columns
    }
    header = "  " + "  ".join(str(c).ljust(widths[c]) for c in columns)
    rule = "  " + "  ".join("-" * widths[c] for c in columns)
    body = [
        "  " + "  ".join(_fmt(r.get(c)).ljust(widths[c]) for c in columns) for r in rows
    ]
    return "\n".join([header, rule, *body])


def _fmt(value: Any) -> str:
    if value is None:
        return "—"
    if isinstance(value, float):
        return f"{value:.3f}".rstrip("0").rstrip(".")
    return str(value)


def _heading(text: str) -> None:
    print(f"\n\033[1m{text}\033[0m")


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------


def cmd_status(args: argparse.Namespace) -> int:
    from vulnintel.config import get_settings
    from vulnintel.data.db import get_db
    from vulnintel.tools import security_intel as intel

    settings = get_settings()
    db = get_db()
    counts = db.table_counts()

    _heading("Configuration")
    for key in ("db_backend", "llm_provider", "llm_model", "embedding_provider", "synthetic_seed"):
        print(f"  {key:22} {getattr(settings, key)}")
    print(f"  {'warehouse':22} {settings.duckdb_file}")

    _heading("Pipeline stages")
    stages = [
        ("synthetic estate", counts.get("assets", 0), "vulnintel generate"),
        ("KEV catalogue", counts.get("kev", 0), "vulnintel ingest kev"),
        ("EPSS scores", counts.get("epss_current", 0), "vulnintel ingest epss"),
        ("CVE records", counts.get("cve", 0), "vulnintel ingest nvd"),
        ("package advisories", counts.get("advisory", 0), "vulnintel ingest osv"),
        ("ATT&CK objects", counts.get("attack_object", 0), "vulnintel ingest attack"),
        ("knowledge chunks", counts.get("kb_chunk", 0), "vulnintel rag build"),
        ("findings", counts.get("vulnerability_finding", 0), "vulnintel match"),
        ("scored findings", counts.get("finding_score", 0), "vulnintel score"),
    ]
    for label, count, hint in stages:
        mark = "\033[32m✓\033[0m" if count else "\033[33m·\033[0m"
        suffix = "" if count else f"   → {hint}"
        print(f"  {mark} {label:22} {count:>10,}{suffix}")

    _heading("Feed freshness")
    print(_table(intel.get_feed_freshness()) if counts.get("ingest_run") else "  (never ingested)")
    return 0


def cmd_db(args: argparse.Namespace) -> int:
    from vulnintel.data.db import get_db
    from vulnintel.data.views import create_views

    db = get_db()
    if args.db_action == "reset":
        if not args.yes:
            answer = input("Drop every table and recreate the schema? [y/N] ").strip().lower()
            if answer != "y":
                print("aborted")
                return 1
        db.drop_all()
    db.init_schema()
    create_views(db)
    print("schema ready")
    return 0


def cmd_generate(args: argparse.Namespace) -> int:
    from vulnintel.data.db import get_db
    from vulnintel.data.views import create_views
    from vulnintel.generator import SyntheticGenerator

    db = get_db()
    db.init_schema()
    generator = SyntheticGenerator(
        db=db, seed=args.seed, asset_count=args.assets, application_count=args.applications
    )
    print(generator.generate())
    create_views(db)
    return 0


def cmd_ingest(args: argparse.Namespace) -> int:
    from vulnintel.data.db import get_db
    from vulnintel.data.views import create_views
    from vulnintel.ingest.attack import AttackPipeline
    from vulnintel.ingest.epss import EpssPipeline
    from vulnintel.ingest.kev import KevPipeline
    from vulnintel.ingest.nvd import NvdPipeline
    from vulnintel.ingest.osv import OsvPipeline

    db = get_db()
    db.init_schema()

    feeds = list(FEEDS) if "all" in args.feeds else args.feeds
    pipelines = {
        "kev": lambda: KevPipeline(db).run(offline=args.offline),
        "epss": lambda: EpssPipeline(db).run(offline=args.offline),
        "attack": lambda: AttackPipeline(db).run(offline=args.offline),
        "osv": lambda: OsvPipeline(db).run(
            offline=args.offline, ecosystems=tuple(args.ecosystems)
        ),
        "nvd": lambda: NvdPipeline(db).run(
            offline=args.offline, backfill=args.backfill, max_pages=args.max_pages
        ),
    }

    failures = 0
    for feed in feeds:
        if feed not in pipelines:
            print(f"unknown feed: {feed}", file=sys.stderr)
            failures += 1
            continue
        _heading(feed.upper())
        try:
            print(f"  {pipelines[feed]()}")
        except Exception as exc:  # noqa: BLE001 - report and continue with the rest
            print(f"  \033[31mfailed: {exc}\033[0m", file=sys.stderr)
            failures += 1

    if "attack" in feeds and not failures:
        AttackPipeline(db).build_cwe_bridge()

    create_views(db)
    return 1 if failures else 0


def cmd_rag(args: argparse.Namespace) -> int:
    from vulnintel.data.db import get_db
    from vulnintel.rag.corpus import write_corpus
    from vulnintel.rag.ingest import ingest_knowledge_base, reembed
    from vulnintel.tools.knowledge import reset_retriever

    db = get_db()
    db.init_schema()

    if args.rag_action == "build":
        if not args.skip_corpus:
            paths = write_corpus()
            print(f"  wrote {len(paths)} synthetic policy documents")
        print(f"  {ingest_knowledge_base(db=db)}")
    elif args.rag_action == "reembed":
        print(f"  re-embedded {reembed(db=db)} chunks")
    elif args.rag_action == "search":
        from vulnintel.tools.knowledge import search_policy

        result = search_policy(args.query, top_k=args.top_k)
        for item in result["evidence"]:
            print(f"\n  \033[1m{item['citation']}\033[0m  (rerank {item['rerank_score']})")
            print(f"  {item['text'][:400]}…")
        for conflict in result["conflicts"]:
            print(f"\n  \033[33mconflict:\033[0m {conflict}")
    reset_retriever()
    return 0


def cmd_match(args: argparse.Namespace) -> int:
    from vulnintel.data.db import get_db
    from vulnintel.risk.matching import FindingMatcher

    counts = FindingMatcher(get_db()).rebuild()
    print(_table([counts]))
    return 0


def cmd_score(args: argparse.Namespace) -> int:
    from vulnintel.data.db import get_db
    from vulnintel.risk.scoring import score_all_findings

    written = score_all_findings(get_db())
    print(f"  scored {written:,} findings")
    return 0


def cmd_plant(args: argparse.Namespace) -> int:
    from vulnintel.data.db import get_db
    from vulnintel.generator.synthetic import plant_scenarios

    adjusted = plant_scenarios(get_db(), seed=args.seed)
    print(f"  pinned {sum(adjusted.values())} inventory rows across {len(adjusted)} packages")
    for key, count in sorted(adjusted.items(), key=lambda kv: -kv[1])[:15]:
        print(f"    {key:44} {count}")
    return 0


def cmd_bootstrap(args: argparse.Namespace) -> int:
    """Everything, in dependency order."""
    from vulnintel.data.db import get_db
    from vulnintel.data.views import create_views

    db = get_db()
    db.init_schema()

    steps: list[tuple[str, Any]] = [
        ("generate estate", lambda: cmd_generate(args)),
        ("ingest feeds", lambda: cmd_ingest(args)),
        ("build knowledge base", lambda: cmd_rag(argparse.Namespace(rag_action="build", skip_corpus=False))),
        ("plant demo scenarios", lambda: cmd_plant(args)),
        ("match findings", lambda: cmd_match(args)),
        ("score findings", lambda: cmd_score(args)),
    ]
    for label, step in steps:
        _heading(label)
        step()

    create_views(db)
    _heading("done")
    return cmd_status(args)


def cmd_rank(args: argparse.Namespace) -> int:
    """Ranked findings with no model in the loop at all."""
    from vulnintel.tools import risk_tools

    result = risk_tools.rank_findings(
        limit=args.limit, kev_only=args.kev_only, group_by_cve=args.by_cve
    )
    findings = result["findings"]
    if not findings:
        print("  no scored findings — run `vulnintel bootstrap` first")
        return 1

    columns = (
        ["cve_id", "score", "asset_count", "application_count", "kev_listed", "epss", "cvss_base"]
        if args.by_cve
        else ["finding_id", "cve_id", "hostname", "application_name", "score",
              "kev_listed", "epss", "installed_version", "fixed_version", "sla_due_date"]
    )
    _heading(f"Top {len(findings)} by enterprise priority score")
    print(_table(findings, columns))

    if args.explain and not args.by_cve:
        _heading("Score breakdown")
        for finding in findings[:3]:
            detail = risk_tools.explain_score(finding["finding_id"])
            parts = ", ".join(
                f"{c['component']}={c['normalised_value']}×{c['weight']}={c['contribution']}"
                for c in detail["breakdown"]
            )
            print(f"  #{detail['finding_id']}  {detail['score']}/100  {parts}")
            for note in detail.get("notes") or []:
                print(f"      · {note}")
    return 0


def cmd_ask(args: argparse.Namespace) -> int:
    from vulnintel.graph import run_investigation

    state = run_investigation(args.question, user_role=args.role)

    if args.json:
        print(json.dumps(
            {
                "run_id": state.get("run_id"),
                "answer": state.get("final_answer"),
                "critique": state.get("critique"),
                "citations": state.get("citations"),
                "latency_ms": state.get("latency_ms"),
            },
            indent=2, default=str,
        ))
        return 0

    _heading("Plan")
    print(f"  intent        {state.get('intent')}")
    print(f"  mode          {state.get('response_mode')}")
    print(f"  agents        {', '.join(state.get('required_agents') or [])}")
    print(f"  re-plans      {state.get('replan_count')}")
    print(f"  nodes         {' → '.join(s['node'] for s in state.get('spans', []))}")

    critique = state.get("critique") or {}
    _heading("Verification")
    print(f"  passed        {critique.get('passed')}")
    print(f"  confidence    {critique.get('confidence')}")
    for assertion in critique.get("assertions", []):
        mark = "✓" if assertion.get("passed") else "✗"
        print(f"    {mark} {assertion['name']}: {assertion['detail']}")

    _heading("Answer")
    print(state.get("final_answer") or "(none)")

    citations = state.get("citations") or []
    if citations:
        _heading("Sources")
        for citation in citations[:12]:
            print(f"  · {citation.get('citation')}")

    print(f"\n  run_id {state.get('run_id')}  ·  {state.get('latency_ms')} ms")
    return 0


def cmd_eval(args: argparse.Namespace) -> int:
    from vulnintel.evaluation import run_suite

    results = run_suite(args.suite, limit=args.limit)
    _heading(f"{args.suite} evaluation")
    print(_table(results["cases"], results["columns"]))
    _heading("Summary")
    for key, value in results["summary"].items():
        print(f"  {key:28} {_fmt(value)}")
    return 0 if results["passed"] else 1


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    from vulnintel.config import REPO_ROOT

    sys.path.insert(0, str(REPO_ROOT / "apps"))
    uvicorn.run("api.main:app", host=args.host, port=args.port, reload=args.reload)
    return 0


def cmd_mcp(args: argparse.Namespace) -> int:
    if args.server == "security-intel":
        from vulnintel.mcp_servers.security_intel.server import main
    elif args.server == "enterprise-assets":
        from vulnintel.mcp_servers.enterprise_assets.server import main
    else:
        print(f"unknown MCP server: {args.server}", file=sys.stderr)
        return 1
    main()
    return 0


def cmd_prompts(args: argparse.Namespace) -> int:
    from vulnintel.prompts import get_registry

    print(_table(
        get_registry().describe(),
        ["name", "version", "effort", "has_schema", "system_tokens", "description"],
    ))
    return 0


# --------------------------------------------------------------------------
# parser
# --------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vulnintel", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", action="version", version=f"vulnintel {__version__}")
    parser.add_argument("--log-level", default=None, help="DEBUG, INFO, WARNING, ERROR")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("status", help="what is loaded and what is missing").set_defaults(func=cmd_status)

    p = sub.add_parser("db", help="schema management")
    p.add_argument("db_action", choices=["init", "reset"])
    p.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
    p.set_defaults(func=cmd_db)

    p = sub.add_parser("generate", help="generate the synthetic estate")
    p.add_argument("--seed", type=int, default=None)
    p.add_argument("--assets", type=int, default=None)
    p.add_argument("--applications", type=int, default=None)
    p.set_defaults(func=cmd_generate)

    p = sub.add_parser("ingest", help="ingest public intelligence feeds")
    p.add_argument("feeds", nargs="+", choices=[*FEEDS, "all"])
    p.add_argument("--offline", action="store_true", help="re-normalise from bronze, no network")
    p.add_argument("--backfill", action="store_true", help="NVD: full corpus rather than a window")
    p.add_argument("--max-pages", type=int, default=None, help="NVD: stop after N pages")
    p.add_argument("--ecosystems", nargs="+", default=["PyPI", "npm", "Maven", "Go"])
    p.set_defaults(func=cmd_ingest)

    p = sub.add_parser("rag", help="knowledge base")
    rag_sub = p.add_subparsers(dest="rag_action", required=True)
    build = rag_sub.add_parser("build")
    build.add_argument("--skip-corpus", action="store_true",
                       help="do not regenerate the synthetic policy documents")
    rag_sub.add_parser("reembed")
    search = rag_sub.add_parser("search")
    search.add_argument("query")
    search.add_argument("--top-k", type=int, default=5)
    p.set_defaults(func=cmd_rag)

    sub.add_parser("match", help="match inventory against advisories").set_defaults(func=cmd_match)
    sub.add_parser("score", help="compute enterprise priority scores").set_defaults(func=cmd_score)

    p = sub.add_parser("plant", help="pin inventory versions into known-vulnerable ranges")
    p.add_argument("--seed", type=int, default=None)
    p.set_defaults(func=cmd_plant)

    p = sub.add_parser("bootstrap", help="run every stage in order")
    p.add_argument("--seed", type=int, default=None)
    p.add_argument("--assets", type=int, default=None)
    p.add_argument("--applications", type=int, default=None)
    p.add_argument("--feeds", nargs="+", default=["kev", "epss", "osv", "attack"])
    p.add_argument("--offline", action="store_true")
    p.add_argument("--backfill", action="store_true")
    p.add_argument("--max-pages", type=int, default=None)
    p.add_argument("--ecosystems", nargs="+", default=["PyPI", "npm"])
    p.set_defaults(func=cmd_bootstrap)

    p = sub.add_parser("rank", help="ranked findings — deterministic, no model")
    p.add_argument("--limit", type=int, default=10)
    p.add_argument("--kev-only", action="store_true")
    p.add_argument("--by-cve", action="store_true")
    p.add_argument("--explain", action="store_true")
    p.set_defaults(func=cmd_rank)

    p = sub.add_parser("ask", help="run a full multi-agent investigation")
    p.add_argument("question")
    p.add_argument("--role", default="analyst",
                   choices=["analyst", "cto", "ciso", "application_owner"])
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_ask)

    p = sub.add_parser("eval", help="run an evaluation suite")
    p.add_argument("suite", choices=["retrieval", "risk", "tools", "end_to_end", "all"])
    p.add_argument("--limit", type=int, default=None)
    p.set_defaults(func=cmd_eval)

    p = sub.add_parser("serve", help="run the API and UI")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--reload", action="store_true")
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("mcp", help="run an MCP server over stdio")
    p.add_argument("server", choices=["security-intel", "enterprise-assets"])
    p.set_defaults(func=cmd_mcp)

    sub.add_parser("prompts", help="list prompt files and versions").set_defaults(func=cmd_prompts)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    setup_logging(args.log_level)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
    except Exception as exc:
        log.debug("command failed", exc_info=True)
        print(f"\n\033[31merror:\033[0m {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
