"""Agent and graph behaviour.

Runs on the mock provider, so these assert on *architecture* rather than on
generation quality: routing, allowlisting, the critic's deterministic
assertions, and the guardrails that stop an agent inventing evidence.
"""

from __future__ import annotations

import pytest

from vulnintel.agents.risk_remediation import verify_no_mutation
from vulnintel.agents.supervisor import SupervisorAgent
from vulnintel.llm import MockProvider, build_provider, set_provider
from vulnintel.tools import AGENT_TOOL_ALLOWLIST, TOOLS, ToolAccessError, ToolBox


@pytest.fixture(autouse=True)
def mock_provider():
    set_provider(build_provider("mock"))
    yield
    set_provider(None)


class TestToolAllowlist:
    def test_each_agent_only_sees_its_own_tools(self):
        box = ToolBox("threat_intel", persist=False)
        assert "get_kev_status" in box.available()
        assert "search_assets" not in box.available()

    def test_calling_outside_the_allowlist_raises(self, db):
        box = ToolBox("threat_intel", persist=False)
        with pytest.raises(ToolAccessError, match="not permitted"):
            box.call("search_assets", limit=1)

    def test_unknown_tool_raises(self, db):
        box = ToolBox("supervisor", persist=False)
        with pytest.raises(ToolAccessError, match="unknown tool"):
            box.call("rm_minus_rf")

    def test_every_allowlisted_name_is_a_real_tool(self):
        for agent, allowed in AGENT_TOOL_ALLOWLIST.items():
            unknown = allowed - set(TOOLS)
            assert not unknown, f"{agent} allowlists non-existent tools: {unknown}"

    def test_responder_holds_no_tools(self, db):
        from vulnintel.agents.responder import ResponderAgent

        assert ResponderAgent(persist=False).tools.available() == []

    def test_calls_are_audited(self, seeded_db):
        box = ToolBox("risk_remediation", persist=False)
        box.call("portfolio_summary")
        assert len(box.calls) == 1
        record = box.calls[0]
        assert record.tool_name == "portfolio_summary"
        assert record.status == "ok"
        assert record.call_id


class TestSupervisorPlanValidation:
    def test_malformed_plan_falls_back_rather_than_failing(self):
        agent = SupervisorAgent(persist=False)
        plan = agent._validate({}, {"question": "anything at all", "user_role": "analyst"})
        assert plan["required_agents"]
        assert plan["parallel_groups"]

    def test_risk_remediation_is_always_last_and_alone(self):
        agent = SupervisorAgent(persist=False)
        plan = agent._validate(
            {
                "intent": "executive_brief",
                "required_agents": ["risk_remediation", "asset_exposure", "threat_intel"],
            },
            {"question": "top risks", "user_role": "cto"},
        )
        assert plan["parallel_groups"][-1] == ["risk_remediation"]
        assert "risk_remediation" not in plan["parallel_groups"][0]

    def test_structurally_required_agents_are_added_back(self):
        """An under-specified plan is topped up, not executed as given."""
        agent = SupervisorAgent(persist=False)
        plan = agent._validate(
            {"intent": "executive_brief", "required_agents": ["policy_rag"]},
            {"question": "top five risks", "user_role": "cto"},
        )
        assert "risk_remediation" in plan["required_agents"]
        assert "asset_exposure" in plan["required_agents"]

    def test_policy_questions_stay_narrow(self):
        """Selective routing must actually be selective."""
        agent = SupervisorAgent(persist=False)
        plan = agent._validate(
            {"intent": "policy_question", "required_agents": ["policy_rag"]},
            {"question": "what does policy require", "user_role": "analyst"},
        )
        assert plan["required_agents"] == ["policy_rag"]

    def test_invented_entities_are_normalised_not_trusted(self):
        agent = SupervisorAgent(persist=False)
        plan = agent._validate(
            {
                "intent": "cve_investigation",
                "entities": {"cve_ids": ["cve-2021-44228", "  "], "products": ["Django"]},
            },
            {"question": "x", "user_role": "analyst"},
        )
        assert plan["entities"]["cve_ids"] == ["CVE-2021-44228"]
        assert plan["entities"]["products"] == ["Django"]

    def test_result_limit_is_clamped(self):
        agent = SupervisorAgent(persist=False)
        # 0 and non-numeric are treated as "unspecified" and fall back to the
        # default; a real value is clamped into range.
        for supplied, expected in [(0, 5), (9999, 50), ("nonsense", 5), (7, 7), (-3, 1)]:
            plan = agent._validate(
                {"intent": "general", "result_limit": supplied},
                {"question": "x", "user_role": "analyst"},
            )
            assert plan["result_limit"] == expected


class TestScoreMutationGuard:
    def test_a_score_matching_a_stored_value_passes(self):
        findings = [{"score": 82.0}, {"score": 61.5}]
        plan = {"executive_summary": "The top issue scores 82/100 on our model."}
        assert verify_no_mutation(plan, findings) == []

    def test_an_invented_score_is_detected(self):
        findings = [{"score": 82.0}]
        plan = {"executive_summary": "This scores 95/100 and must be fixed today."}
        drift = verify_no_mutation(plan, findings)
        assert drift and "95" in drift[0]

    def test_drift_is_detected_inside_list_fields(self):
        findings = [{"score": 40.0}]
        plan = {"why_these_matter": ["Ranked 77/100 by the model."]}
        assert verify_no_mutation(plan, findings)

    def test_no_stored_scores_means_no_false_positives(self):
        assert verify_no_mutation({"executive_summary": "50/100"}, []) == []


class TestMockProvider:
    def test_structured_output_matches_the_schema(self):
        provider = MockProvider()
        schema = {
            "type": "object",
            "properties": {
                "passed": {"type": "boolean"},
                "confidence": {"type": "number"},
                "gaps": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["passed", "confidence", "gaps"],
            "additionalProperties": False,
        }
        result = provider.complete_structured(system="s", prompt="p", schema=schema)
        assert set(result.structured) == {"passed", "confidence", "gaps"}
        assert isinstance(result.structured["gaps"], list)

    def test_enum_values_are_respected(self):
        provider = MockProvider()
        schema = {
            "type": "object",
            "properties": {"mode": {"type": "string", "enum": ["a", "b", "c"]}},
            "required": ["mode"],
            "additionalProperties": False,
        }
        result = provider.complete_structured(system="s", prompt="p", schema=schema)
        assert result.structured["mode"] in {"a", "b", "c"}

    def test_output_is_deterministic(self):
        a = MockProvider().complete(system="s", prompt="p").text
        b = MockProvider().complete(system="s", prompt="p").text
        assert a == b


class TestGraphTopology:
    def test_every_edge_references_a_declared_node(self):
        from vulnintel.graph import graph_topology

        topology = graph_topology()
        node_ids = {n["id"] for n in topology["nodes"]}
        for edge in topology["edges"]:
            assert edge["from"] in node_ids
            assert edge["to"] in node_ids

    def test_the_replan_cycle_exists(self):
        from vulnintel.graph import graph_topology

        edges = graph_topology()["edges"]
        assert any(e["from"] == "critic" and e["to"] == "replan" for e in edges)
        assert any(e["kind"] == "cycle" for e in edges)


class TestEndToEndGraph:
    def test_investigation_completes_and_produces_a_trace(self, seeded_db, knowledge_db):
        from vulnintel.graph import run_investigation

        state = run_investigation("What are our top security risks?", user_role="cto")

        assert state.get("final_answer")
        assert state.get("spans")
        assert all(span.get("node") for span in state["spans"]), "every span names its node"
        assert state.get("replan_count", 0) <= 2

    def test_a_policy_question_does_not_invoke_the_whole_system(self, seeded_db, knowledge_db):
        """§7.1: routing must be selective."""
        from vulnintel.graph import run_investigation

        state = run_investigation(
            "What does our policy require for an exploited critical vulnerability?",
            user_role="analyst",
        )
        nodes = {s["node"] for s in state["spans"]}
        assert "policy_rag" in nodes

    def test_every_model_backed_node_reports_its_tokens(self, seeded_db, knowledge_db):
        """A node that calls the model must record what it spent.

        The cost panel sums per-node tokens, so a node that reports ``None``
        is silently free: the bill is real but the figure shown next to the
        answer excludes it. This caught the responder and the critic —
        between them roughly a third of a run — reporting nothing at all.
        """
        from vulnintel.graph import run_investigation

        state = run_investigation("What are our top security risks?", user_role="cto")

        deterministic = {"replan", "join", "route"}
        silent = [
            span["node"]
            for span in state["spans"]
            if span.get("node") not in deterministic
            and span.get("tier")
            and span.get("input_tokens") is None
        ]
        assert not silent, f"model-backed nodes recorded no tokens: {silent}"

    def test_the_responder_records_tokens(self, seeded_db, knowledge_db):
        """The responder builds its span by hand, so it is the easiest to forget."""
        from vulnintel.graph import run_investigation

        state = run_investigation("What are our top security risks?", user_role="cto")
        responder = next(s for s in state["spans"] if s["node"] == "responder")
        assert responder.get("input_tokens"), "the responder wrote an answer but billed nothing"
        assert responder.get("output_tokens")
