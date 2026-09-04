"""The seven core agents, plus the responder that renders the final answer."""

from vulnintel.agents.asset_exposure import AssetExposureAgent
from vulnintel.agents.base import Agent, AgentResult
from vulnintel.agents.critic import CriticAgent
from vulnintel.agents.policy_rag import PolicyRagAgent
from vulnintel.agents.responder import ResponderAgent, render_deterministic
from vulnintel.agents.risk_remediation import RiskRemediationAgent
from vulnintel.agents.state import GraphState, initial_state
from vulnintel.agents.supervisor import ReplanSupervisor, SupervisorAgent
from vulnintel.agents.threat_intel import ThreatIntelAgent
from vulnintel.agents.vulnerability_intel import VulnerabilityIntelAgent

SPECIALIST_AGENTS = {
    "asset_exposure": AssetExposureAgent,
    "vulnerability_intel": VulnerabilityIntelAgent,
    "threat_intel": ThreatIntelAgent,
    "policy_rag": PolicyRagAgent,
    "risk_remediation": RiskRemediationAgent,
}

__all__ = [
    "SPECIALIST_AGENTS",
    "Agent",
    "AgentResult",
    "AssetExposureAgent",
    "CriticAgent",
    "GraphState",
    "PolicyRagAgent",
    "ReplanSupervisor",
    "ResponderAgent",
    "RiskRemediationAgent",
    "SupervisorAgent",
    "ThreatIntelAgent",
    "VulnerabilityIntelAgent",
    "initial_state",
    "render_deterministic",
]
