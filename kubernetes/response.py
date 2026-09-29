from dataclasses import dataclass
from typing import Literal, Protocol

ActionStatus = Literal["simulated", "blocked"]


@dataclass(frozen=True)
class HealingDecision:
    action: str
    approved: bool
    reason: str
    mode: str = "simulation"


class ClusterObserver(Protocol):
    def snapshot(self, namespace: str) -> dict[str, object]: ...


class IncidentResponder(Protocol):
    def execute(self, decision: HealingDecision) -> dict[str, object]: ...


class SimulationResponder:
    """Safe local responder: records intent and never calls a cluster API."""

    def execute(self, decision: HealingDecision) -> dict[str, object]:
        if not decision.approved:
            return {"status": "blocked", "action": decision.action, "reason": decision.reason}
        return {
            "status": "simulated",
            "action": decision.action,
            "reason": decision.reason,
            "cluster_mutated": False,
        }


def decide_healing(reason: str, *, policy_enabled: bool, operator_approved: bool) -> HealingDecision:
    safe_actions = {"CrashLoopBackOff": "restart_workload"}
    action = safe_actions.get(reason)
    if not action:
        return HealingDecision("none", False, "No allowlisted policy for this incident")
    if not policy_enabled:
        return HealingDecision(action, False, "Remediation policy is disabled")
    if not operator_approved:
        return HealingDecision(action, False, "Operator approval is required")
    # Even with approval, Phase 1 only supports simulation.
    return HealingDecision(action, True, "Approved for simulation only")
