"""Explainable severity-based response policy; severity never grants execution."""
from dataclasses import dataclass


@dataclass(frozen=True)
class ResponsePolicyDecision:
    severity: str
    decision: str
    allowed_actions: tuple[str, ...]
    approval_required: bool
    reason: str


def evaluate_response_policy(severity: str, *, requested_action: str | None = None) -> ResponsePolicyDecision:
    severity = severity.lower()
    if severity == "low":
        actions, decision, approval, reason = (), "record_only", False, "Low severity conditions are recorded without remediation."
    elif severity == "medium":
        actions, decision, approval, reason = ("restart_deployment", "scale_deployment"), "recommend_operator", True, "Medium severity permits a recommendation; operator approval is required."
    elif severity == "high":
        actions, decision, approval, reason = ("restart_deployment", "scale_deployment"), "approval_required", True, "High severity requires explicit operator approval."
    elif severity == "critical":
        actions, decision, approval, reason = ("restart_deployment", "scale_deployment"), "approval_required", True, "Critical severity requires explicit administrator/operator approval; severity never authorizes automatic action."
    else:
        actions, decision, approval, reason = (), "manual_review", True, "Unknown severity cannot authorize remediation."
    if requested_action and requested_action not in actions:
        return ResponsePolicyDecision(severity, "blocked", (), True, "Requested action is not permitted by the severity policy.")
    return ResponsePolicyDecision(severity, decision, actions, approval, reason)
