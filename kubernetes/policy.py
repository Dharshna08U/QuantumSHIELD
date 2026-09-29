from dataclasses import dataclass


@dataclass(frozen=True)
class HealingPolicyDecision:
    status: str
    eligible: bool
    reason: str
    action: str


def decide_incident_response(
    incident_type: str,
    severity: str,
    *,
    ai_eligible: bool,
    policy_enabled: bool,
) -> HealingPolicyDecision:
    """Evaluate a narrow allowlist. Phase 2 only records simulation intent."""
    action = "Review workload capacity and request operator approval"
    if not policy_enabled:
        return HealingPolicyDecision("manual_review", False, "Automatic response policy is disabled", action)
    if severity == "critical":
        return HealingPolicyDecision("manual_review", False, "Critical events require human review", action)
    if incident_type != "resource_exhaustion" or not ai_eligible:
        return HealingPolicyDecision("manual_review", False, "Incident is outside the approved response policy", action)
    return HealingPolicyDecision("approval_required", True, "Operator approval is required; simulation only", action)
