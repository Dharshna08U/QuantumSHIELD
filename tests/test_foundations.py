import csv
import unittest
from pathlib import Path

from blockchain_service.client import BlockchainUnavailable, DisabledBlockchainClient
from kubernetes.response import SimulationResponder, decide_healing
from kubernetes.policy import decide_incident_response
from pqc.provider import PQCUnavailable, UnavailableProvider
from pqc.record import canonical_record, sha256_hex


class CanonicalRecordTests(unittest.TestCase):
    def test_canonical_encoding_is_key_order_independent(self):
        left = canonical_record({"z": 1, "a": "é"})
        right = canonical_record({"a": "é", "z": 1})
        self.assertEqual(left, right)
        self.assertEqual(len(sha256_hex(left)), 64)

    def test_non_finite_numbers_are_rejected(self):
        with self.assertRaises(ValueError):
            canonical_record({"confidence": float("nan")})


class ExplicitUnavailableTests(unittest.TestCase):
    def test_pqc_does_not_claim_success_without_provider(self):
        with self.assertRaises(PQCUnavailable):
            UnavailableProvider().sign(b"record")

    def test_fabric_does_not_claim_success_without_network(self):
        with self.assertRaises(BlockchainUnavailable):
            DisabledBlockchainClient().record("id", "hash", {})


class SafeResponseTests(unittest.TestCase):
    def test_response_remains_simulated_even_when_approved(self):
        decision = decide_healing(
            "CrashLoopBackOff", policy_enabled=True, operator_approved=True
        )
        response = SimulationResponder().execute(decision)
        self.assertEqual(response["status"], "simulated")
        self.assertFalse(response["cluster_mutated"])

    def test_unapproved_or_unknown_actions_are_blocked(self):
        unknown = decide_healing("Unknown", policy_enabled=True, operator_approved=True)
        no_approval = decide_healing(
            "CrashLoopBackOff", policy_enabled=True, operator_approved=False
        )
        self.assertFalse(unknown.approved)
        self.assertFalse(no_approval.approved)
        self.assertEqual(SimulationResponder().execute(no_approval)["status"], "blocked")

    def test_incident_policy_requires_toggle_safe_type_and_noncritical_severity(self):
        disabled = decide_incident_response("resource_exhaustion", "high", ai_eligible=True, policy_enabled=False)
        suspicious = decide_incident_response("suspicious_activity", "high", ai_eligible=True, policy_enabled=True)
        critical = decide_incident_response("resource_exhaustion", "critical", ai_eligible=True, policy_enabled=True)
        eligible = decide_incident_response("resource_exhaustion", "high", ai_eligible=True, policy_enabled=True)
        self.assertFalse(disabled.eligible)
        self.assertFalse(suspicious.eligible)
        self.assertFalse(critical.eligible)
        self.assertEqual(eligible.status, "approval_required")


class DemoDatasetTests(unittest.TestCase):
    def test_demo_dataset_has_multiple_examples_per_label(self):
        path = Path(__file__).resolve().parents[1] / "ai_engine/data/demo_incidents.csv"
        with path.open(encoding="utf-8", newline="") as handle:
            rows = list(csv.DictReader(handle))
        counts: dict[str, int] = {}
        for row in rows:
            counts[row["label"]] = counts.get(row["label"], 0) + 1
        self.assertGreaterEqual(len(counts), 3)
        self.assertTrue(all(count >= 2 for count in counts.values()))


if __name__ == "__main__":
    unittest.main()
