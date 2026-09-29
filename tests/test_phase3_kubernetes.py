import unittest

from kubernetes.detection import DetectionRules, deduplicate_conditions, detect_conditions
from kubernetes.actions import ALLOWED_ACTIONS
from kubernetes.policy import decide_incident_response
from kubernetes.providers import (
    KubernetesRESTProvider, KubernetesUnavailable, MockKubernetesProvider,
    UnavailableKubernetesProvider, validate_resource_name,
)
from kubernetes.response_policy import evaluate_response_policy
from kubernetes.verification import verify_deployment_action, verify_with_retries


def pod(name, phase="Running", restarts=0, waiting=None):
    state = {"waiting": {"reason": waiting}} if waiting else {"running": {}}
    return {"metadata": {"namespace": "payments", "name": name, "uid": name}, "status": {
        "phase": phase, "containerStatuses": [{"name": "api", "restartCount": restarts, "state": state}],
    }}


class KubernetesProviderTests(unittest.TestCase):
    def test_mock_provider_returns_fixture_and_identifies_as_mock(self):
        provider = MockKubernetesProvider(pod_items=[pod("api")])
        self.assertEqual(provider.health()["provider"], "mock")
        self.assertTrue(provider.health()["simulation"])
        self.assertEqual(provider.pods("payments")[0]["metadata"]["name"], "api")

    def test_unavailable_provider_is_explicit(self):
        provider = UnavailableKubernetesProvider()
        with self.assertRaises(KubernetesUnavailable):
            provider.pods()

    def test_resource_name_validation(self):
        self.assertEqual(validate_resource_name("payments-api"), "payments-api")
        for invalid in ("../etc", "BadName", "", "x;id"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                validate_resource_name(invalid)

    def test_rest_adapter_has_no_arbitrary_command_surface(self):
        provider = KubernetesRESTProvider("https://cluster.invalid", "test-token")
        calls = []
        provider._request = lambda path, **kwargs: calls.append((path, kwargs)) or {}
        provider.act("restart_deployment", "payments", "api")
        self.assertTrue(calls[0][0].endswith("/namespaces/payments/deployments/api"))
        self.assertEqual(calls[0][1]["method"], "PATCH")
        self.assertEqual(ALLOWED_ACTIONS, {"restart_deployment", "scale_deployment"})
        with self.assertRaises(ValueError):
            provider.act("kubectl", "payments", "api")


class KubernetesDetectionTests(unittest.TestCase):
    def test_detects_restart_crash_and_deployment_conditions(self):
        provider = MockKubernetesProvider(
            pod_items=[pod("api", phase="Pending", restarts=7, waiting="CrashLoopBackOff")],
            deployment_items=[{"metadata": {"namespace": "payments", "name": "api"},
                              "spec": {"replicas": 3}, "status": {"readyReplicas": 1}}],
            event_items=[{"metadata": {"namespace": "payments", "name": "event-1"},
                          "reason": "FailedMount", "message": "volume attachment pending"}],
        )
        found = detect_conditions(provider, DetectionRules(restart_threshold=5, repeated_crash_count=3))
        types = {item["condition_type"] for item in found}
        self.assertTrue({"pod_crash_loop", "excessive_pod_restarts", "unhealthy_pod", "failed_deployment", "security_relevant_event"}.issubset(types))
        self.assertTrue(all(item["classification"] == "operational_anomaly" for item in found))

    def test_detection_thresholds_are_configurable(self):
        provider = MockKubernetesProvider(pod_items=[pod("api", restarts=2, waiting="CrashLoopBackOff")])
        self.assertEqual(detect_conditions(provider, DetectionRules(restart_threshold=3, repeated_crash_count=3)), [])

    def test_duplicate_condition_fingerprints_are_removed(self):
        items = [{"fingerprint": "a"}, {"fingerprint": "a"}, {"fingerprint": "b"}]
        known = {"a"}
        self.assertEqual(deduplicate_conditions(items, known), [{"fingerprint": "b"}])
        self.assertEqual(known, {"a", "b"})


class ResponsePolicyTests(unittest.TestCase):
    def test_severity_never_silently_authorizes_real_action(self):
        for severity in ("low", "medium", "high", "critical"):
            with self.subTest(severity=severity):
                decision = evaluate_response_policy(severity, requested_action="restart_deployment")
                self.assertTrue(decision.approval_required)
                self.assertNotEqual(decision.decision, "execute")

    def test_critical_requires_approval_and_disallowed_actions_are_blocked(self):
        critical = evaluate_response_policy("critical", requested_action="scale_deployment")
        blocked = evaluate_response_policy("high", requested_action="delete_namespace")
        self.assertEqual(critical.decision, "approval_required")
        self.assertEqual(blocked.decision, "blocked")

    def test_phase_two_policy_remains_simulation_only(self):
        decision = decide_incident_response("resource_exhaustion", "high", ai_eligible=True, policy_enabled=True)
        self.assertEqual(decision.status, "approval_required")

    def test_post_action_verification_requires_observed_desired_state(self):
        before = {"metadata": {"generation": 4}}
        self.assertTrue(verify_deployment_action("restart_deployment", before, {
            "metadata": {"generation": 5}, "status": {"observedGeneration": 5},
        }))
        self.assertFalse(verify_deployment_action("restart_deployment", before, {
            "metadata": {"generation": 5}, "status": {"observedGeneration": 4},
        }))
        self.assertTrue(verify_deployment_action("scale_deployment", {}, {
            "spec": {"replicas": 2}, "status": {"readyReplicas": 2},
        }, 2))
        self.assertFalse(verify_deployment_action("scale_deployment", {}, {
            "spec": {"replicas": 2}, "status": {"readyReplicas": 1},
        }, 2))

    def test_bounded_verification_retries_until_converged(self):
        states = iter([{"metadata": {"generation": 4}, "status": {"observedGeneration": 4}},
                       {"metadata": {"generation": 5}, "status": {"observedGeneration": 5}}])
        result, attempts = verify_with_retries(lambda: next(states), action="restart_deployment",
                                              before={"metadata": {"generation": 4}}, replicas=None,
                                              max_attempts=3, delay_seconds=0)
        self.assertEqual(result, "VERIFIED")
        self.assertEqual([entry["status"] for entry in attempts], ["PENDING", "VERIFIED"])

    def test_bounded_verification_times_out_and_provider_errors_stay_unavailable(self):
        result, attempts = verify_with_retries(lambda: None, action="restart_deployment",
                                              before={}, replicas=None, max_attempts=2,
                                              delay_seconds=0)
        self.assertEqual(result, "TIMEOUT")
        self.assertEqual(len(attempts), 2)

        def unavailable():
            raise KubernetesUnavailable("fixture")
        result, attempts = verify_with_retries(unavailable, action="restart_deployment",
                                              before={}, replicas=None, max_attempts=2,
                                              delay_seconds=0)
        self.assertEqual(result, "UNAVAILABLE")
        self.assertEqual(len(attempts), 2)


if __name__ == "__main__":
    unittest.main()
