import importlib.util
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

if not importlib.util.find_spec("pydantic"):
    raise unittest.SkipTest("pydantic is required for AI response schema tests")

from backend.app.services.ai_client import AIAnalysis, AIClient, AIResponseInvalid, AIUnavailable


class AIClientTests(unittest.TestCase):
    def test_response_is_validated_and_probability_preserved(self):
        result = AIAnalysis.model_validate({
            "classification": "resource_exhaustion",
            "severity": "high",
            "confidence": 0.73,
            "confidence_basis": "classifier class probability",
            "calibrated": False,
            "recommended_action": "Review resources",
            "auto_healing_eligible": True,
            "dataset_notice": "demo",
        })
        self.assertEqual(result.confidence, 0.73)
        self.assertFalse(result.calibrated)

    def test_unreachable_service_is_not_a_prediction(self):
        client = AIClient("http://127.0.0.1:1", timeout=0.1)
        with self.assertRaises(AIUnavailable):
            client.analyze(incident_type="test", summary="test case", description="evidence")

    def test_invalid_response_is_distinguished(self):
        payload = {"classification": "bad", "confidence": 8}

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = json.dumps(payload).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.shutdown)
        client = AIClient(f"http://127.0.0.1:{server.server_port}", timeout=1)
        with self.assertRaises(AIResponseInvalid):
            client.analyze(incident_type="test", summary="test case", description="evidence")


if __name__ == "__main__":
    unittest.main()
