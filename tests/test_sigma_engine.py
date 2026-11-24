import os
import unittest

from schema.event_schema import ProvenanceInfo, SecurityEvent
from security.sigma_engine import (
    RuleException,
    SigmaEngine,
    evaluate_corpus,
    load_sigma_rules_from_dir,
)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SIGMA_DIR = os.path.join(REPO_ROOT, "rules", "sigma")


class TestSigmaEngine(unittest.TestCase):
    def test_load_all_repo_sigma_rules_without_errors(self):
        rules, errors = load_sigma_rules_from_dir(SIGMA_DIR)
        self.assertEqual(errors, [], f"Sigma parse errors: {errors}")
        self.assertEqual(len(rules), 12)
        for r in rules:
            self.assertTrue(r.rule_id)
            self.assertTrue(r.title)
            self.assertTrue(r.condition)

    def test_untrusted_binary_rule_v1_and_v2_schema(self):
        rules, _ = load_sigma_rules_from_dir(SIGMA_DIR)
        engine = SigmaEngine(rules)

        # Positive v1 record: binary outside /usr/bin, /bin, /usr/sbin, /sbin
        bad_v1 = {
            "type": "telemetry",
            "action": "process_exec",
            "phase": "pre",
            "details": {"binary_path": "/tmp/dropper"},
        }
        matches = engine.evaluate_event(bad_v1)
        titles = [m.title for m in matches]
        self.assertIn("Security Lab - Process Execution From Untrusted Binary Path", titles)

        # Negative v2 SecurityEvent: trusted /usr/bin/ls
        good_v2 = SecurityEvent(
            asset_id="mac-01",
            event_category="process",
            event_action="process_exec.pre",
            severity="info",
            confidence=1.0,
            provenance=ProvenanceInfo(source_component="test"),
            payload={"details": {"binary_path": "/usr/bin/ls"}},
        )
        good_matches = engine.evaluate_event(good_v2)
        self.assertEqual(good_matches, [])

    def test_rule_disable_and_false_positive_exception(self):
        rules, _ = load_sigma_rules_from_dir(SIGMA_DIR)
        engine = SigmaEngine(rules)
        untrusted_id = "6f1c2a7e-3b1d-4c6a-9e0f-1a2b3c4d5e01"

        bad_ev = {
            "type": "telemetry",
            "action": "process_exec",
            "phase": "pre",
            "details": {"binary_path": "/opt/homebrew/bin/python3"},
        }
        # Exception suppresses FP
        engine.add_exception(
            RuleException(
                rule_id=untrusted_id,
                field="details.binary_path",
                operator="startswith",
                value="/opt/homebrew/bin/",
                reason="Approved Homebrew toolchain",
            )
        )
        matches = engine.evaluate_event(bad_ev)
        target = [m for m in matches if m.rule_id == untrusted_id]
        self.assertEqual(len(target), 1)
        self.assertTrue(target[0].suppressed_by_exception)

        # Disable rule completely
        self.assertTrue(engine.set_rule_enabled(untrusted_id, False))
        self.assertEqual(engine.evaluate_event(bad_ev), [])

    def test_auth_failure_burst_aggregation(self):
        rules, _ = load_sigma_rules_from_dir(SIGMA_DIR)
        engine = SigmaEngine(rules)
        burst_id = "6f1c2a7e-3b1d-4c6a-9e0f-1a2b3c4d5e06"

        for i in range(4):
            ev = {
                "type": "server_event",
                "event": "auth_failed",
                "peer": "192.168.56.99",
                "timestamp": f"2026-11-23T12:00:0{i}+00:00",
            }
            matches = [m for m in engine.evaluate_event(ev) if m.rule_id == burst_id]
            if i < 3:
                self.assertEqual(matches, [])
            else:
                self.assertEqual(len(matches), 1)

    def test_deterministic_corpus_evaluation_metrics(self):
        rules, _ = load_sigma_rules_from_dir(SIGMA_DIR)
        engine = SigmaEngine(rules)
        corpus = [
            ({"type": "telemetry", "action": "process_exec", "phase": "pre", "details": {"binary_path": "/tmp/evil"}}, True),
            ({"type": "telemetry", "action": "process_exec", "phase": "pre", "details": {"binary_path": "/usr/bin/env"}}, False),
            ({"type": "telemetry", "action": "process_exec", "phase": "pre", "details": {"binary_path": "/bin/sh"}}, False),
        ]
        metrics = evaluate_corpus(engine, corpus)
        self.assertEqual(metrics["tp"], 1)
        self.assertEqual(metrics["fp"], 0)
        self.assertEqual(metrics["fn"], 0)
        self.assertEqual(metrics["tn"], 2)
        self.assertEqual(metrics["precision"], 1.0)
        self.assertEqual(metrics["recall"], 1.0)


if __name__ == "__main__":
    unittest.main()
