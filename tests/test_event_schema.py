import unittest

from schema.event_schema import (
    SCHEMA_VERSION,
    BoundedEventQueue,
    EventDeduplicator,
    ProvenanceInfo,
    SchemaValidationError,
    SecurityEvent,
    migrate_legacy_event,
)


class TestSecurityEventSchema(unittest.TestCase):
    def _sample_event(self, event_id="evt-1", action="exec"):
        return SecurityEvent(
            event_id=event_id,
            timestamp="2026-11-23T12:00:00+00:00",
            asset_id="mac-endpoint-01",
            event_category="process",
            event_action=action,
            severity="medium",
            confidence=0.9,
            provenance=ProvenanceInfo(
                source_component="ghostwire_agent",
                collector_version="2.0.0",
                host_os="macos",
                is_synthetic=False,
            ),
            payload={"pid": 1234, "binary": "/usr/bin/curl"},
        )

    def test_valid_roundtrip_json(self):
        ev = self._sample_event()
        self.assertEqual(ev.schema_version, SCHEMA_VERSION)
        raw = ev.to_dict()
        restored = SecurityEvent.from_dict(raw)
        self.assertEqual(restored.event_id, "evt-1")
        self.assertEqual(restored.payload["pid"], 1234)
        self.assertFalse(restored.provenance.is_synthetic)

    def test_validation_rejects_bad_inputs(self):
        with self.assertRaises(SchemaValidationError):
            SecurityEvent(
                asset_id="host-1",
                event_category="invalid_cat",
                event_action="exec",
                severity="high",
                confidence=0.5,
                provenance=ProvenanceInfo(source_component="test"),
            )
        with self.assertRaises(SchemaValidationError):
            SecurityEvent(
                asset_id="host-1",
                event_category="process",
                event_action="exec",
                severity="high",
                confidence=1.5,
                provenance=ProvenanceInfo(source_component="test"),
            )
        with self.assertRaises(SchemaValidationError):
            SecurityEvent(
                timestamp="not-a-timestamp",
                asset_id="host-1",
                event_category="process",
                event_action="exec",
                severity="high",
                confidence=0.5,
                provenance=ProvenanceInfo(source_component="test"),
            )

    def test_migrate_legacy_v1_telemetry_and_alert(self):
        legacy_tel = {
            "type": "telemetry",
            "phase": "pre",
            "action": "untrusted_exec",
            "agent_id": "agent-01",
            "timestamp": "2026-11-23T12:01:00+00:00",
            "binary": "/tmp/evil.sh",
            "os": "linux",
        }
        migrated = SecurityEvent.from_dict(legacy_tel)
        self.assertEqual(migrated.schema_version, SCHEMA_VERSION)
        self.assertEqual(migrated.event_category, "process")
        self.assertEqual(migrated.event_action, "untrusted_exec.pre")
        self.assertEqual(migrated.asset_id, "agent-01")
        self.assertEqual(migrated.payload["binary"], "/tmp/evil.sh")

        legacy_alert = {
            "type": "alert",
            "agent_id": "agent-01",
            "severity": "WARNING",
            "rule": "heartbeat_anomaly",
            "timestamp": "2026-11-23T12:02:00+00:00",
        }
        migrated_alert = migrate_legacy_event(legacy_alert)
        self.assertEqual(migrated_alert.event_category, "detection_alert")
        self.assertEqual(migrated_alert.severity, "medium")
        self.assertEqual(migrated_alert.correlation.detection_id, "heartbeat_anomaly")

    def test_deduplicator(self):
        dedup = EventDeduplicator(max_entries=2)
        ev1 = self._sample_event(event_id="e1")
        ev2 = self._sample_event(event_id="e2")
        ev3 = self._sample_event(event_id="e3")
        self.assertFalse(dedup.is_duplicate(ev1))
        self.assertTrue(dedup.is_duplicate(ev1))
        self.assertFalse(dedup.is_duplicate(ev2))
        self.assertFalse(dedup.is_duplicate(ev3))
        # ev1 was evicted due to max_entries=2
        self.assertFalse(dedup.is_duplicate(ev1))

    def test_bounded_queue_drop_oldest_emits_telemetry_loss(self):
        q = BoundedEventQueue(max_size=2, policy="drop_oldest", asset_id="host-a")
        self.assertEqual(q.push(self._sample_event(event_id="e1")), (True, None))
        self.assertEqual(q.push(self._sample_event(event_id="e2")), (True, None))
        accepted, loss_ev = q.push(self._sample_event(event_id="e3"))
        self.assertTrue(accepted)
        self.assertIsNotNone(loss_ev)
        self.assertEqual(loss_ev.event_category, "telemetry_loss")
        self.assertEqual(loss_ev.payload["dropped_event_id"], "e1")
        self.assertEqual(q.dropped_count, 1)
        self.assertEqual(len(q), 2)
        self.assertEqual(q.pop().event_id, "e2")

    def test_bounded_queue_reject_new_emits_telemetry_loss(self):
        q = BoundedEventQueue(max_size=1, policy="reject_new", asset_id="host-b")
        q.push(self._sample_event(event_id="e1"))
        accepted, loss_ev = q.push(self._sample_event(event_id="e2"))
        self.assertFalse(accepted)
        self.assertIsNotNone(loss_ev)
        self.assertEqual(loss_ev.payload["reason"], "queue_overflow_reject_new")
        self.assertEqual(q.dropped_count, 1)


if __name__ == "__main__":
    unittest.main()
