"""
Unit and Integration Tests for Privilege Escalation Activity Monitor.
Covers all 8 detection rules, risk classification, parser resilience,
database deduplication, and audit report generation.
"""

import unittest
import io
import os
import tempfile
from datetime import datetime
import pandas as pd

from detection.rules import SecurityRuleEngine, DEFAULT_CONFIG
from detection.risk_classifier import RiskClassifier
from detection.analyzer import AuditAnalyzer
from utils.log_parser import LogParser
from utils.report_generator import ReportGenerator
from database.db_manager import DatabaseManager


class TestDetectionRules(unittest.TestCase):
    """Tests each individual detection rule in isolation."""

    def setUp(self):
        self.engine = SecurityRuleEngine()

    def test_admin_account_creation_detected(self):
        """RULE-01: Verifies detection of new accounts provisioned with administrative roles."""
        event = {
            "event_id": "EVT-T01",
            "timestamp": "2026-10-05 10:00:00",
            "username": "sysadmin",
            "action": "CREATE_USER",
            "target_user": "shadow_admin",
            "new_role": "Administrator",
            "group_name": "Administrators",
            "status": "SUCCESS",
        }
        result = self.engine.check_admin_account_creation(event)
        self.assertIsNotNone(result)
        self.assertEqual(result.rule_id, "RULE-01")
        self.assertEqual(result.risk_level, "HIGH")
        self.assertIn("shadow_admin", result.explanation)

    def test_admin_account_creation_benign(self):
        """Verifies that standard user creation is not falsely flagged."""
        event = {
            "event_id": "EVT-T02",
            "timestamp": "2026-10-05 10:00:00",
            "username": "sysadmin",
            "action": "CREATE_USER",
            "target_user": "regular_john",
            "new_role": "Standard User",
            "group_name": "Domain Users",
            "status": "SUCCESS",
        }
        result = self.engine.check_admin_account_creation(event)
        self.assertIsNone(result)

    def test_privilege_escalation_detected(self):
        """RULE-02: Verifies detection of standard user elevation to administrative role."""
        event = {
            "event_id": "EVT-T03",
            "timestamp": "2026-10-05 11:00:00",
            "username": "sysadmin",
            "action": "ASSIGN_ROLE",
            "target_user": "arun",
            "previous_role": "Standard User",
            "new_role": "Administrator",
            "status": "SUCCESS",
        }
        result = self.engine.check_privilege_escalation(event)
        self.assertIsNotNone(result)
        self.assertEqual(result.rule_id, "RULE-02")
        self.assertEqual(result.risk_level, "HIGH")
        self.assertIn("elevated from 'Standard User' to 'Administrator'", result.explanation)

    def test_privilege_escalation_benign(self):
        """Verifies that routine role lateral change is not flagged as privilege escalation."""
        event = {
            "event_id": "EVT-T04",
            "timestamp": "2026-10-05 11:00:00",
            "username": "sysadmin",
            "action": "ASSIGN_ROLE",
            "target_user": "marketing_user",
            "previous_role": "Viewer",
            "new_role": "Editor",
            "status": "SUCCESS",
        }
        result = self.engine.check_privilege_escalation(event)
        self.assertIsNone(result)

    def test_sensitive_group_membership_detected(self):
        """RULE-03: Verifies detection of addition to sensitive group like Domain Admins."""
        event = {
            "event_id": "EVT-T05",
            "timestamp": "2026-10-05 12:00:00",
            "username": "sysadmin",
            "action": "ADD_TO_GROUP",
            "target_user": "svc_test",
            "group_name": "Domain Admins",
            "status": "SUCCESS",
        }
        result = self.engine.check_privileged_group_membership(event)
        self.assertIsNotNone(result)
        self.assertEqual(result.rule_id, "RULE-03")
        self.assertEqual(result.risk_level, "HIGH")

    def test_unauthorized_actor_detected(self):
        """RULE-04: Verifies flagging of unauthorized actor performing privileged changes."""
        event = {
            "event_id": "EVT-T06",
            "timestamp": "2026-10-05 13:00:00",
            "username": "unauthorized_intern",
            "action": "ASSIGN_ROLE",
            "target_user": "unauthorized_intern",
            "new_role": "root",
            "status": "SUCCESS",
        }
        result = self.engine.check_unauthorized_actor(event)
        self.assertIsNotNone(result)
        self.assertEqual(result.rule_id, "RULE-04")
        self.assertEqual(result.risk_level, "HIGH")
        self.assertIn("unauthorized_intern", result.explanation)

    def test_repeated_failed_operations_detected(self):
        """RULE-05: Verifies flagging when failed attempts reach configured threshold."""
        event = {
            "event_id": "EVT-T07",
            "timestamp": "2026-10-05 14:00:00",
            "username": "attacker",
            "source_ip": "1.2.3.4",
            "action": "ASSIGN_ROLE",
            "status": "FAILED",
        }
        # Below threshold
        self.assertIsNone(self.engine.check_failed_administrative_action(event, failed_count_in_context=2))
        # At or above threshold (default 3)
        res = self.engine.check_failed_administrative_action(event, failed_count_in_context=3)
        self.assertIsNotNone(res)
        self.assertEqual(res.rule_id, "RULE-05")
        self.assertEqual(res.risk_level, "MEDIUM")

    def test_suspicious_permission_change_detected(self):
        """RULE-06: Verifies detection of modifications to critical assets like /etc/sudoers."""
        event = {
            "event_id": "EVT-T08",
            "timestamp": "2026-10-05 15:00:00",
            "username": "sysadmin",
            "action": "MODIFY_PERMISSIONS",
            "resource": "/etc/sudoers",
            "details": "Grant 777 Full Control",
            "status": "SUCCESS",
        }
        result = self.engine.check_suspicious_permission_change(event)
        self.assertIsNotNone(result)
        self.assertEqual(result.rule_id, "RULE-06")
        self.assertEqual(result.risk_level, "MEDIUM")

    def test_after_hours_activity_detected(self):
        """RULE-07: Verifies flagging of privileged operations at midnight or weekends."""
        event = {
            "event_id": "EVT-T09",
            "username": "night_admin",
            "action": "ASSIGN_ROLE",
            "new_role": "Administrator",
            "status": "SUCCESS",
        }
        # Event at 02:30 AM (outside 08:00 - 18:00)
        dt_night = datetime(2026, 10, 6, 2, 30, 0)
        res = self.engine.check_after_hours_activity(event, dt_night)
        self.assertIsNotNone(res)
        self.assertEqual(res.rule_id, "RULE-07")
        self.assertEqual(res.risk_level, "MEDIUM")

        # Event at 10:30 AM on Tuesday (normal working hours)
        dt_work = datetime(2026, 10, 6, 10, 30, 0)
        res_work = self.engine.check_after_hours_activity(event, dt_work)
        self.assertIsNone(res_work)

    def test_rapid_privilege_changes_detected(self):
        """RULE-08: Verifies flagging when target user experiences repeated rapid privilege changes."""
        event = {
            "event_id": "EVT-T10",
            "target_user": "quick_target",
            "action": "ASSIGN_ROLE",
            "new_role": "Administrator",
        }
        # Below threshold
        self.assertIsNone(self.engine.check_rapid_privilege_changes(event, changes_count=1, window_minutes=15))
        # At threshold 2
        res = self.engine.check_rapid_privilege_changes(event, changes_count=2, window_minutes=15)
        self.assertIsNotNone(res)
        self.assertEqual(res.rule_id, "RULE-08")
        self.assertEqual(res.risk_level, "HIGH")


class TestRiskClassifier(unittest.TestCase):
    """Tests risk classification and compound multi-rule weighting."""

    def setUp(self):
        self.classifier = RiskClassifier()
        self.engine = SecurityRuleEngine()

    def test_risk_classification_hierarchy(self):
        # High risk rule
        r_high = self.engine.check_admin_account_creation({
            "action": "CREATE_USER", "new_role": "Administrator", "target_user": "u1"
        })
        level, score, _ = self.classifier.classify_event([r_high])
        self.assertEqual(level, "HIGH")
        self.assertGreaterEqual(score, 10)

        # Compound rules escalate and produce informative summary
        r_med = self.engine.check_suspicious_permission_change({
            "action": "MODIFY_PERMISSIONS", "resource": "/etc/sudoers"
        })
        c_level, c_score, c_summary = self.classifier.classify_event([r_high, r_med])
        self.assertEqual(c_level, "HIGH")
        self.assertIn("COMPOUND ALERT", c_summary)
        self.assertGreater(c_score, score)


class TestLogParser(unittest.TestCase):
    """Tests CSV and JSON log parsing, validation, and error resilience."""

    def test_valid_csv_parsing(self):
        csv_data = io.StringIO(
            "event_id,timestamp,username,source_ip,action,target_user,resource,previous_role,new_role,group_name,status,details\n"
            "EVT-01,2026-10-05 10:00:00,admin,10.0.0.1,LOGIN,admin,srv1,,,,SUCCESS,Clean login\n"
        )
        res = LogParser.parse_file(csv_data, file_name="audit.csv")
        self.assertTrue(res.is_valid)
        self.assertEqual(len(res.df), 1)
        self.assertEqual(res.df.iloc[0]["event_id"], "EVT-01")

    def test_valid_json_parsing(self):
        json_data = io.StringIO(
            '[{"event_id": "EVT-J1", "timestamp": "2026-10-05 10:00:00", "action": "LOGIN", "username": "alice", "status": "SUCCESS"}]'
        )
        res = LogParser.parse_file(json_data, file_name="audit.json")
        self.assertTrue(res.is_valid)
        self.assertEqual(len(res.df), 1)
        self.assertEqual(res.df.iloc[0]["event_id"], "EVT-J1")

    def test_missing_required_fields(self):
        # Missing action column
        bad_csv = io.StringIO("event_id,timestamp,username\nEVT-01,2026-10-05,alice\n")
        res = LogParser.parse_file(bad_csv, file_name="bad.csv")
        self.assertFalse(res.is_valid)
        self.assertTrue(any("Missing required audit field" in err for err in res.errors))

    def test_empty_audit_log_file(self):
        empty_io = io.BytesIO(b"")
        res = LogParser.parse_file(empty_io, file_name="empty.csv")
        self.assertFalse(res.is_valid)
        self.assertTrue(any("empty" in err.lower() for err in res.errors))

    def test_sanitization_removes_dangerous_scripts(self):
        dirty = "<script>alert('xss')</script>John"
        clean = LogParser.sanitize_string(dirty)
        self.assertNotIn("<script>", clean)
        self.assertIn("&lt;script&gt;", clean)

    def test_semicolon_delimited_csv(self):
        semi_csv = io.BytesIO(b"timestamp;action;username;status\n2026-10-05 10:00:00;LOGIN;alice;SUCCESS\n")
        res = LogParser.parse_file(semi_csv, file_name="semi.csv")
        self.assertTrue(res.is_valid)
        self.assertEqual(len(res.df), 1)
        self.assertEqual(res.df.iloc[0]["action"], "LOGIN")

    def test_bom_prefixed_csv(self):
        bom_csv = io.BytesIO(b"\xef\xbb\xbftimestamp,action,username,status\n2026-10-05 10:00:00,LOGIN,alice,SUCCESS\n")
        res = LogParser.parse_file(bom_csv, file_name="bom.csv")
        self.assertTrue(res.is_valid)
        self.assertEqual(len(res.df), 1)
        self.assertEqual(res.df.iloc[0]["username"], "alice")

    def test_custom_column_mapping(self):
        custom_csv = io.BytesIO(b"Time,EventName,Operator\n2026-10-05 10:00:00,ASSIGN_ROLE,bob\n")
        res = LogParser.parse_file(custom_csv, file_name="custom.csv")
        self.assertTrue(res.is_valid)  # "Time" and "EventName" automatically map via extended aliases!
        self.assertEqual(res.df.iloc[0]["action"], "ASSIGN_ROLE")



class TestDatabaseManager(unittest.TestCase):
    """Tests SQLite persistence, deduplication, and retrieval."""

    def setUp(self):
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_db.close()
        self.db = DatabaseManager(self.temp_db.name)

    def tearDown(self):
        if os.path.exists(self.temp_db.name):
            try:
                os.remove(self.temp_db.name)
            except OSError:
                pass

    def test_duplicate_events_ignored(self):
        events = pd.DataFrame([
            {"event_id": "EVT-D01", "timestamp": "2026-10-05 10:00:00", "action": "LOGIN", "username": "alice", "status": "SUCCESS"},
            {"event_id": "EVT-D01", "timestamp": "2026-10-05 10:00:00", "action": "LOGIN", "username": "alice", "status": "SUCCESS"},
        ])
        # First insert
        inserted_1 = self.db.insert_audit_events(events.iloc[[0]])
        self.assertEqual(inserted_1, 1)

        # Duplicate insert of same event_id
        inserted_2 = self.db.insert_audit_events(events.iloc[[1]])
        self.assertEqual(inserted_2, 0)  # Should be ignored

        stored = self.db.get_all_events()
        self.assertEqual(len(stored), 1)


class TestReportGenerator(unittest.TestCase):
    """Tests CSV, TXT, and JSON report generation."""

    def test_report_generation_formats(self):
        metrics = {
            "total_events": 10,
            "total_suspicious": 2,
            "suspicious_rate": 20.0,
            "high_count": 1,
            "medium_count": 1,
            "low_count": 0,
            "admin_creation_count": 1,
            "priv_escalation_count": 0,
            "group_membership_count": 0,
            "unauth_actor_count": 0,
            "failed_actions_count": 0,
            "perm_change_count": 1,
            "after_hours_count": 0,
            "rapid_changes_count": 0,
        }
        alerts = [{
            "event_id": "EVT-R01",
            "timestamp": "2026-10-05 10:00:00",
            "username": "sysadmin",
            "source_ip": "10.0.0.1",
            "action": "CREATE_USER",
            "target_user": "shadow_admin",
            "risk_level": "HIGH",
            "rule_name": "Administrator Account Creation",
            "explanation": "High risk account creation",
            "investigation_steps": "Check change request ticket",
        }]

        # Test CSV export
        csv_rep = ReportGenerator.generate_csv_report(alerts)
        self.assertIn("EVT-R01", csv_rep)
        self.assertIn("shadow_admin", csv_rep)

        # Test TXT export
        txt_rep = ReportGenerator.generate_txt_report(metrics, alerts, source_filename="sample.csv")
        self.assertIn("PRIVILEGE ESCALATION ACTIVITY AUDIT REPORT", txt_rep)
        self.assertIn("Total Audit Events Analyzed     : 10", txt_rep)
        self.assertIn("STRATEGIC SECURITY RECOMMENDATIONS", txt_rep)

        # Test JSON export
        json_rep = ReportGenerator.generate_json_report(metrics, alerts, source_filename="sample.csv")
        self.assertIn("Privilege Escalation Activity Audit Report", json_rep)
        self.assertIn("EVT-R01", json_rep)


if __name__ == "__main__":
    unittest.main()
