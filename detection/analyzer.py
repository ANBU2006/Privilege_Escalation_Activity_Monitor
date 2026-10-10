"""
Audit Analyzer module.
Processes batches of audit events, correlates temporal and multi-event behaviors,
applies detection rules, and outputs structured security alerts and analytics.
"""

from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
import pandas as pd
import logging

from .rules import SecurityRuleEngine, RuleResult, DEFAULT_CONFIG
from .risk_classifier import RiskClassifier

logger = logging.getLogger(__name__)


class AuditAnalyzer:
    """Analyzes audit log datasets for privilege escalation and security anomalies."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = {**DEFAULT_CONFIG}
        if config:
            self.config.update(config)

        self.rule_engine = SecurityRuleEngine(self.config)
        self.risk_classifier = RiskClassifier()

    def analyze_dataframe(self, df: pd.DataFrame) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """
        Analyzes a validated DataFrame of audit events.
        Returns:
            alerts: List of structured alert dictionaries for each flagged event.
            metrics: Summary metrics and statistical aggregations.
        """
        if df.empty:
            return [], self._empty_metrics()

        # Work on a copy and ensure timestamps are parsed
        df_sorted = df.copy()
        if "parsed_datetime" not in df_sorted.columns:
            df_sorted["parsed_datetime"] = pd.to_datetime(df_sorted["timestamp"], errors="coerce")

        # Sort chronologically for temporal correlation
        df_sorted = df_sorted.sort_values(by="parsed_datetime", ascending=True).reset_index(drop=True)

        alerts: List[Dict[str, Any]] = []

        # Sliding window state trackers
        # 1. Failed attempts tracker: (username or ip) -> list of failure datetimes
        failure_history: Dict[str, List[datetime]] = {}
        # 2. Privilege change tracker: target_user -> list of change datetimes
        priv_change_history: Dict[str, List[datetime]] = {}

        rapid_window = timedelta(minutes=self.config.get("rapid_change_window_minutes", 15))
        failed_window = timedelta(minutes=15)  # 15-minute sliding window for failed attempts

        priv_change_actions = {
            "ASSIGN_ROLE", "ROLE_CHANGE", "ADD_TO_GROUP", "GROUP_MEMBER_ADD",
            "PRIVILEGE_ELEVATION", "MODIFY_USER", "CREATE_USER"
        }

        for _, row in df_sorted.iterrows():
            event = row.to_dict()
            dt = event.get("parsed_datetime")
            if pd.isna(dt) or not isinstance(dt, datetime):
                # Fallback to current time if unparseable
                event_dt = None
            else:
                event_dt = dt.to_pydatetime() if hasattr(dt, "to_pydatetime") else dt

            triggered_rules: List[RuleResult] = []

            # --- Update Temporal State ---
            actor = str(event.get("username", "") or "Unknown").strip()
            source_ip = str(event.get("source_ip", "") or "Unknown").strip()
            status = str(event.get("status", "")).upper()
            action = str(event.get("action", "")).upper()
            target_user = str(event.get("target_user", "") or "").strip()

            # Track failed operations
            failure_key = f"{actor}@{source_ip}" if source_ip else actor
            failed_count = 0
            if status == "FAILED" and event_dt:
                history = failure_history.setdefault(failure_key, [])
                history.append(event_dt)
                # Keep only failures within window
                history = [t for t in history if (event_dt - t) <= failed_window]
                failure_history[failure_key] = history
                failed_count = len(history)
            elif status == "FAILED" and not event_dt:
                # Count session-wide if no valid datetime
                history = failure_history.setdefault(failure_key, [])
                history.append(datetime.utcnow())
                failed_count = len(history)

            # Track rapid privilege changes affecting target user
            rapid_count = 0
            is_priv_change = (
                action in priv_change_actions
                or self.rule_engine.is_privileged_role(event.get("new_role"))
                or self.rule_engine.is_privileged_group(event.get("group_name"))
            )
            if is_priv_change and target_user and event_dt:
                c_history = priv_change_history.setdefault(target_user, [])
                c_history.append(event_dt)
                c_history = [t for t in c_history if (event_dt - t) <= rapid_window]
                priv_change_history[target_user] = c_history
                rapid_count = len(c_history)
            elif is_priv_change and target_user and not event_dt:
                c_history = priv_change_history.setdefault(target_user, [])
                c_history.append(datetime.utcnow())
                rapid_count = len(c_history)

            # --- Evaluate Rules ---
            # RULE-01: Admin Account Creation
            r1 = self.rule_engine.check_admin_account_creation(event)
            if r1:
                triggered_rules.append(r1)

            # RULE-02: Privilege Escalation
            r2 = self.rule_engine.check_privilege_escalation(event)
            if r2:
                triggered_rules.append(r2)

            # RULE-03: Privileged Group Membership
            r3 = self.rule_engine.check_privileged_group_membership(event)
            if r3:
                triggered_rules.append(r3)

            # RULE-04: Unauthorized Privilege Modification Actor
            r4 = self.rule_engine.check_unauthorized_actor(event)
            if r4:
                triggered_rules.append(r4)

            # RULE-05: Repeated Failed Administrative Actions
            r5 = self.rule_engine.check_failed_administrative_action(event, failed_count)
            if r5:
                triggered_rules.append(r5)

            # RULE-06: Suspicious Permission Changes
            r6 = self.rule_engine.check_suspicious_permission_change(event)
            if r6:
                triggered_rules.append(r6)

            # RULE-07: After-Hours Privileged Activity
            r7 = self.rule_engine.check_after_hours_activity(event, event_dt)
            if r7:
                triggered_rules.append(r7)

            # RULE-08: Rapid Privilege Changes
            r8 = self.rule_engine.check_rapid_privilege_changes(
                event, rapid_count, self.config.get("rapid_change_window_minutes", 15)
            )
            if r8:
                triggered_rules.append(r8)

            # --- If rules were triggered, construct alert ---
            if triggered_rules:
                comp_level, comp_score, comp_summary = self.risk_classifier.classify_event(triggered_rules)

                # Primary rule explanation and combined recommended steps
                primary_rule = triggered_rules[0]
                rule_ids = [r.rule_id for r in triggered_rules]
                rule_names = [r.rule_name for r in triggered_rules]

                combined_explanation = "\n\n".join([r.explanation for r in triggered_rules])
                combined_steps = "\n".join([f"[{r.rule_id}] {r.investigation_steps}" for r in triggered_rules])

                alert_record = {
                    "event_id": str(event.get("event_id", "")),
                    "timestamp": str(event.get("timestamp", "")),
                    "username": str(event.get("username", "") or ""),
                    "source_ip": str(event.get("source_ip", "") or ""),
                    "action": str(event.get("action", "") or ""),
                    "target_user": str(event.get("target_user", "") or ""),
                    "resource": str(event.get("resource", "") or ""),
                    "previous_role": str(event.get("previous_role", "") or ""),
                    "new_role": str(event.get("new_role", "") or ""),
                    "group_name": str(event.get("group_name", "") or ""),
                    "status": str(event.get("status", "") or ""),
                    "details": str(event.get("details", "") or ""),
                    "rule_id": primary_rule.rule_id,
                    "rule_name": primary_rule.rule_name,
                    "rules_triggered": rule_ids,
                    "rule_names_list": rule_names,
                    "risk_level": comp_level,
                    "risk_score": comp_score,
                    "explanation": combined_explanation,
                    "investigation_steps": combined_steps,
                    "triggered_count": len(triggered_rules),
                }
                alerts.append(alert_record)

        metrics = self._calculate_metrics(df_sorted, alerts)
        return alerts, metrics

    def _calculate_metrics(self, df: pd.DataFrame, alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculates security metrics and breakdowns from analysis output."""
        total_events = len(df)
        total_suspicious = len(alerts)

        high_count = sum(1 for a in alerts if a["risk_level"] == "HIGH")
        medium_count = sum(1 for a in alerts if a["risk_level"] == "MEDIUM")
        low_count = sum(1 for a in alerts if a["risk_level"] == "LOW")

        # Specific feature counts
        admin_creation_count = sum(1 for a in alerts if "RULE-01" in a["rules_triggered"])
        priv_escalation_count = sum(1 for a in alerts if "RULE-02" in a["rules_triggered"])
        group_membership_count = sum(1 for a in alerts if "RULE-03" in a["rules_triggered"])
        unauth_actor_count = sum(1 for a in alerts if "RULE-04" in a["rules_triggered"])
        failed_actions_count = sum(1 for a in alerts if "RULE-05" in a["rules_triggered"])
        perm_change_count = sum(1 for a in alerts if "RULE-06" in a["rules_triggered"])
        after_hours_count = sum(1 for a in alerts if "RULE-07" in a["rules_triggered"])
        rapid_changes_count = sum(1 for a in alerts if "RULE-08" in a["rules_triggered"])

        rule_breakdown = {
            "Admin Account Creation": admin_creation_count,
            "Privilege Escalation": priv_escalation_count,
            "Privileged Group Membership": group_membership_count,
            "Unauthorized Privilege Actor": unauth_actor_count,
            "Repeated Failed Actions": failed_actions_count,
            "Suspicious Permission Changes": perm_change_count,
            "After-Hours Privileged Activity": after_hours_count,
            "Rapid Privilege Changes": rapid_changes_count,
        }

        risk_distribution = {
            "HIGH": high_count,
            "MEDIUM": medium_count,
            "LOW": low_count,
        }

        suspicious_rate = round((total_suspicious / total_events * 100), 2) if total_events > 0 else 0.0

        return {
            "total_events": total_events,
            "total_suspicious": total_suspicious,
            "suspicious_rate": suspicious_rate,
            "high_count": high_count,
            "medium_count": medium_count,
            "low_count": low_count,
            "admin_creation_count": admin_creation_count,
            "priv_escalation_count": priv_escalation_count,
            "group_membership_count": group_membership_count,
            "unauth_actor_count": unauth_actor_count,
            "failed_actions_count": failed_actions_count,
            "perm_change_count": perm_change_count,
            "after_hours_count": after_hours_count,
            "rapid_changes_count": rapid_changes_count,
            "risk_distribution": risk_distribution,
            "rule_breakdown": rule_breakdown,
        }

    def _empty_metrics(self) -> Dict[str, Any]:
        """Returns baseline empty metrics structure."""
        return {
            "total_events": 0,
            "total_suspicious": 0,
            "suspicious_rate": 0.0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "admin_creation_count": 0,
            "priv_escalation_count": 0,
            "group_membership_count": 0,
            "unauth_actor_count": 0,
            "failed_actions_count": 0,
            "perm_change_count": 0,
            "after_hours_count": 0,
            "rapid_changes_count": 0,
            "risk_distribution": {"HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "rule_breakdown": {},
        }
