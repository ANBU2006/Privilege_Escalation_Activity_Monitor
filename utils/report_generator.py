"""
Report Generator for Privilege Escalation Activity Monitor.
Produces executive summary reports in TXT, CSV, JSON, and Markdown formats
with actionable cybersecurity findings and incident investigation guidance.
"""

import io
import json
from datetime import datetime, timezone
from typing import List, Dict, Any
import pandas as pd


class ReportGenerator:
    """Generates structured cybersecurity audit reports."""

    @staticmethod
    def generate_csv_report(alerts: List[Dict[str, Any]]) -> str:
        """Converts detection alerts into a structured CSV report."""
        if not alerts:
            return "event_id,timestamp,username,source_ip,action,target_user,risk_level,rule_name,explanation\n"

        export_keys = [
            "event_id",
            "timestamp",
            "risk_level",
            "rule_name",
            "username",
            "source_ip",
            "action",
            "target_user",
            "previous_role",
            "new_role",
            "group_name",
            "status",
            "explanation",
            "investigation_steps",
        ]
        rows = []
        for alert in alerts:
            row = {k: alert.get(k, "") for k in export_keys}
            rows.append(row)

        df = pd.DataFrame(rows)
        return df.to_csv(index=False)

    @staticmethod
    def generate_txt_report(
        metrics: Dict[str, Any],
        alerts: List[Dict[str, Any]],
        source_filename: str = "Unknown",
        analyst_notes: str = "",
    ) -> str:
        """Produces a human-readable, executive-ready TXT audit report."""
        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        lines = [
            "=" * 78,
            "               PRIVILEGE ESCALATION ACTIVITY AUDIT REPORT",
            "                     T2-PS7 Cybersecurity Monitoring",
            "=" * 78,
            f"Generated At    : {now_utc}",
            f"Source Log File : {source_filename}",
            f"Classification  : CONFIDENTIAL - SECURITY AUDIT INTERNAL USE ONLY",
            "-" * 78,
            "",
            "1. EXECUTIVE SUMMARY",
            "-------------------",
            f"Total Audit Events Analyzed     : {metrics.get('total_events', 0)}",
            f"Total Suspicious Events Flagged : {metrics.get('total_suspicious', 0)}",
            f"Suspicious Activity Rate        : {metrics.get('suspicious_rate', 0.0)}%",
            "",
            "Risk Distribution Breakdown:",
            f"  - [HIGH RISK]   Critical Detections : {metrics.get('high_count', 0)}",
            f"  - [MEDIUM RISK] Suspicious Patterns : {metrics.get('medium_count', 0)}",
            f"  - [LOW RISK]    Informational Items : {metrics.get('low_count', 0)}",
            "",
            "Category Breakdown:",
            f"  - Administrator Account Creations   : {metrics.get('admin_creation_count', 0)}",
            f"  - Direct Privilege Escalations      : {metrics.get('priv_escalation_count', 0)}",
            f"  - Privileged Group Additions        : {metrics.get('group_membership_count', 0)}",
            f"  - Unauthorized Actor Modifications  : {metrics.get('unauth_actor_count', 0)}",
            f"  - Repeated Failed Admin Actions     : {metrics.get('failed_actions_count', 0)}",
            f"  - Suspicious Permission Changes     : {metrics.get('perm_change_count', 0)}",
            f"  - After-Hours Privileged Operations : {metrics.get('after_hours_count', 0)}",
            f"  - Rapid Privilege Modifications     : {metrics.get('rapid_changes_count', 0)}",
            "",
        ]

        if analyst_notes:
            lines.extend([
                "2. AUDITOR & ANALYST REMARKS",
                "---------------------------",
                analyst_notes,
                "",
            ])

        lines.extend([
            "3. DETAILED SUSPICIOUS FINDINGS",
            "------------------------------",
        ])

        if not alerts:
            lines.append("No suspicious privilege escalation activities were detected in this dataset.")
            lines.append("")
        else:
            for idx, alert in enumerate(alerts, 1):
                lines.extend([
                    f"Finding #{idx:02d} [{alert.get('risk_level', 'LOW')} RISK] - {alert.get('rule_name', 'Rule')}",
                    f"  Event ID         : {alert.get('event_id')}",
                    f"  Timestamp        : {alert.get('timestamp')}",
                    f"  Actor (Username) : {alert.get('username')} (Source IP: {alert.get('source_ip')})",
                    f"  Action           : {alert.get('action')}",
                    f"  Target Account   : {alert.get('target_user', 'N/A')}",
                    f"  Role Elevation   : {alert.get('previous_role', 'None')} -> {alert.get('new_role', 'None')}",
                    f"  Group Impacted   : {alert.get('group_name', 'N/A')}",
                    f"  Outcome Status   : {alert.get('status', 'N/A')}",
                    "  Explanation:",
                    f"    {alert.get('explanation', '').replace(chr(10), chr(10) + '    ')}",
                    "  Recommended Investigation Steps:",
                    f"    {alert.get('investigation_steps', '').replace(chr(10), chr(10) + '    ')}",
                    "-" * 78,
                ])

        lines.extend([
            "",
            "4. STRATEGIC SECURITY RECOMMENDATIONS",
            "-------------------------------------",
            "1. Implement Just-In-Time (JIT) and Privileged Identity Management (PIM) to eliminate",
            "   permanent standing administrative roles.",
            "2. Enforce Multi-Factor Authentication (MFA) and restricted jump hosts for all accounts",
            "   authorized to modify directory groups or system roles.",
            "3. Establish mandatory change request tickets for all out-of-band and after-hours",
            "   administrative actions.",
            "4. Deploy automated alerts to Security Operations Center (SOC) on any addition to",
            "   'Domain Admins', 'sudo', or 'Administrators' groups.",
            "5. Review and restrict sensitive OS files (/etc/sudoers, SAM registry) using strict",
            "   file integrity monitoring (FIM).",
            "",
            "5. AUDIT & LEGAL DISCLAIMER",
            "---------------------------",
            "This report is generated by a rule-based cybersecurity monitoring engine for educational",
            "and authorized auditing purposes. Findings indicate policy violations or anomalies",
            "and require secondary human verification prior to taking disciplinary or punitive actions.",
            "=" * 78,
            "                            END OF REPORT",
            "=" * 78,
        ])

        return "\n".join(lines)

    @staticmethod
    def generate_json_report(
        metrics: Dict[str, Any], alerts: List[Dict[str, Any]], source_filename: str = "Unknown"
    ) -> str:
        """Produces machine-readable JSON security report."""
        report_data = {
            "report_metadata": {
                "title": "Privilege Escalation Activity Audit Report",
                "version": "1.0.0",
                "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                "source_file": source_filename,
            },
            "metrics": metrics,
            "alerts": alerts,
        }
        return json.dumps(report_data, indent=2)
