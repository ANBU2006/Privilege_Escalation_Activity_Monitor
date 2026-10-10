"""
Rule-Based Security Detection Engine.
Contains modular, deterministic detection rules for privilege escalation,
unauthorized administrative activity, group modification, and suspicious permission changes.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Any, Set
import pandas as pd


@dataclass
class RuleDefinition:
    """Metadata and defaults for a detection rule."""
    rule_id: str
    name: str
    default_risk: str
    description: str
    recommended_steps: str
    mitre_technique: str


@dataclass
class RuleResult:
    """Outcome of evaluating an audit log entry against a rule."""
    rule_id: str
    rule_name: str
    risk_level: str
    is_flagged: bool
    explanation: str
    investigation_steps: str
    context: Dict[str, Any] = field(default_factory=dict)


# Standard default configuration sets
DEFAULT_CONFIG = {
    "privileged_roles": [
        "Administrator",
        "Domain Admin",
        "Enterprise Admin",
        "Global Admin",
        "root",
        "superuser",
        "Privileged User",
        "admin",
        "wheel",
    ],
    "privileged_groups": [
        "Administrators",
        "Domain Admins",
        "Enterprise Admins",
        "Schema Admins",
        "sudo",
        "root",
        "wheel",
        "Account Operators",
        "Backup Operators",
        "DnsAdmins",
    ],
    "authorized_admin_actors": [
        "sysadmin",
        "secops_admin",
        "it_admin",
        "root",
        "admin_service",
        "authorized_secadmin",
    ],
    "sensitive_resources": [
        "/etc/sudoers",
        "/etc/shadow",
        "/etc/passwd",
        "/etc/pam.d",
        "C:\\Windows\\System32",
        "C:\\Windows\\System32\\config\\SAM",
        "Active Directory",
        "SECURITY_REGISTRY",
        "PAM_CONFIG",
        "Domain Controllers",
        "Root CA",
    ],
    "failed_attempts_threshold": 3,
    "working_hours_start": 8,  # 08:00
    "working_hours_end": 18,   # 18:00
    "work_days": [0, 1, 2, 3, 4],  # Mon=0 through Fri=4
    "rapid_change_window_minutes": 15,
    "rapid_change_threshold": 2,
}


RULE_CATALOG: Dict[str, RuleDefinition] = {
    "RULE-01": RuleDefinition(
        rule_id="RULE-01",
        name="Administrator Account Creation",
        default_risk="HIGH",
        description="Detects creation of new accounts provisioned directly with administrator or privileged roles.",
        recommended_steps="1. Confirm whether an approved change request or ticket authorized this account creation. "
                          "2. Verify initiator identity and IP address. "
                          "3. Inspect target account for immediate unauthorized logon attempts.",
        mitre_technique="T1136.001 - Create Account: Local Account / T1136.002 - Domain Account",
    ),
    "RULE-02": RuleDefinition(
        rule_id="RULE-02",
        name="Privilege Escalation",
        default_risk="HIGH",
        description="Detects elevation of user roles from standard permissions to administrative or superuser privileges.",
        recommended_steps="1. Review IT service management ticket approving elevation. "
                          "2. Verify whether elevation is temporary (JIT/PIM) or permanent. "
                          "3. Audit actor's prior commands and recent authentication activity.",
        mitre_technique="T1548 - Abuse Elevation Control Mechanism / T1078 - Valid Accounts",
    ),
    "RULE-03": RuleDefinition(
        rule_id="RULE-03",
        name="Privileged Group Membership Addition",
        default_risk="HIGH",
        description="Detects addition of users into sensitive administrative groups (e.g., Domain Admins, sudo).",
        recommended_steps="1. Validate membership request with security management. "
                          "2. Check Active Directory or IAM audit logs for corroborating group modification events. "
                          "3. Revoke membership immediately if unauthorized.",
        mitre_technique="T1098 - Account Manipulation",
    ),
    "RULE-04": RuleDefinition(
        rule_id="RULE-04",
        name="Unauthorized Privilege Modification Actor",
        default_risk="HIGH",
        description="Detects privileged role assignments, group additions, or permissions modified by unexpected or non-admin actors.",
        recommended_steps="1. Investigate the actor account for credential compromise or token theft. "
                          "2. Check actor's logon location and source IP reputation. "
                          "3. Isolate the affected endpoint if unauthorized administrative activity is confirmed.",
        mitre_technique="T1078.003 - Local Accounts / T1078.002 - Domain Accounts",
    ),
    "RULE-05": RuleDefinition(
        rule_id="RULE-05",
        name="Repeated Failed Administrative Actions",
        default_risk="MEDIUM",
        description="Detects repeated unsuccessful attempts to execute administrative actions or elevate privileges.",
        recommended_steps="1. Identify if user or script is attempting brute-force permission probes. "
                          "2. Check source IP for scanning or dictionary attack patterns. "
                          "3. Temporarily lock account if suspicious automated attempts persist.",
        mitre_technique="T1110 - Brute Force",
    ),
    "RULE-06": RuleDefinition(
        rule_id="RULE-06",
        name="Suspicious Permission Changes",
        default_risk="MEDIUM",
        description="Detects modifications granting overly permissive access to sensitive operating system resources or configs.",
        recommended_steps="1. Inspect Access Control Lists (ACLs) or file permission attributes on the target resource. "
                          "2. Revert unauthorized 777 or Full Control permissions immediately. "
                          "3. Perform file integrity verification on the affected resource.",
        mitre_technique="T1222 - File and Directory Permissions Modification",
    ),
    "RULE-07": RuleDefinition(
        rule_id="RULE-07",
        name="After-Hours Privileged Activity",
        default_risk="MEDIUM",
        description="Detects privileged actions executed outside standard organizational working hours or on weekends.",
        recommended_steps="1. Verify whether the operator was scheduled for after-hours maintenance or on-call duties. "
                          "2. Contact actor directly via secondary communication channel. "
                          "3. Check for atypical geographic logon origins.",
        mitre_technique="T1078 - Valid Accounts (Anomalous Timing)",
    ),
    "RULE-08": RuleDefinition(
        rule_id="RULE-08",
        name="Rapid Privilege Changes",
        default_risk="HIGH",
        description="Detects rapid successive privilege changes on the same target account within a narrow time window.",
        recommended_steps="1. Examine all actions targeting this account within the window. "
                          "2. Determine if privileges were granted and revoked to evade detection. "
                          "3. Correlate with firewall and endpoint telemetry.",
        mitre_technique="T1098 - Account Manipulation (Rapid Elevation/Revocation)",
    ),
}


class SecurityRuleEngine:
    """Evaluates audit log events against security detection rules using configurable parameters."""

    def __init__(self, custom_config: Optional[Dict[str, Any]] = None):
        self.config = {**DEFAULT_CONFIG}
        if custom_config:
            self.config.update(custom_config)

        # Normalize lookup collections for case-insensitive matching
        self._privileged_roles_set = {r.strip().lower() for r in self.config["privileged_roles"]}
        self._privileged_groups_set = {g.strip().lower() for g in self.config["privileged_groups"]}
        self._authorized_actors_set = {a.strip().lower() for a in self.config["authorized_admin_actors"]}
        self._sensitive_resources = [res.strip().lower() for res in self.config["sensitive_resources"]]

    def is_privileged_role(self, role: Optional[str]) -> bool:
        """Checks if a given role name represents administrative/elevated privileges."""
        if not role:
            return False
        return role.strip().lower() in self._privileged_roles_set

    def is_privileged_group(self, group: Optional[str]) -> bool:
        """Checks if a given group name is a sensitive or administrative security group."""
        if not group:
            return False
        return group.strip().lower() in self._privileged_groups_set

    def is_authorized_actor(self, username: Optional[str]) -> bool:
        """Checks if an actor is in the authorized administrators whitelist."""
        if not username:
            return False
        return username.strip().lower() in self._authorized_actors_set

    def is_sensitive_resource(self, resource: Optional[str]) -> bool:
        """Checks if a resource name or path is in sensitive resources list."""
        if not resource:
            return False
        res_lower = resource.strip().lower()
        return any(sens in res_lower for sens in self._sensitive_resources)

    # -------------------------------------------------------------
    # RULE 1: Administrator Account Creation
    # -------------------------------------------------------------
    def check_admin_account_creation(self, event: Dict[str, Any]) -> Optional[RuleResult]:
        action = str(event.get("action", "")).upper()
        new_role = str(event.get("new_role", "") or "")
        group_name = str(event.get("group_name", "") or "")
        details = str(event.get("details", "") or "")

        create_actions = {"CREATE_USER", "USER_CREATED", "ACCOUNT_CREATE", "NEW_USER", "ADD_ACCOUNT"}
        if action in create_actions:
            is_priv_role = self.is_privileged_role(new_role)
            is_priv_grp = self.is_privileged_group(group_name)
            has_admin_mention = "admin" in new_role.lower() or "admin" in details.lower()

            if is_priv_role or is_priv_grp or has_admin_mention:
                target = event.get("target_user") or event.get("username") or "Unknown"
                actor = event.get("username") or "Unknown"
                role_assigned = new_role if new_role else group_name

                explanation = (
                    f"HIGH RISK: New account '{target}' was created with privileged role '{role_assigned}' "
                    f"by user '{actor}'. Directly provisioning accounts with administrative privileges bypasses "
                    f"standard onboarding and least-privilege principles."
                )
                return RuleResult(
                    rule_id="RULE-01",
                    rule_name=RULE_CATALOG["RULE-01"].name,
                    risk_level=RULE_CATALOG["RULE-01"].default_risk,
                    is_flagged=True,
                    explanation=explanation,
                    investigation_steps=RULE_CATALOG["RULE-01"].recommended_steps,
                    context={"target_user": target, "actor": actor, "assigned_role": role_assigned},
                )
        return None

    # -------------------------------------------------------------
    # RULE 2: Privilege Escalation
    # -------------------------------------------------------------
    def check_privilege_escalation(self, event: Dict[str, Any]) -> Optional[RuleResult]:
        action = str(event.get("action", "")).upper()
        prev_role = str(event.get("previous_role", "") or "").strip()
        new_role = str(event.get("new_role", "") or "").strip()

        escalation_actions = {
            "ASSIGN_ROLE",
            "ROLE_CHANGE",
            "MODIFY_USER",
            "PRIVILEGE_ELEVATION",
            "ELEVATE_ROLE",
            "UPDATE_ROLE",
            "PERMISSION_ELEVATE",
        }

        if action in escalation_actions or (new_role and new_role != prev_role):
            if self.is_privileged_role(new_role) and not self.is_privileged_role(prev_role):
                target = event.get("target_user") or "Unknown"
                actor = event.get("username") or "Unknown"
                p_display = prev_role if prev_role else "Standard/None"

                explanation = (
                    f"HIGH RISK: User '{target}' was elevated from '{p_display}' to '{new_role}' by '{actor}'. "
                    f"This direct privilege escalation grants full administrative authority to the target account."
                )
                return RuleResult(
                    rule_id="RULE-02",
                    rule_name=RULE_CATALOG["RULE-02"].name,
                    risk_level=RULE_CATALOG["RULE-02"].default_risk,
                    is_flagged=True,
                    explanation=explanation,
                    investigation_steps=RULE_CATALOG["RULE-02"].recommended_steps,
                    context={"target_user": target, "previous_role": p_display, "new_role": new_role, "actor": actor},
                )
        return None

    # -------------------------------------------------------------
    # RULE 3: Privileged Group Membership Addition
    # -------------------------------------------------------------
    def check_privileged_group_membership(self, event: Dict[str, Any]) -> Optional[RuleResult]:
        action = str(event.get("action", "")).upper()
        group_name = str(event.get("group_name", "") or "").strip()

        group_actions = {
            "ADD_TO_GROUP",
            "GROUP_MEMBER_ADD",
            "ADD_USER_TO_GROUP",
            "ASSIGN_GROUP",
            "MEMBER_ADDED",
        }

        if (action in group_actions or "GROUP" in action) and self.is_privileged_group(group_name):
            target = event.get("target_user") or "Unknown"
            actor = event.get("username") or "Unknown"

            explanation = (
                f"HIGH RISK: User '{target}' was added to high-privilege security group '{group_name}' "
                f"by actor '{actor}'. Membership in this group grants administrative or root-equivalent rights."
            )
            return RuleResult(
                rule_id="RULE-03",
                rule_name=RULE_CATALOG["RULE-03"].name,
                risk_level=RULE_CATALOG["RULE-03"].default_risk,
                is_flagged=True,
                explanation=explanation,
                investigation_steps=RULE_CATALOG["RULE-03"].recommended_steps,
                context={"target_user": target, "group_name": group_name, "actor": actor},
            )
        return None

    # -------------------------------------------------------------
    # RULE 4: Unauthorized Privilege Modification Actor
    # -------------------------------------------------------------
    def check_unauthorized_actor(self, event: Dict[str, Any]) -> Optional[RuleResult]:
        actor = str(event.get("username", "") or "").strip()
        action = str(event.get("action", "")).upper()
        new_role = str(event.get("new_role", "") or "")
        group_name = str(event.get("group_name", "") or "")
        resource = str(event.get("resource", "") or "")

        # Only evaluate if the action is performing a privileged operation
        is_priv_op = (
            self.is_privileged_role(new_role)
            or self.is_privileged_group(group_name)
            or self.is_sensitive_resource(resource)
            or action in {"ASSIGN_ROLE", "ADD_TO_GROUP", "CREATE_USER", "MODIFY_PERMISSIONS"}
        )

        if is_priv_op and actor and not self.is_authorized_actor(actor):
            target = event.get("target_user") or event.get("resource") or "system"
            explanation = (
                f"HIGH RISK: Privileged operation '{action}' affecting '{target}' was executed by actor '{actor}', "
                f"who is NOT in the authorized security administrator directory. Potential account compromise or insider threat."
            )
            return RuleResult(
                rule_id="RULE-04",
                rule_name=RULE_CATALOG["RULE-04"].name,
                risk_level=RULE_CATALOG["RULE-04"].default_risk,
                is_flagged=True,
                explanation=explanation,
                investigation_steps=RULE_CATALOG["RULE-04"].recommended_steps,
                context={"actor": actor, "action": action, "target": target},
            )
        return None

    # -------------------------------------------------------------
    # RULE 5: Repeated Failed Administrative Actions
    # -------------------------------------------------------------
    def check_failed_administrative_action(
        self, event: Dict[str, Any], failed_count_in_context: int
    ) -> Optional[RuleResult]:
        status = str(event.get("status", "")).upper()
        threshold = self.config.get("failed_attempts_threshold", 3)

        if status == "FAILED" and failed_count_in_context >= threshold:
            actor = event.get("username") or "Unknown"
            ip = event.get("source_ip") or "Unknown"
            action = event.get("action") or "ADMIN_ACTION"

            explanation = (
                f"MEDIUM RISK: Repeated failed administrative operation '{action}' detected for actor '{actor}' "
                f"(Source IP: {ip}). Account or IP reached {failed_count_in_context} failures (threshold: {threshold}), "
                f"indicating potential brute-force attempts, unauthorized tampering, or elevation probing."
            )
            return RuleResult(
                rule_id="RULE-05",
                rule_name=RULE_CATALOG["RULE-05"].name,
                risk_level=RULE_CATALOG["RULE-05"].default_risk,
                is_flagged=True,
                explanation=explanation,
                investigation_steps=RULE_CATALOG["RULE-05"].recommended_steps,
                context={"actor": actor, "source_ip": ip, "failures": failed_count_in_context, "threshold": threshold},
            )
        return None

    # -------------------------------------------------------------
    # RULE 6: Suspicious Permission Changes
    # -------------------------------------------------------------
    def check_suspicious_permission_change(self, event: Dict[str, Any]) -> Optional[RuleResult]:
        action = str(event.get("action", "")).upper()
        resource = str(event.get("resource", "") or "").strip()
        details = str(event.get("details", "") or "")

        perm_actions = {
            "MODIFY_PERMISSIONS",
            "PERMISSION_CHANGE",
            "CHMOD",
            "ACL_MODIFY",
            "GRANT_ACCESS",
            "PERM_MODIFY",
            "GRANT_PERMISSIONS",
        }

        risky_keywords = ["777", "full control", "all=(all)", "write+execute", "everyone", "grant_all"]
        has_risky_keyword = any(kw in details.lower() for kw in risky_keywords)

        if (action in perm_actions or "PERM" in action) and (self.is_sensitive_resource(resource) or has_risky_keyword):
            actor = event.get("username") or "Unknown"
            target_res = resource if resource else "Sensitive Object"

            explanation = (
                f"MEDIUM RISK: Permission modification detected on sensitive asset '{target_res}' by actor '{actor}'. "
                f"Resource is a critical OS component or permissions were granted with elevated scopes."
            )
            return RuleResult(
                rule_id="RULE-06",
                rule_name=RULE_CATALOG["RULE-06"].name,
                risk_level=RULE_CATALOG["RULE-06"].default_risk,
                is_flagged=True,
                explanation=explanation,
                investigation_steps=RULE_CATALOG["RULE-06"].recommended_steps,
                context={"resource": target_res, "actor": actor, "details": details},
            )
        return None

    # -------------------------------------------------------------
    # RULE 7: After-Hours Privileged Activity
    # -------------------------------------------------------------
    def check_after_hours_activity(self, event: Dict[str, Any], event_dt: Optional[datetime]) -> Optional[RuleResult]:
        if not event_dt:
            return None

        # Check if privileged action
        action = str(event.get("action", "")).upper()
        new_role = str(event.get("new_role", "") or "")
        group_name = str(event.get("group_name", "") or "")
        resource = str(event.get("resource", "") or "")

        is_priv = (
            self.is_privileged_role(new_role)
            or self.is_privileged_group(group_name)
            or self.is_sensitive_resource(resource)
            or action in {"ASSIGN_ROLE", "ADD_TO_GROUP", "CREATE_USER", "MODIFY_PERMISSIONS"}
        )

        if not is_priv:
            return None

        start_h = self.config.get("working_hours_start", 8)
        end_h = self.config.get("working_hours_end", 18)
        work_days = self.config.get("work_days", [0, 1, 2, 3, 4])

        hour = event_dt.hour
        weekday = event_dt.weekday()

        is_outside_hours = hour < start_h or hour >= end_h
        is_weekend = weekday not in work_days

        if is_outside_hours or is_weekend:
            actor = event.get("username") or "Unknown"
            time_str = event_dt.strftime("%A %H:%M:%S")
            reason = "weekend" if is_weekend else f"outside standard hours ({start_h:02d}:00-{end_h:02d}:00)"

            explanation = (
                f"MEDIUM RISK: Privileged operation '{action}' was executed at {time_str} by actor '{actor}'. "
                f"Activity occurred {reason}. Unusual timing frequently accompanies unauthorized out-of-band changes."
            )
            return RuleResult(
                rule_id="RULE-07",
                rule_name=RULE_CATALOG["RULE-07"].name,
                risk_level=RULE_CATALOG["RULE-07"].default_risk,
                is_flagged=True,
                explanation=explanation,
                investigation_steps=RULE_CATALOG["RULE-07"].recommended_steps,
                context={"timestamp": time_str, "actor": actor, "action": action, "reason": reason},
            )
        return None

    # -------------------------------------------------------------
    # RULE 8: Rapid Privilege Changes
    # -------------------------------------------------------------
    def check_rapid_privilege_changes(
        self, event: Dict[str, Any], changes_count: int, window_minutes: int
    ) -> Optional[RuleResult]:
        threshold = self.config.get("rapid_change_threshold", 2)
        if changes_count >= threshold:
            target = event.get("target_user") or "Unknown"
            actor = event.get("username") or "Unknown"

            explanation = (
                f"HIGH RISK: Account '{target}' experienced {changes_count} privilege changes within "
                f"{window_minutes} minutes (threshold: {threshold}). Rapid successive privilege adjustments "
                f"often indicate automated permission tampering or rapid grant-and-revoke evasion techniques."
            )
            return RuleResult(
                rule_id="RULE-08",
                rule_name=RULE_CATALOG["RULE-08"].name,
                risk_level=RULE_CATALOG["RULE-08"].default_risk,
                is_flagged=True,
                explanation=explanation,
                investigation_steps=RULE_CATALOG["RULE-08"].recommended_steps,
                context={"target_user": target, "count": changes_count, "window_minutes": window_minutes},
            )
        return None
