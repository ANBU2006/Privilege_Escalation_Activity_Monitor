"""
Dynamic Synthetic Audit Log Generator for Privilege Escalation Activity Monitor.
Generates realistic, completely randomized audit datasets on-demand with fresh timestamps,
users, IP addresses, and varied combinations of benign and attack scenarios across all 8 rules.
"""

import random
import uuid
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import pandas as pd


class AuditDataGenerator:
    """Generates fresh synthetic audit logs with configurable size and threat scenarios."""

    USERS_POOL = [
        "alice.smith", "bob.jones", "charlie.brown", "david.lee", "sarah.connor",
        "elena.rostova", "marcus.vance", "priya.patel", "samuel.jackson", "chen.wei",
        "liam.miller", "sophia.taylor", "hassan.ali", "kevin.durant", "emma.watson",
        "lucas.silva", "maria.garcia", "dev_intern_1", "dev_intern_2", "guest_contractor",
        "temp_consultant", "vendor_support", "audit_bot", "night_operator", "shadow_user"
    ]

    AUTHORIZED_ADMINS = [
        "sysadmin", "secops_admin", "it_admin", "root", "admin_service", "authorized_secadmin"
    ]

    UNAUTHORIZED_ACTORS = [
        "intern_dev", "guest_contractor", "temp_consultant", "vendor_support",
        "night_operator", "unknown_actor", "attacker_pivot", "contractor_mike"
    ]

    BENIGN_ROLES = ["Standard User", "Viewer", "Editor", "Contributor", "Junior Developer", "Analyst", "Operator"]
    PRIVILEGED_ROLES = ["Administrator", "root", "Domain Admin", "Enterprise Admin", "Global Admin", "superuser", "Privileged User"]

    BENIGN_GROUPS = ["Domain Users", "HR_Employees", "Finance_Team", "Marketing_Team", "Engineering", "Operations", "Consultants"]
    PRIVILEGED_GROUPS = ["Administrators", "Domain Admins", "sudo", "wheel", "Enterprise Admins", "Backup Operators", "Account Operators"]

    SENSITIVE_RESOURCES = [
        "/etc/sudoers", "/etc/shadow", "/etc/pam.d/su",
        "C:\\Windows\\System32\\config\\SAM", "/etc/passwd",
        "C:\\Windows\\System32\\drivers\\etc\\hosts"
    ]

    STANDARD_RESOURCES = [
        "Workstation-01", "Workstation-05", "IAM_Console", "Payroll_Portal",
        "ERP_System", "Active Directory", "File_Share", "Cloud_Portal", "Database_Cluster"
    ]

    @classmethod
    def generate_logs(
        cls,
        num_events: int = 25,
        attack_ratio: float = 0.35,
        start_time: Optional[datetime] = None,
    ) -> pd.DataFrame:
        """
        Generates a DataFrame of randomized audit events.
        Guarantees fresh timestamps, unique event IDs, and realistic scenario distribution.
        """
        if start_time is None:
            # Spread over the past 24-48 hours up to now
            start_time = datetime.now() - timedelta(hours=min(48, num_events * 1.5))

        current_time = start_time
        events: List[Dict[str, Any]] = []
        target_attacks = max(3, int(num_events * attack_ratio))
        normal_events = num_events - target_attacks

        # Build list of attack types to include
        attack_types = [
            "RULE-01",  # Admin account creation
            "RULE-02",  # Privilege escalation
            "RULE-03",  # Privileged group addition
            "RULE-04",  # Unauthorized actor
            "RULE-05",  # Repeated failed attempts
            "RULE-06",  # Suspicious permissions
            "RULE-07",  # After-hours action
            "RULE-08",  # Rapid privilege changes
        ]
        random.shuffle(attack_types)

        attack_schedule = []
        for i in range(target_attacks):
            rule = attack_types[i % len(attack_types)]
            attack_schedule.append(rule)

        plan = ["BENIGN"] * normal_events + attack_schedule
        random.shuffle(plan)

        # Counter for unique sequential IDs
        gen_token = uuid.uuid4().hex[:4].upper()
        event_counter = 1001

        # State tracking for rapid/failed sequences
        rapid_target = random.choice(cls.USERS_POOL)

        for step in plan:
            # Increment time realistically (5 to 45 minutes gap)
            current_time += timedelta(minutes=random.randint(5, 45), seconds=random.randint(10, 59))
            event_id = f"EVT-{gen_token}-{event_counter}"
            event_counter += 1

            if step == "BENIGN":
                events.append(cls._create_benign_event(event_id, current_time))
            elif step == "RULE-01":
                events.append(cls._create_rule01_admin_creation(event_id, current_time))
            elif step == "RULE-02":
                events.append(cls._create_rule02_priv_escalation(event_id, current_time))
            elif step == "RULE-03":
                events.append(cls._create_rule03_group_addition(event_id, current_time))
            elif step == "RULE-04":
                events.append(cls._create_rule04_unauthorized_actor(event_id, current_time))
            elif step == "RULE-05":
                # Generates a sequence of 3 failed elevation attempts
                fail_events = cls._create_rule05_failed_actions(event_counter, current_time, gen_token)
                events.extend(fail_events)
                event_counter += len(fail_events)
            elif step == "RULE-06":
                events.append(cls._create_rule06_permission_tampering(event_id, current_time))
            elif step == "RULE-07":
                events.append(cls._create_rule07_after_hours(event_id, current_time))
            elif step == "RULE-08":
                # Generates 2 rapid changes within 2-3 minutes
                rapid_events = cls._create_rule08_rapid_changes(event_counter, current_time, rapid_target, gen_token)
                events.extend(rapid_events)
                event_counter += len(rapid_events)

        # Sort by timestamp
        df = pd.DataFrame(events)
        if not df.empty and "timestamp" in df.columns:
            df = df.sort_values(by="timestamp").reset_index(drop=True)

        return df

    @classmethod
    def _random_internal_ip(cls) -> str:
        subnets = ["192.168.1.", "10.0.0.", "172.16.10."]
        return f"{random.choice(subnets)}{random.randint(10, 240)}"

    @classmethod
    def _random_external_ip(cls) -> str:
        return f"{random.choice(['198.51.100.', '203.0.113.', '45.33.32.'])}{random.randint(15, 220)}"

    @classmethod
    def _create_benign_event(cls, event_id: str, ts: datetime) -> Dict[str, Any]:
        action_type = random.choice(["LOGIN", "LOGOUT", "MODIFY_USER", "PASSWORD_CHANGE", "READ_REPORT"])
        user = random.choice(cls.USERS_POOL)
        
        if action_type in ("LOGIN", "LOGOUT"):
            return {
                "event_id": event_id,
                "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
                "username": user,
                "source_ip": cls._random_internal_ip(),
                "action": action_type,
                "target_user": user,
                "resource": random.choice(cls.STANDARD_RESOURCES),
                "previous_role": "",
                "new_role": "",
                "group_name": random.choice(cls.BENIGN_GROUPS),
                "status": "SUCCESS",
                "details": f"Routine user authentication {action_type.lower()}",
            }
        elif action_type == "MODIFY_USER":
            return {
                "event_id": event_id,
                "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
                "username": random.choice(cls.AUTHORIZED_ADMINS),
                "source_ip": cls._random_internal_ip(),
                "action": "MODIFY_USER",
                "target_user": user,
                "resource": "IAM_Console",
                "previous_role": "Viewer",
                "new_role": "Editor",
                "group_name": random.choice(cls.BENIGN_GROUPS),
                "status": "SUCCESS",
                "details": "Approved standard department role adjustment",
            }
        elif action_type == "PASSWORD_CHANGE":
            return {
                "event_id": event_id,
                "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
                "username": user,
                "source_ip": cls._random_internal_ip(),
                "action": "PASSWORD_CHANGE",
                "target_user": user,
                "resource": "Domain Controller",
                "previous_role": "",
                "new_role": "",
                "group_name": "Domain Users",
                "status": "SUCCESS",
                "details": "Routine 90-day password self-service update",
            }
        else:
            return {
                "event_id": event_id,
                "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
                "username": user,
                "source_ip": cls._random_internal_ip(),
                "action": "READ_REPORT",
                "target_user": user,
                "resource": "ERP_System",
                "previous_role": "",
                "new_role": "",
                "group_name": "Finance_Team",
                "status": "SUCCESS",
                "details": "Read access to monthly department summary report",
            }

    @classmethod
    def _create_rule01_admin_creation(cls, event_id: str, ts: datetime) -> Dict[str, Any]:
        rogue_account = f"adm_{uuid.uuid4().hex[:5]}"
        return {
            "event_id": event_id,
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "username": random.choice(cls.AUTHORIZED_ADMINS),
            "source_ip": cls._random_internal_ip(),
            "action": "CREATE_USER",
            "target_user": rogue_account,
            "resource": "Active Directory",
            "previous_role": "",
            "new_role": random.choice(["Administrator", "root", "Global Admin"]),
            "group_name": random.choice(["Administrators", "Domain Admins"]),
            "status": "SUCCESS",
            "details": f"New user '{rogue_account}' provisioned directly with administrative role [RULE-01]",
        }

    @classmethod
    def _create_rule02_priv_escalation(cls, event_id: str, ts: datetime) -> Dict[str, Any]:
        target = random.choice(cls.USERS_POOL)
        return {
            "event_id": event_id,
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "username": random.choice(cls.AUTHORIZED_ADMINS),
            "source_ip": cls._random_internal_ip(),
            "action": "ASSIGN_ROLE",
            "target_user": target,
            "resource": "IAM_Console",
            "previous_role": random.choice(cls.BENIGN_ROLES),
            "new_role": random.choice(cls.PRIVILEGED_ROLES),
            "group_name": "Administrators",
            "status": "SUCCESS",
            "details": f"User '{target}' elevated from non-admin role to administrative role [RULE-02]",
        }

    @classmethod
    def _create_rule03_group_addition(cls, event_id: str, ts: datetime) -> Dict[str, Any]:
        target = random.choice(cls.USERS_POOL)
        priv_group = random.choice(cls.PRIVILEGED_GROUPS)
        return {
            "event_id": event_id,
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "username": random.choice(cls.AUTHORIZED_ADMINS),
            "source_ip": cls._random_internal_ip(),
            "action": "ADD_TO_GROUP",
            "target_user": target,
            "resource": "Active Directory",
            "previous_role": "",
            "new_role": "",
            "group_name": priv_group,
            "status": "SUCCESS",
            "details": f"Account '{target}' added to highly privileged group '{priv_group}' [RULE-03]",
        }

    @classmethod
    def _create_rule04_unauthorized_actor(cls, event_id: str, ts: datetime) -> Dict[str, Any]:
        actor = random.choice(cls.UNAUTHORIZED_ACTORS)
        return {
            "event_id": event_id,
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "username": actor,
            "source_ip": cls._random_internal_ip(),
            "action": "ASSIGN_ROLE",
            "target_user": actor,
            "resource": "IAM_Gateway",
            "previous_role": "Junior Developer",
            "new_role": "root",
            "group_name": "wheel",
            "status": "SUCCESS",
            "details": f"Unauthorized non-admin actor '{actor}' executed self-promotion [RULE-02, RULE-04]",
        }

    @classmethod
    def _create_rule05_failed_actions(cls, start_counter: int, ts: datetime, token: str) -> List[Dict[str, Any]]:
        rogue_user = random.choice(cls.UNAUTHORIZED_ACTORS)
        rogue_ip = cls._random_external_ip()
        results = []
        for i in range(3):
            sub_ts = ts + timedelta(minutes=i * 2 + 1, seconds=random.randint(5, 30))
            results.append({
                "event_id": f"EVT-{token}-{start_counter + i}",
                "timestamp": sub_ts.strftime("%Y-%m-%d %H:%M:%S"),
                "username": rogue_user,
                "source_ip": rogue_ip,
                "action": random.choice(["ASSIGN_ROLE", "ADD_TO_GROUP", "MODIFY_PERMISSIONS"]),
                "target_user": rogue_user,
                "resource": "IAM_Gateway",
                "previous_role": "Contractor",
                "new_role": "Administrator",
                "group_name": "Domain Admins",
                "status": "FAILED",
                "details": f"Failed unauthorized administrative elevation attempt {i+1} of 3 [RULE-05]",
            })
        return results

    @classmethod
    def _create_rule06_permission_tampering(cls, event_id: str, ts: datetime) -> Dict[str, Any]:
        res = random.choice(cls.SENSITIVE_RESOURCES)
        return {
            "event_id": event_id,
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "username": random.choice(cls.AUTHORIZED_ADMINS),
            "source_ip": cls._random_internal_ip(),
            "action": "MODIFY_PERMISSIONS",
            "target_user": "all_users",
            "resource": res,
            "previous_role": "",
            "new_role": "",
            "group_name": "wheel",
            "status": "SUCCESS",
            "details": f"Dangerous permission modification on critical system asset '{res}' granting 777 / Full Control [RULE-06]",
        }

    @classmethod
    def _create_rule07_after_hours(cls, event_id: str, ts: datetime) -> Dict[str, Any]:
        # Force hour to be 02:00 AM - 04:00 AM
        night_ts = ts.replace(hour=random.randint(1, 4), minute=random.randint(10, 50))
        actor = random.choice(cls.UNAUTHORIZED_ACTORS)
        return {
            "event_id": event_id,
            "timestamp": night_ts.strftime("%Y-%m-%d %H:%M:%S"),
            "username": actor,
            "source_ip": cls._random_external_ip(),
            "action": "ADD_TO_GROUP",
            "target_user": f"stealth_{actor}",
            "resource": "PAM_Service",
            "previous_role": "",
            "new_role": "",
            "group_name": "sudo",
            "status": "SUCCESS",
            "details": f"Privileged group addition occurred outside authorized business hours at {night_ts.strftime('%H:%M')} [RULE-07]",
        }

    @classmethod
    def _create_rule08_rapid_changes(cls, start_counter: int, ts: datetime, target: str, token: str) -> List[Dict[str, Any]]:
        admin = random.choice(cls.AUTHORIZED_ADMINS)
        ip = cls._random_internal_ip()
        ts1 = ts + timedelta(minutes=1, seconds=15)
        ts2 = ts + timedelta(minutes=3, seconds=45)
        return [
            {
                "event_id": f"EVT-{token}-{start_counter}",
                "timestamp": ts1.strftime("%Y-%m-%d %H:%M:%S"),
                "username": admin,
                "source_ip": ip,
                "action": "ASSIGN_ROLE",
                "target_user": target,
                "resource": "IAM_Console",
                "previous_role": "Contractor",
                "new_role": "Privileged User",
                "group_name": "Consultants",
                "status": "SUCCESS",
                "details": f"Rapid privilege change 1: '{target}' elevated to Privileged User [RULE-08]",
            },
            {
                "event_id": f"EVT-{token}-{start_counter + 1}",
                "timestamp": ts2.strftime("%Y-%m-%d %H:%M:%S"),
                "username": admin,
                "source_ip": ip,
                "action": "ADD_TO_GROUP",
                "target_user": target,
                "resource": "IAM_Console",
                "previous_role": "",
                "new_role": "",
                "group_name": "Administrators",
                "status": "SUCCESS",
                "details": f"Rapid privilege change 2: '{target}' added to Administrators within 2 minutes [RULE-08, RULE-03]",
            },
        ]
