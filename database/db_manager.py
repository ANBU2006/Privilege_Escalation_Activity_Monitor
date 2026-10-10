"""
Database Manager for Privilege Escalation Activity Monitor.
Handles SQLite schema setup, event storage, alert persistence, analysis history,
and parameterized queries for security auditing.
"""

import sqlite3
import json
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
import pandas as pd

logger = logging.getLogger(__name__)


class DatabaseManager:
    """Manages SQLite database storage for audit events, alerts, and historical runs."""

    def __init__(self, db_path: str = "audit_monitor.db"):
        self.db_path = db_path
        self.init_db()

    def get_connection(self) -> sqlite3.Connection:
        """Returns a SQLite connection with row factory configured."""
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self) -> None:
        """Initializes tables for audit events, alerts, analysis runs, and configurations."""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Table for imported raw audit events (deduplicated by event_id)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_events (
                    event_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    username TEXT,
                    source_ip TEXT,
                    action TEXT NOT NULL,
                    target_user TEXT,
                    resource TEXT,
                    previous_role TEXT,
                    new_role TEXT,
                    group_name TEXT,
                    status TEXT,
                    details TEXT,
                    imported_at TEXT NOT NULL
                )
            """)

            # Table for detection alerts
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS detection_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL,
                    event_id TEXT NOT NULL,
                    rule_id TEXT NOT NULL,
                    rule_name TEXT NOT NULL,
                    risk_level TEXT NOT NULL,
                    explanation TEXT NOT NULL,
                    investigation_steps TEXT NOT NULL,
                    detected_at TEXT NOT NULL,
                    FOREIGN KEY (event_id) REFERENCES audit_events(event_id)
                )
            """)

            # Table for analysis run summaries
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS analysis_runs (
                    run_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    file_name TEXT NOT NULL,
                    total_events INTEGER NOT NULL,
                    total_alerts INTEGER NOT NULL,
                    high_count INTEGER NOT NULL,
                    medium_count INTEGER NOT NULL,
                    low_count INTEGER NOT NULL
                )
            """)

            # Table for persistent rule configuration
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS rule_config (
                    config_key TEXT PRIMARY KEY,
                    config_value TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """)

            conn.commit()

    def save_analysis_run(
        self,
        run_id: str,
        file_name: str,
        total_events: int,
        total_alerts: int,
        high_count: int,
        medium_count: int,
        low_count: int,
    ) -> None:
        """Records metadata summary for an audit analysis execution."""
        now_utc = datetime.now(timezone.utc).isoformat()
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO analysis_runs 
                (run_id, timestamp, file_name, total_events, total_alerts, high_count, medium_count, low_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (run_id, now_utc, file_name, total_events, total_alerts, high_count, medium_count, low_count),
            )
            conn.commit()

    def insert_audit_events(self, df: pd.DataFrame) -> int:
        """
        Inserts audit events from a Pandas DataFrame into the database.
        Uses INSERT OR IGNORE to prevent duplicate entries based on event_id.
        Returns the count of successfully inserted records.
        """
        if df.empty:
            return 0

        now_utc = datetime.now(timezone.utc).isoformat()
        records_to_insert = []

        for _, row in df.iterrows():
            record = (
                str(row.get("event_id", "")),
                str(row.get("timestamp", "")),
                str(row.get("username", "") or ""),
                str(row.get("source_ip", "") or ""),
                str(row.get("action", "") or ""),
                str(row.get("target_user", "") or ""),
                str(row.get("resource", "") or ""),
                str(row.get("previous_role", "") or ""),
                str(row.get("new_role", "") or ""),
                str(row.get("group_name", "") or ""),
                str(row.get("status", "") or ""),
                str(row.get("details", "") or ""),
                now_utc,
            )
            records_to_insert.append(record)

        with self.get_connection() as conn:
            cursor = conn.cursor()
            initial_count = cursor.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
            cursor.executemany(
                """
                INSERT OR IGNORE INTO audit_events 
                (event_id, timestamp, username, source_ip, action, target_user, 
                 resource, previous_role, new_role, group_name, status, details, imported_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                records_to_insert,
            )
            conn.commit()
            final_count = cursor.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
            return final_count - initial_count

    def insert_detection_alerts(self, alerts: List[Dict[str, Any]], run_id: str) -> int:
        """
        Inserts detection alerts for a given analysis run into SQLite.
        Returns count of alerts inserted.
        """
        if not alerts:
            return 0

        now_utc = datetime.now(timezone.utc).isoformat()
        alert_tuples = []
        for alert in alerts:
            alert_tuples.append((
                run_id,
                str(alert.get("event_id", "")),
                str(alert.get("rule_id", "")),
                str(alert.get("rule_name", "")),
                str(alert.get("risk_level", "LOW")),
                str(alert.get("explanation", "")),
                str(alert.get("investigation_steps", "")),
                now_utc,
            ))

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.executemany(
                """
                INSERT INTO detection_alerts 
                (run_id, event_id, rule_id, rule_name, risk_level, explanation, investigation_steps, detected_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                alert_tuples,
            )
            conn.commit()
            return len(alert_tuples)

    def get_all_runs(self) -> List[Dict[str, Any]]:
        """Retrieves history of all completed audit runs, newest first."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM analysis_runs ORDER BY timestamp DESC")
            rows = cursor.fetchall()
            return [dict(r) for r in rows]

    def get_alerts_by_run(self, run_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Retrieves alerts joined with corresponding event metadata.
        If run_id is None, retrieves latest alerts.
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            query = """
                SELECT 
                    a.id, a.run_id, a.event_id, a.rule_id, a.rule_name, a.risk_level, 
                    a.explanation, a.investigation_steps, a.detected_at,
                    e.timestamp, e.username, e.source_ip, e.action, e.target_user,
                    e.resource, e.previous_role, e.new_role, e.group_name, e.status, e.details
                FROM detection_alerts a
                LEFT JOIN audit_events e ON a.event_id = e.event_id
            """
            params = []
            if run_id:
                query += " WHERE a.run_id = ? ORDER BY a.id ASC"
                params.append(run_id)
            else:
                query += " ORDER BY a.id DESC"

            cursor.execute(query, params)
            rows = cursor.fetchall()
            return [dict(r) for r in rows]

    def get_event_by_id(self, event_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves raw audit event by unique event_id."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM audit_events WHERE event_id = ?", (event_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def get_all_events(self, limit: int = 500) -> pd.DataFrame:
        """Retrieves stored audit events as a Pandas DataFrame."""
        with self.get_connection() as conn:
            query = "SELECT * FROM audit_events ORDER BY timestamp DESC LIMIT ?"
            return pd.read_sql_query(query, conn, params=(limit,))

    def save_rule_config(self, config_data: Dict[str, Any]) -> None:
        """Stores custom rule configurations as JSON in SQLite."""
        now_utc = datetime.now(timezone.utc).isoformat()
        with self.get_connection() as conn:
            cursor = conn.cursor()
            for key, val in config_data.items():
                cursor.execute(
                    """
                    INSERT OR REPLACE INTO rule_config (config_key, config_value, updated_at)
                    VALUES (?, ?, ?)
                    """,
                    (key, json.dumps(val), now_utc),
                )
            conn.commit()

    def load_rule_config(self) -> Dict[str, Any]:
        """Loads stored custom rule configurations from SQLite."""
        config: Dict[str, Any] = {}
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT config_key, config_value FROM rule_config")
            rows = cursor.fetchall()
            for row in rows:
                try:
                    config[row["config_key"]] = json.loads(row["config_value"])
                except Exception:
                    config[row["config_key"]] = row["config_value"]
        return config

    def clear_database(self) -> None:
        """Clears all audit data, alerts, and runs. Use with caution."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM detection_alerts")
            cursor.execute("DELETE FROM audit_events")
            cursor.execute("DELETE FROM analysis_runs")
            conn.commit()
