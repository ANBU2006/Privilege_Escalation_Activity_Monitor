"""
Log Parser and Validator for Privilege Escalation Activity Monitor.
Parses, sanitizes, and validates audit logs provided in CSV or JSON formats.
Ensures resilience against malformed schemas, missing fields, and untrusted input.
"""

import io
import json
import re
import html
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Any, Optional, Union
import pandas as pd


@dataclass
class ParsingResult:
    """Encapsulates outcome of parsing and validating an audit log file."""
    df: pd.DataFrame
    is_valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    total_rows: int = 0
    valid_rows: int = 0
    raw_columns: List[str] = field(default_factory=list)
    raw_df: Optional[pd.DataFrame] = None


# Column alias mapping for standardizing headers across diverse log schemas
COLUMN_ALIASES: Dict[str, str] = {
    # Event ID
    "event_id": "event_id",
    "eventid": "event_id",
    "id": "event_id",
    "record_id": "event_id",
    "record_number": "event_id",
    "recordid": "event_id",
    "uuid": "event_id",
    # Timestamp
    "timestamp": "timestamp",
    "time": "timestamp",
    "datetime": "timestamp",
    "date": "timestamp",
    "time_created": "timestamp",
    "timecreated": "timestamp",
    "event_time": "timestamp",
    "eventtime": "timestamp",
    "timestamp_utc": "timestamp",
    "created_at": "timestamp",
    "created": "timestamp",
    "occurred_at": "timestamp",
    "occurred": "timestamp",
    "log_time": "timestamp",
    "logtime": "timestamp",
    "date_time": "timestamp",
    "generation_time": "timestamp",
    "utctime": "timestamp",
    "event_date": "timestamp",
    # Username / Actor
    "username": "username",
    "user": "username",
    "actor": "username",
    "source_user": "username",
    "subject_user_name": "username",
    "subjectusername": "username",
    "user_name": "username",
    "account_name": "username",
    "account": "username",
    "caller": "username",
    "caller_name": "username",
    "initiator": "username",
    "principal": "username",
    "identity": "username",
    "who": "username",
    "admin_user": "username",
    "operator": "username",
    "operator_name": "username",
    # Source IP
    "source_ip": "source_ip",
    "ip": "source_ip",
    "client_ip": "source_ip",
    "ip_address": "source_ip",
    "ipaddress": "source_ip",
    "caller_ip": "source_ip",
    "client_ip_address": "source_ip",
    "remote_ip": "source_ip",
    "remote_address": "source_ip",
    "host_ip": "source_ip",
    # Action
    "action": "action",
    "activity": "action",
    "event_type": "action",
    "event_name": "action",
    "eventname": "action",
    "eventtype": "action",
    "operation": "action",
    "operation_name": "action",
    "operationname": "action",
    "event": "action",
    "task": "action",
    "task_name": "action",
    "taskname": "action",
    "audit_action": "action",
    "command": "action",
    "activity_name": "action",
    "activityname": "action",
    "action_name": "action",
    "actionname": "action",
    "method": "action",
    "type": "action",

    # Target User
    "target_user": "target_user",
    "target": "target_user",
    "affected_user": "target_user",
    "target_user_name": "target_user",
    "targetusername": "target_user",
    "target_account": "target_user",
    "subject": "target_user",
    "destination_user": "target_user",
    "member_name": "target_user",
    "member": "target_user",
    "user_modified": "target_user",
    "recipient": "target_user",
    # Resource
    "resource": "resource",
    "object": "resource",
    "target_resource": "resource",
    "object_name": "resource",
    "target_object": "resource",
    "resource_name": "resource",
    "file_name": "resource",
    "filename": "resource",
    "path": "resource",
    "service": "resource",
    "system": "resource",
    # Previous Role
    "previous_role": "previous_role",
    "prev_role": "previous_role",
    "old_role": "previous_role",
    "prior_role": "previous_role",
    "original_role": "previous_role",
    "from_role": "previous_role",
    # New Role
    "new_role": "new_role",
    "assigned_role": "new_role",
    "role": "new_role",
    "elevated_role": "new_role",
    "to_role": "new_role",
    "target_role": "new_role",
    "new_permission": "new_role",
    # Group Name
    "group_name": "group_name",
    "group": "group_name",
    "target_group": "group_name",
    "member_of": "group_name",
    "group_added": "group_name",
    "security_group": "group_name",
    "group_membership": "group_name",
    # Status
    "status": "status",
    "result": "status",
    "outcome": "status",
    "result_type": "status",
    "outcome_code": "status",
    "status_code": "status",
    "status_name": "status",
    "success": "status",
    "disposition": "status",
    # Details
    "details": "details",
    "description": "details",
    "message": "details",
    "msg": "details",
    "info": "details",
    "reason": "details",
    "summary": "details",
    "raw_message": "details",
    "notes": "details",
}

REQUIRED_CORE_FIELDS = ["timestamp", "action"]
STANDARD_COLUMNS = [
    "event_id",
    "timestamp",
    "username",
    "source_ip",
    "action",
    "target_user",
    "resource",
    "previous_role",
    "new_role",
    "group_name",
    "status",
    "details",
]


class LogParser:
    """Robust parser for CSV and JSON audit logs."""

    @staticmethod
    def sanitize_string(val: Any) -> str:
        """Sanitizes text to prevent XSS, script injection, and control characters."""
        if val is None or pd.isna(val):
            return ""
        s = str(val).strip()
        # Escape HTML tags
        s = html.escape(s)
        # Strip ASCII control characters except standard whitespace
        s = re.sub(r"[\x00-\x08\x0B\x0C\x0E-\x1F]", "", s)
        return s

    @classmethod
    def _read_csv_bytes(cls, content_bytes: bytes) -> pd.DataFrame:
        """
        Robustly reads CSV bytes by trying multiple encodings and detecting delimiters
        (comma, semicolon, tab, pipe).
        """
        encodings = ["utf-8-sig", "utf-8", "cp1252", "latin1", "iso-8859-1"]
        decoded_text = None
        for enc in encodings:
            try:
                decoded_text = content_bytes.decode(enc)
                break
            except UnicodeDecodeError:
                continue

        if decoded_text is None:
            decoded_text = content_bytes.decode("utf-8", errors="replace")

        decoded_text = decoded_text.lstrip("\ufeff\ufffe")

        # Delimiter heuristic from first non-empty lines
        sample_lines = [line for line in decoded_text.splitlines() if line.strip()][:5]
        delimiter = None
        if sample_lines:
            header_line = sample_lines[0]
            delim_counts = {
                ",": header_line.count(","),
                ";": header_line.count(";"),
                "\t": header_line.count("\t"),
                "|": header_line.count("|"),
            }
            best_delim = max(delim_counts, key=delim_counts.get)
            if delim_counts[best_delim] > 0:
                delimiter = best_delim

        try:
            if delimiter:
                return pd.read_csv(io.StringIO(decoded_text), sep=delimiter, on_bad_lines="skip")
            else:
                return pd.read_csv(io.StringIO(decoded_text), sep=None, engine="python", on_bad_lines="skip")
        except Exception:
            return pd.read_csv(io.StringIO(decoded_text), on_bad_lines="skip")

    @classmethod
    def parse_file(
        cls, file_input: Union[str, io.BytesIO, io.StringIO], file_name: str = ""
    ) -> ParsingResult:
        """
        Parses CSV or JSON file data into a structured, validated DataFrame.
        file_input can be a filepath, BytesIO, or StringIO.
        """
        errors: List[str] = []
        warnings: List[str] = []

        raw_df: Optional[pd.DataFrame] = None
        lower_name = file_name.lower()

        # Step 1: Read raw content into DataFrame
        try:
            if isinstance(file_input, (io.BytesIO, io.StringIO)):
                content_bytes = (
                    file_input.getvalue()
                    if isinstance(file_input, io.BytesIO)
                    else file_input.getvalue().encode("utf-8")
                )
                if len(content_bytes) == 0:
                    return ParsingResult(df=pd.DataFrame(), is_valid=False, errors=["Uploaded file is empty (0 bytes)."])

                # Detect format based on filename or inspection
                if lower_name.endswith(".json") or content_bytes.lstrip().startswith((b"[", b"{")):
                    raw_df = cls._read_json_bytes(content_bytes)
                else:
                    raw_df = cls._read_csv_bytes(content_bytes)
            elif isinstance(file_input, str):
                if file_input.lower().endswith(".json"):
                    with open(file_input, "rb") as f:
                        raw_df = cls._read_json_bytes(f.read())
                else:
                    with open(file_input, "rb") as f:
                        raw_df = cls._read_csv_bytes(f.read())
            else:
                return ParsingResult(df=pd.DataFrame(), is_valid=False, errors=["Unsupported file input type."])
        except Exception as e:
            return ParsingResult(
                df=pd.DataFrame(),
                is_valid=False,
                errors=[f"Failed to parse file format ({type(e).__name__}): {str(e)}"],
            )

        if raw_df is None or raw_df.empty:
            return ParsingResult(
                df=pd.DataFrame(),
                is_valid=False,
                errors=["Audit log file contains no records or empty dataset."],
            )

        total_rows = len(raw_df)
        detected_raw_columns = [str(c) for c in raw_df.columns]

        # Step 2: Normalize Column Names
        normalized_columns = {}
        for col in raw_df.columns:
            cleaned_col = str(col).strip().lstrip("\ufeff\ufffe").lower().replace(" ", "_").replace("-", "_")
            if cleaned_col in COLUMN_ALIASES:
                normalized_columns[col] = COLUMN_ALIASES[cleaned_col]
            else:
                normalized_columns[col] = cleaned_col

        working_df = raw_df.rename(columns=normalized_columns)

        # Step 3: Validate core fields
        for req in REQUIRED_CORE_FIELDS:
            if req not in working_df.columns:
                errors.append(f"Missing required audit field: '{req}'. File must include timestamp and action.")

        if errors:
            return ParsingResult(
                df=pd.DataFrame(),
                is_valid=False,
                errors=errors,
                warnings=warnings,
                total_rows=total_rows,
                raw_columns=detected_raw_columns,
                raw_df=raw_df,
            )

        # Ensure all standard columns exist
        for col in STANDARD_COLUMNS:
            if col not in working_df.columns:
                working_df[col] = ""

        # Step 4: Sanitize and Clean Data
        cleaned_records = []
        for idx, row in working_df.iterrows():
            clean_row = {}
            for col in STANDARD_COLUMNS:
                clean_row[col] = cls.sanitize_string(row.get(col, ""))

            # Synthesize event_id if empty
            if not clean_row["event_id"]:
                clean_row["event_id"] = f"EVT-GEN-{idx+1:04d}"

            # Standardize status
            status_val = clean_row["status"].upper()
            if not status_val or status_val in {"OK", "PASS", "SUCCESSFUL", "TRUE"}:
                clean_row["status"] = "SUCCESS"
            elif status_val in {"FAIL", "ERROR", "FAILURE", "FALSE", "DENIED"}:
                clean_row["status"] = "FAILED"
            else:
                clean_row["status"] = status_val

            cleaned_records.append(clean_row)

        processed_df = pd.DataFrame(cleaned_records)

        # Step 5: Validate and parse timestamps
        processed_df["parsed_datetime"] = pd.to_datetime(
            processed_df["timestamp"], errors="coerce"
        )
        invalid_ts_count = processed_df["parsed_datetime"].isna().sum()
        if invalid_ts_count > 0:
            warnings.append(
                f"{invalid_ts_count} rows have invalid or unparseable timestamps. "
                "Defaulting to event stream order."
            )

        # Fill any remaining NaNs in standard columns
        for col in STANDARD_COLUMNS:
            processed_df[col] = processed_df[col].fillna("")

        return ParsingResult(
            df=processed_df,
            is_valid=True,
            errors=errors,
            warnings=warnings,
            total_rows=total_rows,
            valid_rows=len(processed_df),
            raw_columns=detected_raw_columns,
            raw_df=raw_df,
        )

    @classmethod
    def process_with_custom_mapping(
        cls, raw_df: pd.DataFrame, column_mapping: Dict[str, str]
    ) -> ParsingResult:
        """
        Maps user-specified columns from raw_df to standard fields, then cleans and validates.
        column_mapping is a dict: { "standard_field_name": "raw_column_name" }
        """
        errors: List[str] = []
        warnings: List[str] = []

        mapped_df = pd.DataFrame()
        for std_col, raw_col in column_mapping.items():
            if raw_col and raw_col in raw_df.columns:
                mapped_df[std_col] = raw_df[raw_col]

        for req in REQUIRED_CORE_FIELDS:
            if req not in mapped_df.columns:
                errors.append(f"Missing required audit field: '{req}'. Please select a column for {req}.")

        if errors:
            return ParsingResult(
                df=pd.DataFrame(),
                is_valid=False,
                errors=errors,
                warnings=warnings,
                total_rows=len(raw_df),
                raw_columns=[str(c) for c in raw_df.columns],
                raw_df=raw_df,
            )

        # Ensure all standard columns exist
        for col in STANDARD_COLUMNS:
            if col not in mapped_df.columns:
                mapped_df[col] = ""

        # Sanitize and Clean Data
        cleaned_records = []
        for idx, row in mapped_df.iterrows():
            clean_row = {}
            for col in STANDARD_COLUMNS:
                clean_row[col] = cls.sanitize_string(row.get(col, ""))

            if not clean_row["event_id"]:
                clean_row["event_id"] = f"EVT-GEN-{idx+1:04d}"

            status_val = clean_row["status"].upper()
            if not status_val or status_val in {"OK", "PASS", "SUCCESSFUL", "TRUE"}:
                clean_row["status"] = "SUCCESS"
            elif status_val in {"FAIL", "ERROR", "FAILURE", "FALSE", "DENIED"}:
                clean_row["status"] = "FAILED"
            else:
                clean_row["status"] = status_val

            cleaned_records.append(clean_row)

        processed_df = pd.DataFrame(cleaned_records)

        # Validate and parse timestamps
        processed_df["parsed_datetime"] = pd.to_datetime(
            processed_df["timestamp"], errors="coerce"
        )
        invalid_ts_count = processed_df["parsed_datetime"].isna().sum()
        if invalid_ts_count > 0:
            warnings.append(
                f"{invalid_ts_count} rows have invalid or unparseable timestamps. Defaulting to event stream order."
            )

        for col in STANDARD_COLUMNS:
            processed_df[col] = processed_df[col].fillna("")

        return ParsingResult(
            df=processed_df,
            is_valid=True,
            errors=errors,
            warnings=warnings,
            total_rows=len(raw_df),
            valid_rows=len(processed_df),
            raw_columns=[str(c) for c in raw_df.columns],
            raw_df=raw_df,
        )

    @classmethod
    def _read_json_bytes(cls, content_bytes: bytes) -> pd.DataFrame:
        """Parses JSON content supporting JSON arrays and newline-delimited JSON (ndjson)."""
        decoded = content_bytes.decode("utf-8", errors="replace").strip()
        try:
            parsed = json.loads(decoded)
            if isinstance(parsed, list):
                return pd.DataFrame(parsed)
            elif isinstance(parsed, dict):
                # Check if wrapped in events key
                for k in ["events", "logs", "records", "data"]:
                    if k in parsed and isinstance(parsed[k], list):
                        return pd.DataFrame(parsed[k])
                return pd.DataFrame([parsed])
        except json.JSONDecodeError:
            # Try newline-delimited JSON
            records = []
            for line in decoded.splitlines():
                line = line.strip()
                if line:
                    records.append(json.loads(line))
            if records:
                return pd.DataFrame(records)
            raise
