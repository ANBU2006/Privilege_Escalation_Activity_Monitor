"""
T2-PS7 – Privilege Escalation Activity Monitor
A complete, beginner-friendly cybersecurity audit application.
Built with Python, Pandas, Rule-Based Detection Engine, SQLite, Matplotlib, and Streamlit.
"""

import os
import io
import json
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional

import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt

# Internal application modules
from database.db_manager import DatabaseManager
from detection.rules import SecurityRuleEngine, RULE_CATALOG, DEFAULT_CONFIG
from detection.risk_classifier import RiskClassifier
from detection.analyzer import AuditAnalyzer
from utils.log_parser import LogParser, ParsingResult
from utils.report_generator import ReportGenerator
from utils.data_generator import AuditDataGenerator



# -----------------------------------------------------------------------------
# Streamlit Page Configuration & Dark Cybersecurity CSS Theme
# -----------------------------------------------------------------------------
st.set_page_config(
    page_title="Privilege Escalation Activity Monitor",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

CYBER_CSS = """
<style>
    /* Dark Cybersecurity Global Styles */
    .stApp {
        background-color: #0b0f19;
        color: #e2e8f0;
    }
    
    /* Sleek card containers */
    .cyber-card {
        background: linear-gradient(135deg, #131b2e 0%, #1a243b 100%);
        border: 1px solid #2d3b55;
        border-radius: 10px;
        padding: 20px;
        margin-bottom: 20px;
        box-shadow: 0 4px 15px rgba(0, 0, 0, 0.4);
    }
    
    .metric-card {
        background: #111827;
        border: 1px solid #1f2937;
        border-left: 4px solid #38bdf8;
        border-radius: 8px;
        padding: 16px;
        margin-bottom: 12px;
    }
    
    .metric-card-high {
        border-left: 4px solid #ef4444;
    }
    .metric-card-med {
        border-left: 4px solid #f59e0b;
    }
    .metric-card-low {
        border-left: 4px solid #10b981;
    }
    
    .metric-value {
        font-size: 2rem;
        font-weight: 700;
        color: #f8fafc;
        margin: 0;
    }
    .metric-title {
        font-size: 0.85rem;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        color: #94a3b8;
        margin-bottom: 4px;
    }
    
    /* Risk Badges */
    .badge-high {
        background-color: rgba(239, 68, 68, 0.2);
        color: #f87171;
        border: 1px solid #ef4444;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.8rem;
    }
    .badge-med {
        background-color: rgba(245, 158, 11, 0.2);
        color: #fbbf24;
        border: 1px solid #f59e0b;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.8rem;
    }
    .badge-low {
        background-color: rgba(16, 185, 129, 0.2);
        color: #34d399;
        border: 1px solid #10b981;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.8rem;
    }
    
    /* Custom divider */
    hr {
        border: 0;
        height: 1px;
        background: #2d3b55;
        margin: 20px 0;
    }
    
    /* Table headers styling */
    .dataframe th {
        background-color: #1e293b !important;
        color: #38bdf8 !important;
        font-weight: 600 !important;
    }
</style>
"""
st.markdown(CYBER_CSS, unsafe_allow_html=True)

# -----------------------------------------------------------------------------
# Database and Engine Initialization
# -----------------------------------------------------------------------------
@st.cache_resource
def get_db_manager() -> DatabaseManager:
    return DatabaseManager("audit_monitor.db")

db = get_db_manager()

# Initialize session state
if "rule_config" not in st.session_state:
    stored_cfg = db.load_rule_config()
    st.session_state["rule_config"] = {**DEFAULT_CONFIG, **stored_cfg}

if "analyzed_df" not in st.session_state:
    st.session_state["analyzed_df"] = pd.DataFrame()
if "alerts" not in st.session_state:
    st.session_state["alerts"] = []
if "metrics" not in st.session_state:
    st.session_state["metrics"] = {}
if "active_file_name" not in st.session_state:
    st.session_state["active_file_name"] = "None"
if "selected_event_id" not in st.session_state:
    st.session_state["selected_event_id"] = None


def run_analysis_pipeline(df: pd.DataFrame, file_name: str) -> None:
    """Executes rule analysis, computes metrics, and persists run into SQLite."""
    analyzer = AuditAnalyzer(config=st.session_state["rule_config"])
    alerts, metrics = analyzer.analyze_dataframe(df)

    st.session_state["analyzed_df"] = df
    st.session_state["alerts"] = alerts
    st.session_state["metrics"] = metrics
    st.session_state["active_file_name"] = file_name

    # Persist to SQLite
    run_id = f"RUN-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6]}"
    db.save_analysis_run(
        run_id=run_id,
        file_name=file_name,
        total_events=metrics.get("total_events", 0),
        total_alerts=metrics.get("total_suspicious", 0),
        high_count=metrics.get("high_count", 0),
        medium_count=metrics.get("medium_count", 0),
        low_count=metrics.get("low_count", 0),
    )
    db.insert_audit_events(df)
    db.insert_detection_alerts(alerts, run_id=run_id)


# Auto-load synthetic sample dataset on initial load if session is empty
if st.session_state["analyzed_df"].empty:
    sample_csv_path = os.path.join(os.path.dirname(__file__), "data", "sample_audit_logs.csv")
    if os.path.exists(sample_csv_path):
        parsed = LogParser.parse_file(sample_csv_path, file_name="sample_audit_logs.csv")
        if parsed.is_valid:
            run_analysis_pipeline(parsed.df, "sample_audit_logs.csv")

# -----------------------------------------------------------------------------
# Sidebar Navigation & System Telemetry
# -----------------------------------------------------------------------------
st.sidebar.markdown("### 🛡️ **T2-PS7 Monitor**")
st.sidebar.markdown(
    "<small style='color: #38bdf8;'>Privilege Escalation Activity Auditing System</small>",
    unsafe_allow_html=True,
)

nav_page = st.sidebar.radio(
    "Navigation Menu",
    [
        "📊 Dashboard",
        "📥 Upload Audit Logs",
        "🛡️ Detection Results",
        "🔍 Alert Details & Deep Dive",
        "🗄️ Audit History (SQLite)",
        "📄 Reports & Export",
        "⚙️ Rule Configuration",
        "ℹ️ About the Project",
    ],
    index=0,
)

st.sidebar.markdown("---")
st.sidebar.markdown("#### **Active Audit Context**")
st.sidebar.text(f"File: {st.session_state['active_file_name']}")
st.sidebar.text(f"Events: {len(st.session_state['analyzed_df'])}")
st.sidebar.text(f"Alerts: {len(st.session_state['alerts'])}")

# Buttons to quickly reload or generate fresh sample logs
sample_csv_path = os.path.join(os.path.dirname(__file__), "data", "sample_audit_logs.csv")
if os.path.exists(sample_csv_path):
    if st.sidebar.button("🔄 Reload Base Sample", use_container_width=True):
        parsed = LogParser.parse_file(sample_csv_path, file_name="sample_audit_logs.csv")
        if parsed.is_valid:
            run_analysis_pipeline(parsed.df, "sample_audit_logs.csv")
            st.sidebar.success("Sample dataset reloaded!")
            st.rerun()

if st.sidebar.button("🎲 Generate & Load Fresh Data", use_container_width=True, type="primary"):
    fresh_df = AuditDataGenerator.generate_logs(num_events=25)
    fresh_name = f"audit_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    run_analysis_pipeline(fresh_df, fresh_name)
    st.sidebar.success("Generated & loaded fresh randomized dataset!")
    st.rerun()


st.sidebar.markdown(
    "<div style='margin-top: 25px; padding: 10px; background: #111827; border-radius: 6px; border: 1px solid #1f2937; font-size: 0.75rem; color: #94a3b8;'>"
    "⚡ <b>Engine Status:</b> Active<br>"
    "🛡️ <b>Mode:</b> Rule-Based Heuristics<br>"
    "🗄️ <b>Storage:</b> SQLite Thread-Safe<br>"
    "🎯 <b>Detection Rules:</b> 8 Active"
    "</div>",
    unsafe_allow_html=True,
)

# -----------------------------------------------------------------------------
# Matplotlib Dark Theme Helper
# -----------------------------------------------------------------------------
def set_matplotlib_cyber_style():
    plt.style.use("dark_background")
    plt.rcParams.update({
        "figure.facecolor": "#111827",
        "axes.facecolor": "#111827",
        "axes.edgecolor": "#374151",
        "axes.labelcolor": "#e2e8f0",
        "text.color": "#e2e8f0",
        "xtick.color": "#94a3b8",
        "ytick.color": "#94a3b8",
        "grid.color": "#1f2937",
        "grid.linestyle": "--",
        "font.family": "sans-serif",
    })


# =============================================================================
# PAGE 1: 📊 DASHBOARD
# =============================================================================
if nav_page == "📊 Dashboard":
    st.markdown("## 📊 **Security Operations Center Dashboard**")
    st.markdown(
        "Real-time telemetry and risk classification for privilege escalation and administrative anomalies."
    )

    metrics = st.session_state["metrics"]
    alerts = st.session_state["alerts"]
    df = st.session_state["analyzed_df"]

    if df.empty:
        st.info("No audit logs currently loaded. Please upload a log file or reload the sample dataset.")
    else:
        # Top KPI Metrics Cards
        col1, col2, col3, col4, col5 = st.columns(5)
        with col1:
            st.markdown(
                f"""<div class="metric-card">
                    <div class="metric-title">Total Analyzed</div>
                    <div class="metric-value">{metrics.get('total_events', 0)}</div>
                </div>""",
                unsafe_allow_html=True,
            )
        with col2:
            st.markdown(
                f"""<div class="metric-card">
                    <div class="metric-title">Suspicious Events</div>
                    <div class="metric-value" style="color: #38bdf8;">{metrics.get('total_suspicious', 0)}</div>
                </div>""",
                unsafe_allow_html=True,
            )
        with col3:
            st.markdown(
                f"""<div class="metric-card metric-card-high">
                    <div class="metric-title">High Risk</div>
                    <div class="metric-value" style="color: #ef4444;">{metrics.get('high_count', 0)}</div>
                </div>""",
                unsafe_allow_html=True,
            )
        with col4:
            st.markdown(
                f"""<div class="metric-card metric-card-med">
                    <div class="metric-title">Medium Risk</div>
                    <div class="metric-value" style="color: #f59e0b;">{metrics.get('medium_count', 0)}</div>
                </div>""",
                unsafe_allow_html=True,
            )
        with col5:
            st.markdown(
                f"""<div class="metric-card metric-card-low">
                    <div class="metric-title">Low Risk</div>
                    <div class="metric-value" style="color: #10b981;">{metrics.get('low_count', 0)}</div>
                </div>""",
                unsafe_allow_html=True,
            )

        # Secondary Feature Cards
        c1, c2, c3, c4 = st.columns(4)
        with c1:
            st.markdown(
                f"""<div class="metric-card">
                    <div class="metric-title">Admin Created</div>
                    <div class="metric-value">{metrics.get('admin_creation_count', 0)}</div>
                </div>""",
                unsafe_allow_html=True,
            )
        with c2:
            st.markdown(
                f"""<div class="metric-card">
                    <div class="metric-title">Privilege Escalations</div>
                    <div class="metric-value">{metrics.get('priv_escalation_count', 0)}</div>
                </div>""",
                unsafe_allow_html=True,
            )
        with c3:
            st.markdown(
                f"""<div class="metric-card">
                    <div class="metric-title">Group Membership Adds</div>
                    <div class="metric-value">{metrics.get('group_membership_count', 0)}</div>
                </div>""",
                unsafe_allow_html=True,
            )
        with c4:
            st.markdown(
                f"""<div class="metric-card">
                    <div class="metric-title">Suspicious Rate</div>
                    <div class="metric-value">{metrics.get('suspicious_rate', 0.0)}%</div>
                </div>""",
                unsafe_allow_html=True,
            )

        st.markdown("---")

        # Visual Analytics Charts Row
        chart_col1, chart_col2 = st.columns(2)

        set_matplotlib_cyber_style()

        with chart_col1:
            st.markdown("#### **Risk Severity Breakdown**")
            fig1, ax1 = plt.subplots(figsize=(6, 4))
            risk_dist = metrics.get("risk_distribution", {"HIGH": 0, "MEDIUM": 0, "LOW": 0})
            labels = ["High Risk", "Medium Risk", "Low Risk"]
            values = [risk_dist.get("HIGH", 0), risk_dist.get("MEDIUM", 0), risk_dist.get("LOW", 0)]
            colors = ["#ef4444", "#f59e0b", "#10b981"]

            # Filter non-zero for clean chart
            plot_labels = [l for l, v in zip(labels, values) if v > 0]
            plot_vals = [v for v in values if v > 0]
            plot_colors = [c for c, v in zip(colors, values) if v > 0]

            if plot_vals:
                wedges, texts, autotexts = ax1.pie(
                    plot_vals,
                    labels=plot_labels,
                    autopct="%1.1f%%",
                    colors=plot_colors,
                    startangle=140,
                    wedgeprops={"edgecolor": "#111827", "linewidth": 2, "width": 0.6},
                )
                for t in texts:
                    t.set_color("#cbd5e1")
                for at in autotexts:
                    at.set_color("#ffffff")
                    at.set_fontweight("bold")
                ax1.set_title("Detection Risk Proportions", color="#38bdf8", pad=15)
            else:
                ax1.text(0.5, 0.5, "No Alerts Detected", ha="center", va="center", color="#94a3b8")
            st.pyplot(fig1, clear_figure=True)

        with chart_col2:
            st.markdown("#### **Detections by Rule Category**")
            fig2, ax2 = plt.subplots(figsize=(6, 4))
            rule_bd = metrics.get("rule_breakdown", {})
            cat_names = list(rule_bd.keys())
            cat_counts = list(rule_bd.values())

            y_pos = range(len(cat_names))
            bars = ax2.barh(y_pos, cat_counts, color="#38bdf8", edgecolor="#0284c7")
            ax2.set_yticks(y_pos)
            ax2.set_yticklabels(cat_names, fontsize=8)
            ax2.invert_yaxis()
            ax2.set_xlabel("Trigger Count", fontsize=9)
            ax2.grid(axis="x", alpha=0.3)
            ax2.set_title("Rule Trigger Frequency", color="#38bdf8", pad=15)
            # Add labels to end of bars
            for bar in bars:
                width = bar.get_width()
                if width > 0:
                    ax2.text(width + 0.1, bar.get_y() + bar.get_height() / 2, str(int(width)),
                             va="center", ha="left", color="#e2e8f0", fontsize=8)
            plt.tight_layout()
            st.pyplot(fig2, clear_figure=True)

        st.markdown("---")

        # Recent Alerts Quick Table
        st.markdown("#### **Recent Suspicious Activities**")
        if alerts:
            recent_alerts = alerts[-5:]
            recent_rows = []
            for a in reversed(recent_alerts):
                recent_rows.append({
                    "Event ID": a["event_id"],
                    "Timestamp": a["timestamp"],
                    "Risk": RiskClassifier.get_risk_badge(a["risk_level"]),
                    "Actor": a["username"],
                    "Action": a["action"],
                    "Target User": a["target_user"] or "N/A",
                    "Rule Triggered": a["rule_name"],
                })
            st.dataframe(pd.DataFrame(recent_rows), use_container_width=True, hide_index=True)
            st.caption("Navigate to the **Detection Results** page for complete filtering, search, and investigation.")
        else:
            st.success("No suspicious events detected in current audit dataset.")


# =============================================================================
# PAGE 2: 📥 UPLOAD AUDIT LOGS
# =============================================================================
elif nav_page == "📥 Upload Audit Logs":
    st.markdown("## 📥 **Import & Validate Audit Logs**")
    st.markdown(
        "Upload audit event logs formatted as **CSV** or **JSON** (supporting standard JSON arrays and newline-delimited logs)."
    )

    upload_col, sample_col = st.columns([2, 1])

    with sample_col:
        st.markdown(
            """<div class="cyber-card">
                <h4 style="color: #38bdf8; margin-top: 0;">🎲 Generate Fresh Audit Datasets</h4>
                <p style="font-size: 0.85rem; color: #94a3b8;">
                    Generate brand new, randomized datasets on demand with fresh timestamps, unique actors, 
                    IPs, and diverse attack scenarios across all 8 detection rules.
                </p>
            </div>""",
            unsafe_allow_html=True,
        )

        # Initialize dynamic dataset in session_state if absent
        if "dynamic_dataset" not in st.session_state:
            st.session_state["dynamic_dataset"] = AuditDataGenerator.generate_logs(num_events=25)
            st.session_state["dynamic_dataset_name"] = f"audit_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        gen_size = st.select_slider(
            "Events to Generate:",
            options=[15, 25, 50, 100],
            value=25,
            key="gen_size_slider",
        )

        col_g1, col_g2 = st.columns(2)
        with col_g1:
            if st.button("🎲 Generate New", type="secondary", use_container_width=True):
                st.session_state["dynamic_dataset"] = AuditDataGenerator.generate_logs(num_events=gen_size)
                st.session_state["dynamic_dataset_name"] = f"audit_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                st.success(f"Generated {gen_size} fresh events!")

        with col_g2:
            if st.button("🚀 Load Directly", type="primary", use_container_width=True):
                dyn_df = st.session_state["dynamic_dataset"]
                file_name_run = f"{st.session_state.get('dynamic_dataset_name', 'fresh_logs')}.csv"
                run_analysis_pipeline(dyn_df, file_name_run)
                st.success("Fresh dataset loaded and analyzed!")
                st.rerun()

        # Dynamic dataset download options
        dyn_df = st.session_state["dynamic_dataset"]
        csv_bytes = dyn_df.to_csv(index=False).encode("utf-8")
        json_bytes = dyn_df.to_json(orient="records", indent=2).encode("utf-8")
        file_base = st.session_state.get("dynamic_dataset_name", "audit_logs")

        st.download_button(
            label="⬇️ Download Fresh CSV",
            data=csv_bytes,
            file_name=f"{file_base}.csv",
            mime="text/csv",
            use_container_width=True,
        )

        st.download_button(
            label="⬇️ Download Fresh JSON",
            data=json_bytes,
            file_name=f"{file_base}.json",
            mime="application/json",
            use_container_width=True,
        )

        with st.expander("📁 Original Static Baseline Sample", expanded=False):
            sample_csv_path = os.path.join(os.path.dirname(__file__), "data", "sample_audit_logs.csv")
            if os.path.exists(sample_csv_path):
                with open(sample_csv_path, "r", encoding="utf-8") as f:
                    static_bytes = f.read().encode("utf-8")
                st.download_button(
                    label="⬇️ Download Static Base CSV",
                    data=static_bytes,
                    file_name="sample_audit_logs.csv",
                    mime="text/csv",
                    use_container_width=True,
                )


    with upload_col:
        uploaded_file = st.file_uploader(
            "Select Audit Log File",
            type=["csv", "json"],
            help="Upload raw system or directory audit logs in CSV or JSON format.",
        )

        if uploaded_file is not None:
            with st.spinner("Parsing and validating audit log format..."):
                file_bytes = io.BytesIO(uploaded_file.getvalue())
                parsing_result = LogParser.parse_file(file_bytes, file_name=uploaded_file.name)

            if not parsing_result.is_valid:
                st.error("❌ File Validation Failed")
                for err in parsing_result.errors:
                    st.write(f"- {err}")

                # If the file was parsed into a DataFrame but missed core column names, offer interactive column mapping!
                if parsing_result.raw_df is not None and not parsing_result.raw_df.empty:
                    st.info(
                        "💡 **Custom Column Mapping Assistant:** Your file was read, but the required columns "
                        "(`timestamp`, `action`) were not automatically identified. Map your file's columns below to proceed:"
                    )

                    raw_cols = ["(None / Skip)"] + list(parsing_result.raw_columns)

                    with st.expander("🛠️ Map File Columns to Audit Schema", expanded=True):
                        # Helper to auto-pick best matching index
                        def find_best_col(target_names: list, cols: list) -> int:
                            for idx, c in enumerate(cols):
                                if idx > 0 and any(t.lower() in str(c).lower() for t in target_names):
                                    return idx
                            return 0

                        map_col1, map_col2 = st.columns(2)
                        with map_col1:
                            mapped_ts = st.selectbox(
                                "Timestamp Column * (Required)",
                                options=raw_cols,
                                index=find_best_col(["time", "date"], raw_cols),
                                key="map_ts",
                            )
                            mapped_action = st.selectbox(
                                "Action / Activity Column * (Required)",
                                options=raw_cols,
                                index=find_best_col(["action", "event", "activity", "operation", "task"], raw_cols),
                                key="map_action",
                            )
                            mapped_user = st.selectbox(
                                "Actor / Username Column",
                                options=raw_cols,
                                index=find_best_col(["user", "actor", "caller", "account"], raw_cols),
                                key="map_user",
                            )
                            mapped_target = st.selectbox(
                                "Target User Column",
                                options=raw_cols,
                                index=find_best_col(["target", "subject", "affected"], raw_cols),
                                key="map_target",
                            )

                        with map_col2:
                            mapped_role = st.selectbox(
                                "New Role / Assigned Role Column",
                                options=raw_cols,
                                index=find_best_col(["new_role", "role", "assigned"], raw_cols),
                                key="map_role",
                            )
                            mapped_prev_role = st.selectbox(
                                "Previous Role Column",
                                options=raw_cols,
                                index=find_best_col(["prev", "old"], raw_cols),
                                key="map_prev_role",
                            )
                            mapped_group = st.selectbox(
                                "Group Name Column",
                                options=raw_cols,
                                index=find_best_col(["group", "member_of"], raw_cols),
                                key="map_group",
                            )
                            mapped_status = st.selectbox(
                                "Status / Result Column",
                                options=raw_cols,
                                index=find_best_col(["status", "result", "outcome"], raw_cols),
                                key="map_status",
                            )

                        if st.button("🔄 Apply Custom Mapping & Analyze", type="primary", use_container_width=True):
                            custom_map = {
                                "timestamp": mapped_ts if mapped_ts != "(None / Skip)" else "",
                                "action": mapped_action if mapped_action != "(None / Skip)" else "",
                                "username": mapped_user if mapped_user != "(None / Skip)" else "",
                                "target_user": mapped_target if mapped_target != "(None / Skip)" else "",
                                "new_role": mapped_role if mapped_role != "(None / Skip)" else "",
                                "previous_role": mapped_prev_role if mapped_prev_role != "(None / Skip)" else "",
                                "group_name": mapped_group if mapped_group != "(None / Skip)" else "",
                                "status": mapped_status if mapped_status != "(None / Skip)" else "",
                            }
                            remap_res = LogParser.process_with_custom_mapping(parsing_result.raw_df, custom_map)
                            if remap_res.is_valid:
                                run_analysis_pipeline(remap_res.df, uploaded_file.name)
                                st.success("Mapping applied and analysis complete!")
                                st.rerun()
                            else:
                                for err in remap_res.errors:
                                    st.error(f"Mapping error: {err}")
            else:
                st.success(f"✅ Successfully parsed {parsing_result.valid_rows} events from '{uploaded_file.name}'")

                if parsing_result.warnings:
                    with st.expander("⚠️ Parser Warnings", expanded=False):
                        for warn in parsing_result.warnings:
                            st.write(f"- {warn}")

                if st.button("🚀 Analyze & Save to Database", type="primary", use_container_width=True):
                    run_analysis_pipeline(parsing_result.df, uploaded_file.name)
                    st.success("Analysis complete! Results stored into SQLite and dashboard updated.")
                    st.rerun()

    # Data Preview of Currently Active Dataset
    st.markdown("---")
    st.markdown("#### **Active Audit Event Stream Preview**")
    if not st.session_state["analyzed_df"].empty:
        df_preview = st.session_state["analyzed_df"].copy()
        if "parsed_datetime" in df_preview.columns:
            df_preview = df_preview.drop(columns=["parsed_datetime"])
        st.dataframe(df_preview.head(15), use_container_width=True)
        st.caption(f"Showing first 15 records of {len(df_preview)} total events in active dataset.")
    else:
        st.info("No records currently loaded.")


# =============================================================================
# PAGE 3: 🛡️ DETECTION RESULTS
# =============================================================================
elif nav_page == "🛡️ Detection Results":
    st.markdown("## 🛡️ **Rule-Based Security Detection Results**")
    st.markdown("Explore, filter, and search flagged suspicious privilege escalation events.")

    alerts = st.session_state["alerts"]

    if not alerts:
        st.info("No suspicious activities detected in the active audit dataset.")
    else:
        # Search & Filtering Bar
        filter_col1, filter_col2, filter_col3, filter_col4 = st.columns([2, 1, 1, 1])

        with filter_col1:
            search_query = st.text_input("🔍 Search Actor, Target, IP, or Event ID", "").strip().lower()

        with filter_col2:
            risk_filter = st.selectbox("Risk Level", ["All", "HIGH", "MEDIUM", "LOW"], index=0)

        with filter_col3:
            available_rules = ["All"] + sorted(list({a["rule_name"] for a in alerts}))
            rule_filter = st.selectbox("Rule Triggered", available_rules, index=0)

        with filter_col4:
            available_actions = ["All"] + sorted(list({a["action"] for a in alerts}))
            action_filter = st.selectbox("Action Type", available_actions, index=0)

        # Apply Filters
        filtered_alerts = []
        for a in alerts:
            # Risk filter
            if risk_filter != "All" and a["risk_level"] != risk_filter:
                continue
            # Rule filter
            if rule_filter != "All" and a["rule_name"] != rule_filter:
                continue
            # Action filter
            if action_filter != "All" and a["action"] != action_filter:
                continue
            # Free search query
            if search_query:
                combined_text = (
                    f"{a['event_id']} {a['username']} {a['target_user']} {a['source_ip']} "
                    f"{a['action']} {a['resource']} {a['explanation']}"
                ).lower()
                if search_query not in combined_text:
                    continue
            filtered_alerts.append(a)

        st.markdown(f"**Showing {len(filtered_alerts)} of {len(alerts)} flagged detections**")

        # Table Display
        display_rows = []
        for a in filtered_alerts:
            role_change = f"{a['previous_role'] or 'None'} ➡️ {a['new_role'] or 'None'}" if (a['previous_role'] or a['new_role']) else "N/A"
            display_rows.append({
                "Event ID": a["event_id"],
                "Timestamp": a["timestamp"],
                "Risk": RiskClassifier.get_risk_badge(a["risk_level"]),
                "Actor": a["username"],
                "Action": a["action"],
                "Target User": a["target_user"] or "N/A",
                "Role Elevation": role_change,
                "Rule Name": a["rule_name"],
                "Source IP": a["source_ip"],
            })

        st.dataframe(pd.DataFrame(display_rows), use_container_width=True, hide_index=True)

        st.markdown("---")
        # Direct Jump to Investigation
        select_event_ids = [a["event_id"] for a in filtered_alerts]
        if select_event_ids:
            col_sel, col_btn = st.columns([3, 1])
            with col_sel:
                chosen_event = st.selectbox("Select Flagged Event to Investigate:", select_event_ids)
            with col_btn:
                st.write("")
                st.write("")
                if st.button("🔍 Deep Dive Investigation", type="primary", use_container_width=True):
                    st.session_state["selected_event_id"] = chosen_event
                    st.info(f"Selected {chosen_event}. Switch to 'Alert Details & Deep Dive' tab in sidebar to view.")


# =============================================================================
# PAGE 4: 🔍 ALERT DETAILS & DEEP DIVE
# =============================================================================
elif nav_page == "🔍 Alert Details & Deep Dive":
    st.markdown("## 🔍 **Alert Details & Forensic Dossier**")
    st.markdown("Detailed breakdown of triggered detection rules, context explanations, and investigation playbooks.")

    alerts = st.session_state["alerts"]

    if not alerts:
        st.info("No alerts available to inspect.")
    else:
        all_event_ids = [a["event_id"] for a in alerts]
        current_idx = 0
        if st.session_state["selected_event_id"] in all_event_ids:
            current_idx = all_event_ids.index(st.session_state["selected_event_id"])

        selected_id = st.selectbox("Select Event ID:", all_event_ids, index=current_idx)
        st.session_state["selected_event_id"] = selected_id

        # Find alert
        target_alert = next((a for a in alerts if a["event_id"] == selected_id), None)

        if target_alert:
            risk_badge = RiskClassifier.get_risk_badge(target_alert["risk_level"])

            # Main Alert Card
            st.markdown(
                f"""<div class="cyber-card">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <h3 style="margin: 0; color: #38bdf8;">Event Dossier: {target_alert['event_id']}</h3>
                        <span style="font-size: 1.1rem;">{risk_badge}</span>
                    </div>
                    <p style="color: #94a3b8; margin-top: 5px;">Triggered Rule: <b>{target_alert['rule_name']}</b> ({target_alert['rule_id']})</p>
                </div>""",
                unsafe_allow_html=True,
            )

            # Metadata grid
            m1, m2, m3, m4 = st.columns(4)
            with m1:
                st.markdown(f"**Timestamp:** `{target_alert['timestamp']}`")
                st.markdown(f"**Actor (Username):** `{target_alert['username']}`")
            with m2:
                st.markdown(f"**Source IP:** `{target_alert['source_ip']}`")
                st.markdown(f"**Action:** `{target_alert['action']}`")
            with m3:
                st.markdown(f"**Target User:** `{target_alert['target_user'] or 'None'}`")
                st.markdown(f"**Resource:** `{target_alert['resource'] or 'None'}`")
            with m4:
                st.markdown(f"**Outcome Status:** `{target_alert['status']}`")
                st.markdown(f"**Group:** `{target_alert['group_name'] or 'None'}`")

            # Role Elevation Visualizer
            if target_alert.get("previous_role") or target_alert.get("new_role"):
                st.markdown(
                    f"""<div style="background: #111827; padding: 12px 18px; border-radius: 6px; border: 1px solid #1f2937; margin: 15px 0;">
                        <span style="color: #94a3b8;">Role Transition: </span>
                        <span style="color: #cbd5e1; font-weight: 600;">{target_alert.get('previous_role') or 'Standard/None'}</span>
                        <span style="color: #38bdf8; font-size: 1.2rem; margin: 0 10px;">➔</span>
                        <span style="color: #ef4444; font-weight: 700;">{target_alert.get('new_role') or 'None'}</span>
                    </div>""",
                    unsafe_allow_html=True,
                )

            # Detailed Explanation
            st.markdown("#### 💡 **Detection Reason & Security Narrative**")
            st.info(target_alert["explanation"])

            # Recommended Investigation Steps
            st.markdown("#### 🛠️ **Recommended Forensic Investigation Steps**")
            steps_list = target_alert["investigation_steps"].split("\n")
            for step in steps_list:
                if step.strip():
                    st.markdown(f"- {step.strip()}")

            # Raw Event Record
            with st.expander("🔍 Inspect Raw Audit Event Data", expanded=False):
                st.json(target_alert)


# =============================================================================
# PAGE 5: 🗄️ AUDIT HISTORY (SQLITE)
# =============================================================================
elif nav_page == "🗄️ Audit History (SQLite)":
    st.markdown("## 🗄️ **SQLite Audit Storage & Historical Analysis Runs**")
    st.markdown(
        "Audit logs and detection runs are stored using parameterized queries in SQLite (`audit_monitor.db`)."
    )

    runs = db.get_all_runs()

    st.markdown("### **Past Analysis Runs**")
    if runs:
        runs_df = pd.DataFrame(runs)
        st.dataframe(runs_df, use_container_width=True, hide_index=True)
    else:
        st.info("No prior analysis runs found in SQLite storage.")

    st.markdown("---")
    st.markdown("### **Stored Raw Audit Events (Latest 100)**")
    raw_events_df = db.get_all_events(limit=100)
    if not raw_events_df.empty:
        st.dataframe(raw_events_df, use_container_width=True, hide_index=True)
    else:
        st.info("No events stored in SQLite.")

    st.markdown("---")
    with st.expander("⚠️ Database Maintenance & Reset", expanded=False):
        st.warning("Clearing the database permanently purges all historical runs, events, and alerts.")
        if st.button("🗑️ Purge All Stored Records", type="secondary"):
            db.clear_database()
            st.success("Database cleared successfully.")
            st.rerun()


# =============================================================================
# PAGE 6: 📄 REPORTS & EXPORT
# =============================================================================
elif nav_page == "📄 Reports & Export":
    st.markdown("## 📄 **Audit Report Generation & Export**")
    st.markdown(
        "Generate formal cybersecurity compliance audit reports in **CSV**, **TXT**, and **JSON** formats."
    )

    metrics = st.session_state["metrics"]
    alerts = st.session_state["alerts"]
    filename = st.session_state["active_file_name"]

    if not alerts and st.session_state["analyzed_df"].empty:
        st.info("No audit logs loaded. Please upload logs or reload sample data to generate reports.")
    else:
        # Analyst notes input
        analyst_notes = st.text_area(
            "Auditor / Analyst Remarks (Included in TXT Report):",
            value="Audit performed in accordance with corporate security baseline standards. Potential privilege escalation anomalies highlighted for immediate Tier-2 SOC validation.",
            height=80,
        )

        col_txt, col_csv, col_json = st.columns(3)

        # TXT Report
        txt_report_str = ReportGenerator.generate_txt_report(
            metrics=metrics, alerts=alerts, source_filename=filename, analyst_notes=analyst_notes
        )
        with col_txt:
            st.download_button(
                label="📥 Download Audit Report (TXT)",
                data=txt_report_str.encode("utf-8"),
                file_name=f"audit_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.txt",
                mime="text/plain",
                type="primary",
                use_container_width=True,
            )

        # CSV Alerts Report
        csv_report_str = ReportGenerator.generate_csv_report(alerts)
        with col_csv:
            st.download_button(
                label="📥 Download Alerts Data (CSV)",
                data=csv_report_str.encode("utf-8"),
                file_name=f"audit_alerts_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
                use_container_width=True,
            )

        # JSON Machine Report
        json_report_str = ReportGenerator.generate_json_report(
            metrics=metrics, alerts=alerts, source_filename=filename
        )
        with col_json:
            st.download_button(
                label="📥 Download Machine Report (JSON)",
                data=json_report_str.encode("utf-8"),
                file_name=f"audit_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json",
                use_container_width=True,
            )

        st.markdown("---")
        st.markdown("#### **Executive Report Preview (TXT Format)**")
        st.code(txt_report_str, language="text")


# =============================================================================
# PAGE 7: ⚙️ RULE CONFIGURATION
# =============================================================================
elif nav_page == "⚙️ Rule Configuration":
    st.markdown("## ⚙️ **Detection Rule Configuration & Tuning**")
    st.markdown(
        "Customize detection thresholds, whitelist authorized security administrators, and adjust operational parameters."
    )

    current_cfg = st.session_state["rule_config"]

    with st.form("rule_config_form"):
        st.markdown("#### 1. Privileged Roles & Sensitive Groups")
        priv_roles_text = st.text_area(
            "Privileged Roles (comma-separated):",
            value=", ".join(current_cfg.get("privileged_roles", [])),
            help="Roles considered high privilege (e.g. Administrator, root, superuser).",
        )

        priv_groups_text = st.text_area(
            "Privileged Groups (comma-separated):",
            value=", ".join(current_cfg.get("privileged_groups", [])),
            help="Security groups granting administrative authority.",
        )

        st.markdown("#### 2. Authorized Administrators & Whitelist")
        auth_actors_text = st.text_area(
            "Authorized Security Actors (comma-separated):",
            value=", ".join(current_cfg.get("authorized_admin_actors", [])),
            help="User accounts permitted to perform administrative modifications without triggering RULE-04.",
        )

        st.markdown("#### 3. Operational Windows & Thresholds")
        col_w1, col_w2, col_w3 = st.columns(3)
        with col_w1:
            w_start = st.number_input(
                "Working Hours Start (0-23):",
                min_value=0,
                max_value=23,
                value=int(current_cfg.get("working_hours_start", 8)),
            )
            w_end = st.number_input(
                "Working Hours End (0-23):",
                min_value=0,
                max_value=23,
                value=int(current_cfg.get("working_hours_end", 18)),
            )
        with col_w2:
            failed_threshold = st.number_input(
                "Failed Actions Threshold (Count):",
                min_value=1,
                max_value=20,
                value=int(current_cfg.get("failed_attempts_threshold", 3)),
            )
        with col_w3:
            rapid_window = st.number_input(
                "Rapid Change Window (Minutes):",
                min_value=1,
                max_value=120,
                value=int(current_cfg.get("rapid_change_window_minutes", 15)),
            )

        submit_save = st.form_submit_button("💾 Save Configuration & Re-analyze", type="primary")

    if submit_save:
        updated_cfg = {
            "privileged_roles": [r.strip() for r in priv_roles_text.split(",") if r.strip()],
            "privileged_groups": [g.strip() for g in priv_groups_text.split(",") if g.strip()],
            "authorized_admin_actors": [a.strip() for a in auth_actors_text.split(",") if a.strip()],
            "working_hours_start": int(w_start),
            "working_hours_end": int(w_end),
            "failed_attempts_threshold": int(failed_threshold),
            "rapid_change_window_minutes": int(rapid_window),
        }
        st.session_state["rule_config"] = {**current_cfg, **updated_cfg}
        db.save_rule_config(updated_cfg)

        # Re-run analysis on active DataFrame with updated config
        if not st.session_state["analyzed_df"].empty:
            run_analysis_pipeline(st.session_state["analyzed_df"], st.session_state["active_file_name"])

        st.success("Rule configuration updated and active dataset re-evaluated!")
        st.rerun()

    if st.button("🔄 Reset to Default Configuration"):
        st.session_state["rule_config"] = {**DEFAULT_CONFIG}
        db.save_rule_config(DEFAULT_CONFIG)
        if not st.session_state["analyzed_df"].empty:
            run_analysis_pipeline(st.session_state["analyzed_df"], st.session_state["active_file_name"])
        st.success("Reset to factory defaults.")
        st.rerun()


# =============================================================================
# PAGE 8: ℹ️ ABOUT THE PROJECT
# =============================================================================
elif nav_page == "ℹ️ About the Project":
    st.markdown("## ℹ️ **About: T2-PS7 Privilege Escalation Monitor**")
    st.markdown(
        "A modular, educational, and audit-grade cybersecurity application for detecting privilege elevation anomalies."
    )

    st.markdown(
        """<div class="cyber-card">
            <h3 style="color: #38bdf8; margin-top: 0;">🎯 Project Objective & Purpose</h3>
            <p style="color: #cbd5e1; line-height: 1.6;">
                Privilege escalation is one of the most critical stages in modern cyberattacks (Cyber Kill Chain Step 4 / 
                MITRE ATT&CK TA0004). Once adversaries establish initial access via standard user accounts, they attempt to 
                elevate their permissions to gain domain or root control.
            </p>
            <p style="color: #cbd5e1; line-height: 1.6;">
                <b>T2-PS7</b> monitors system audit logs in real-time, executing deterministic, rule-based security heuristics 
                to identify privilege creep, unauthorized account creation, group tampering, and out-of-band administrative actions.
            </p>
        </div>""",
        unsafe_allow_html=True,
    )

    st.markdown("### 🗺️ **MITRE ATT&CK® Framework Mapping**")
    mitre_data = [
        {"Rule ID": "RULE-01", "Rule Name": "Admin Account Creation", "MITRE Technique": "T1136.001 / T1136.002", "Tactic": "Persistence"},
        {"Rule ID": "RULE-02", "Rule Name": "Privilege Escalation", "MITRE Technique": "T1548 / T1078", "Tactic": "Privilege Escalation"},
        {"Rule ID": "RULE-03", "Rule Name": "Privileged Group Membership", "MITRE Technique": "T1098 - Account Manipulation", "Tactic": "Persistence"},
        {"Rule ID": "RULE-04", "Rule Name": "Unauthorized Actor", "MITRE Technique": "T1078 - Valid Accounts", "Tactic": "Defense Evasion"},
        {"Rule ID": "RULE-05", "Rule Name": "Repeated Failed Admin Actions", "MITRE Technique": "T1110 - Brute Force", "Tactic": "Credential Access"},
        {"Rule ID": "RULE-06", "Rule Name": "Suspicious Permission Changes", "MITRE Technique": "T1222 - Permission Modification", "Tactic": "Defense Evasion"},
        {"Rule ID": "RULE-07", "Rule Name": "After-Hours Privileged Activity", "MITRE Technique": "T1078 - Anomalous Timing", "Tactic": "Defense Evasion"},
        {"Rule ID": "RULE-08", "Rule Name": "Rapid Privilege Changes", "MITRE Technique": "T1098 - Rapid Elevation/Revocation", "Tactic": "Privilege Escalation"},
    ]
    st.dataframe(pd.DataFrame(mitre_data), use_container_width=True, hide_index=True)

    st.markdown("---")
    st.markdown("### 🔬 **Rule-Based Heuristics vs. Machine Learning**")
    st.markdown(
        """
        - **Why Rule-Based?** Security auditing demands **deterministic explainability**, zero 'black-box' hallucinations, 
          and immediate compliance mapping. Every alert triggered in this system has an exact causal reason and recommended playbook.
        - **Deterministic vs Heuristic:** Rules can be tuned by administrators to match the organization's explicit policies 
          without needing gigabytes of labeled training data.
        """
    )

    st.markdown("---")
    st.markdown("### ⚠️ **Educational & Legal Notice**")
    st.warning(RiskClassifier.get_educational_disclaimer())
