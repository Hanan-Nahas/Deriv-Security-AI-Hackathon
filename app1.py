"""Streamlit dashboard for secure chat, pentest mode, and logs analytics."""

from __future__ import annotations

import logging
import uuid

import pandas as pd
import streamlit as st

from ai_shield.core.llm_pipeline import LLMPipeline
from ai_shield.core.rag_engine import RAGEngine
from ai_shield.pentest.attack_generator import AttackGenerator
from ai_shield.pentest.report_generator import ReportGenerator
from ai_shield.pentest.vulnerability_analyzer import VulnerabilityAnalyzer
from ai_shield.utils.logging_config import configure_logging
from ai_shield.waf.behavior_monitor import BehaviorMonitor

configure_logging()
logger = logging.getLogger(__name__)

st.set_page_config(page_title="Deriv's AI Shield", layout="wide")
st.markdown(
    """
    <style>
    .hero-card {
        padding: 1.25rem 1.5rem;
        border-radius: 16px;
        background: linear-gradient(135deg, #0ea5e9 0%, #6366f1 55%, #9333ea 100%);
        color: #fff;
        box-shadow: 0 12px 30px rgba(15, 23, 42, 0.18);
    }
    .hero-card h1 {
        font-size: 2.1rem;
        margin-bottom: 0.2rem;
    }
    .hero-card p {
        margin: 0;
        font-size: 1rem;
        opacity: 0.95;
    }
    .pill {
        display: inline-block;
        padding: 0.2rem 0.6rem;
        border-radius: 999px;
        font-weight: 600;
        font-size: 0.8rem;
        margin-right: 0.4rem;
    }
    .pill-waf { background: #0f172a; color: #38bdf8; border: 1px solid rgba(226, 232, 240, 0.3); }
    .pill-pentest { background: #0f172a; color: #facc15; border: 1px solid rgba(226, 232, 240, 0.3); }
    .pill-monitor { background: #0f172a; color: #34d399; border: 1px solid rgba(226, 232, 240, 0.3); }
    .metric-card {
        padding: 1rem;
        border-radius: 14px;
        border: 1px solid rgba(148, 163, 184, 0.25);
        background: #ffffff;
        box-shadow: 0 8px 24px rgba(15, 23, 42, 0.08);
    }
    .section-title {
        font-size: 1.2rem;
        font-weight: 700;
        margin-top: 0.6rem;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

st.markdown(
    """
    <div class="hero-card">
        <h1>🛡️ Deriv AI Shield</h1>
        <p>AI WAF + Autonomous Pentesting + Behavior Monitoring for real-time LLM security.</p>
        <div style="margin-top: 0.6rem;">
            <span class="pill pill-waf">AI WAF</span>
            <span class="pill pill-pentest">Pentest</span>
            <span class="pill pill-monitor">Threat Monitor</span>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

if "session_id" not in st.session_state:
    st.session_state.session_id = str(uuid.uuid4())
if "chat_history" not in st.session_state:
    st.session_state.chat_history = []
if "pentest_records" not in st.session_state:
    st.session_state.pentest_records = []
if "threat_scores" not in st.session_state:
    st.session_state.threat_scores = []

theme_mode = st.sidebar.toggle("Dark Mode", value=False)
if theme_mode:
    st.markdown(
        """
        <style>
        body, .stApp { background-color: #0f172a; color: #e2e8f0; }
        .stMarkdown, .stMarkdown p, .stText, .stCaption, .stSubheader, .stTitle {
            color: #e2e8f0 !important;
        }
        .stTextInput, .stTextArea, .stTextArea textarea, .stTextInput input {
            color: #e2e8f0 !important;
            background-color: #111827 !important;
        }
        label, .stSelectbox, .stSlider, .stRadio, .stCheckbox, .stToggle {
            color: #e2e8f0 !important;
        }
        .stDataFrame, .stTable, .stMetric {
            color: #e2e8f0 !important;
        }
        .metric-card {
            background: #111827 !important;
            border: 1px solid rgba(148, 163, 184, 0.3) !important;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

monitor = BehaviorMonitor()
rag_engine = RAGEngine()
rag_engine.add_documents([
    "Deriv AI Shield blocks prompt injection and data exfiltration attacks.",
    "Always validate user input before sending to any language model.",
    "Apply output redaction to avoid leaking keys, passwords, and tokens.",
])
pipeline = LLMPipeline(behavior_monitor=monitor, rag_engine=rag_engine)
attack_generator = AttackGenerator()
analyzer = VulnerabilityAnalyzer()
reporter = ReportGenerator()

tab1, tab2, tab3 = st.tabs(["💬 Secure Chat", "🧪 Pentest Mode", "📊 Logs Dashboard"])

with tab1:
    st.subheader("Protected LLM Conversation (AI WAF)")
    col_a, col_b, col_c = st.columns(3)
    with col_a:
        st.markdown('<div class="metric-card"><b>AI WAF Status</b><br>✅ Active</div>', unsafe_allow_html=True)
    with col_b:
        st.markdown(
            '<div class="metric-card"><b>Input Filters</b><br>Prompt Injection, Encoding, Role Overrides</div>',
            unsafe_allow_html=True,
        )
    with col_c:
        st.markdown(
            '<div class="metric-card"><b>Output Guard</b><br>Secrets Redaction + Leakage Prevention</div>',
            unsafe_allow_html=True,
        )
    user_input = st.text_area("Enter your message", height=120)
    if st.button("Clear Chat", key="clear_chat_btn"):
        st.session_state.chat_history = []
    if st.button("Send", key="send_btn"):
        response = pipeline.process(user_input=user_input, session_id=st.session_state.session_id)
        st.session_state.chat_history.append(
            {
                "user": user_input,
                "assistant": response.text,
                "blocked": response.blocked,
                "risk": response.risk_score,
                "reason": response.reason,
            }
        )

    st.markdown('<div class="section-title">⚡ Live Attack Simulation</div>', unsafe_allow_html=True)
    attack_payloads = attack_generator.generate(count=5)
    attack_choice = st.selectbox("Select a simulated attack", [a.payload for a in attack_payloads])
    if st.button("Simulate Attack", key="simulate_btn"):
        response = pipeline.process(user_input=attack_choice, session_id=st.session_state.session_id)
        st.session_state.chat_history.append(
            {
                "user": attack_choice,
                "assistant": response.text,
                "blocked": response.blocked,
                "risk": response.risk_score,
                "reason": response.reason,
            }
        )

    for i, turn in enumerate(reversed(st.session_state.chat_history), start=1):
        st.markdown(f"**Turn {i}**")
        st.write(f"User: {turn['user']}")
        st.write(f"Assistant: {turn['assistant']}")
        st.caption(f"Blocked: {turn['blocked']} | Risk: {turn['risk']} | Reason: {turn.get('reason', 'n/a')}")

with tab2:
    st.subheader("Autonomous Security Testing")
    st.caption("Launch AI-driven pentests to surface critical prompt injection and data exfiltration risks.")
    count = st.slider("Number of generated attacks", min_value=5, max_value=30, value=10)
    if st.button("Run Pentest", key="pentest_btn"):
        records = []
        for attack in attack_generator.generate(count=count):
            result = pipeline.input_filter.scan(attack.payload)
            monitor.add_event(st.session_state.session_id, attack.category, result.risk_score)
            records.append(analyzer.analyze(attack, result))

        summary = analyzer.aggregate(records)
        riskiest = analyzer.most_dangerous_unblocked(records)
        mitigations = analyzer.mitigation_suggestions(records)
        markdown_report = reporter.generate_markdown(records, summary)
        html_report = reporter.generate_html(markdown_report)
        paths = reporter.save_reports(markdown_report, html_report)

        st.session_state.pentest_records = records
        st.success("Pentest run completed")
        st.subheader("Executive Summary")
        st.write(f"**Overall risk score:** {summary.get('overall_score', 0.0)}")
        st.write(f"**Critical vulnerabilities:** {summary.get('critical_findings', 0)}")
        st.write(f"**Most dangerous unblocked attack:** {riskiest.get('category', 'none')}")
        st.write(f"**Potential impact:** {riskiest.get('impact', 'N/A')}")
        st.write("**Auto-mitigation suggestions:**")
        for item in mitigations:
            st.write(f"- {item}")
        st.json(summary)
        st.code(markdown_report, language="markdown")
        st.write(f"Saved reports: {paths}")
        pdf_bytes = b""
        if paths.get("pdf"):
            with open(paths["pdf"], "rb") as handle:
                pdf_bytes = handle.read()
        st.download_button(
            "Download PDF Report",
            data=pdf_bytes,
            file_name=paths.get("pdf", "pentest_report.pdf"),
            disabled=not pdf_bytes,
        )
        blocked = sum(1 for record in records if record.blocked)
        unblocked = len(records) - blocked
        st.subheader("Blocked vs Unblocked")
        st.bar_chart(pd.DataFrame({"count": [blocked, unblocked]}, index=["Blocked", "Unblocked"]))
        st.subheader("Severity Heatmap")
        severity_df = pd.DataFrame([{"severity": r.severity, "blocked": r.blocked} for r in records])
        heatmap = severity_df.groupby(["severity", "blocked"]).size().unstack(fill_value=0)
        st.dataframe(heatmap)

with tab3:
    st.subheader("Threat and Activity Dashboard")
    summary = monitor.get_session_summary(st.session_state.session_id)
    st.session_state.threat_scores.append(summary.get("threat_score", 0.0))
    st.metric("Threat Score", summary.get("threat_score", 0.0))
    st.metric("Events", summary.get("event_count", 0))

    if st.session_state.threat_scores:
        st.line_chart(pd.DataFrame({"Threat Score": st.session_state.threat_scores}))

    if summary.get("top_attack_types"):
        df = pd.DataFrame(
            [{"Attack Type": key, "Count": val} for key, val in summary["top_attack_types"].items()]
        )
        st.bar_chart(df.set_index("Attack Type"))

    if st.session_state.pentest_records:
        df_records = pd.DataFrame([record.__dict__ for record in st.session_state.pentest_records])
        st.dataframe(df_records)
        st.subheader("Attack Details")
        for record in st.session_state.pentest_records:
            with st.expander(f"{record.category} | Severity {record.severity} | Blocked {record.blocked}"):
                st.write(f"Payload: {record.payload}")
                st.write(f"Vulnerability Score: {record.vulnerability_score}")

