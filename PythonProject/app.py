import pandas as pd
import streamlit as st

from core.api import check_hash_virustotal, check_ip_abuseipdb
from core.config import APP_CONFIG, load_api_keys
from core.dashboard import render_bulk_tab
from core.risk import get_category, get_recommendation, get_severity
from core.validators import validate_hash, validate_public_ip


st.set_page_config(
    page_title=APP_CONFIG["page_title"],
    page_icon=APP_CONFIG["page_icon"],
    layout="wide",
)


ABUSEIPDB_API_KEY, VIRUSTOTAL_API_KEY = load_api_keys()


def render_sidebar() -> dict:
    with st.sidebar:
        st.header("Settings")

        st.caption(f"Cache TTL: {APP_CONFIG['cache_ttl'] // 60} minutes")
        st.caption(f"Request Timeout: {APP_CONFIG['request_timeout']} seconds")
        st.caption(f"Bulk Limit: {APP_CONFIG['max_bulk_ips']} public IPs/run")

        st.divider()
        st.header("Risk Thresholds")

        malicious_threshold = st.slider(
            "Malicious Threshold",
            min_value=1,
            max_value=100,
            value=50,
            step=1,
        )

        high_severity_threshold = st.slider(
            "High Severity Threshold",
            min_value=1,
            max_value=100,
            value=75,
            step=1,
        )

        st.divider()
        st.header("API Providers")
        st.write("- AbuseIPDB")
        st.write("- VirusTotal")

    return {
        "malicious_threshold": malicious_threshold,
        "high_severity_threshold": high_severity_threshold,
    }


def render_confidence_note() -> None:
    st.caption(
        "Note: External reputation data should be validated with internal telemetry "
        "before containment, blocking, or escalation decisions."
    )


def render_single_ip_tab(thresholds: dict) -> None:
    st.header("Single IP Investigation")

    ip_input = st.text_input(
        "IP Address",
        placeholder="Example: 8.8.8.8",
    )

    if not st.button("Scan IP", use_container_width=True, key="scan_single_ip"):
        return

    is_valid, normalized_ip, error_message = validate_public_ip(ip_input)

    if not is_valid:
        st.warning(error_message)
        return

    with st.spinner("Checking AbuseIPDB..."):
        result = check_ip_abuseipdb(
            ip_address=normalized_ip,
            api_key=ABUSEIPDB_API_KEY,
        )

    if not result["ok"]:
        st.error(result["error"])
        return

    data = result["data"]

    score = int(data.get("abuseConfidenceScore", 0) or 0)
    reports = int(data.get("totalReports", 0) or 0)

    category = get_category(
        score=score,
        malicious_threshold=thresholds["malicious_threshold"],
    )

    severity = get_severity(
        score=score,
        reports=reports,
        high_severity_threshold=thresholds["high_severity_threshold"],
    )

    if category == "Malicious":
        st.error(f"🚨 MALICIOUS | Score: {score}% | Severity: {severity}")
    elif category == "Suspicious":
        st.warning(f"⚠️ SUSPICIOUS | Score: {score}% | Severity: {severity}")
    else:
        st.success(f"✅ CLEAN | Score: {score}% | Severity: {severity}")

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("ISP", data.get("isp", "-"))
    col2.metric("Country", data.get("countryCode", "-"))
    col3.metric("Reports", reports)
    col4.metric("Usage Type", data.get("usageType", "-"))

    st.subheader("Recommended Action")
    st.info(get_recommendation(category))

    render_confidence_note()

    with st.expander("Raw AbuseIPDB Response"):
        st.json(data)


def render_single_hash_tab() -> None:
    st.header("Malware Hash Check")

    hash_input = st.text_input(
        "File Hash",
        placeholder="MD5 / SHA1 / SHA256",
    )

    if not st.button("Scan Hash", use_container_width=True, key="scan_single_hash"):
        return

    is_valid, normalized_hash, hash_type = validate_hash(hash_input)

    if not is_valid:
        st.warning(hash_type)
        return

    with st.spinner("Checking VirusTotal..."):
        result = check_hash_virustotal(
            file_hash=normalized_hash,
            api_key=VIRUSTOTAL_API_KEY,
        )

    if not result["ok"]:
        st.error(result["error"])
        return

    data = result["data"]

    if data.get("not_found"):
        st.warning("Hash tidak ditemukan di VirusTotal.")
        return

    stats = data.get("last_analysis_stats", {})

    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    harmless = int(stats.get("harmless", 0) or 0)
    undetected = int(stats.get("undetected", 0) or 0)

    if malicious > 0:
        st.error(f"🚨 DETECTED | {malicious} engine mendeteksi malicious.")
    elif suspicious > 0:
        st.warning(f"⚠️ SUSPICIOUS | {suspicious} engine menandai suspicious.")
    else:
        st.success("✅ CLEAN / No malicious detection found.")

    col1, col2, col3, col4, col5 = st.columns(5)

    col1.metric("Hash Type", hash_type)
    col2.metric("Malicious", malicious)
    col3.metric("Suspicious", suspicious)
    col4.metric("Harmless", harmless)
    col5.metric("Undetected", undetected)

    render_confidence_note()

    with st.expander("VirusTotal Analysis Stats"):
        st.json(stats)

    with st.expander("Raw VirusTotal Attributes"):
        st.json(data)


def main() -> None:
    st.title("🛡️ SOC Analyst Toolkit")
    st.markdown("Incident Response Dashboard for IOC Reputation, Bulk Analysis, and Reporting")

    thresholds = render_sidebar()

    tab_ip, tab_hash, tab_bulk = st.tabs(
        [
            "🌐 Single IP",
            "🦠 Single Hash",
            "📊 Bulk Reporting",
        ]
    )

    with tab_ip:
        render_single_ip_tab(thresholds)

    with tab_hash:
        render_single_hash_tab()

    with tab_bulk:
        render_bulk_tab(
            api_key=ABUSEIPDB_API_KEY,
            thresholds=thresholds,
        )


if __name__ == "__main__":
    main()
