from datetime import datetime

import pandas as pd
import streamlit as st

from core.api import check_hash_virustotal, check_ip_abuseipdb
from core.config import APP_CONFIG, load_api_keys
from core.report import create_pdf_report
from core.risk import get_category, get_recommendation, get_severity
from core.validators import parse_bulk_ips, validate_hash, validate_public_ip


st.set_page_config(
    page_title=APP_CONFIG["page_title"],
    page_icon=APP_CONFIG["page_icon"],
    layout="wide",
)


ABUSEIPDB_API_KEY, VIRUSTOTAL_API_KEY = load_api_keys()


def build_success_row(ip_address: str, data: dict) -> dict:
    score = int(data.get("abuseConfidenceScore", 0) or 0)
    reports = int(data.get("totalReports", 0) or 0)

    category = get_category(score)
    severity = get_severity(score, reports)

    return {
        "Scan Time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "IOC Type": "IP Address",
        "IP": ip_address,
        "Risk Score": score,
        "Category": category,
        "Severity": severity,
        "Reports": reports,
        "Country": data.get("countryCode", "-"),
        "ISP": data.get("isp", "-"),
        "Recommended Action": get_recommendation(category),
        "Error": "",
    }


def build_invalid_row(ip_address: str, error_message: str) -> dict:
    return {
        "Scan Time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "IOC Type": "IP Address",
        "IP": ip_address,
        "Risk Score": "-",
        "Category": "Invalid",
        "Severity": "-",
        "Reports": 0,
        "Country": "-",
        "ISP": "-",
        "Recommended Action": get_recommendation("Invalid"),
        "Error": error_message,
    }


def build_error_row(ip_address: str, error_message: str) -> dict:
    return {
        "Scan Time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "IOC Type": "IP Address",
        "IP": ip_address,
        "Risk Score": "-",
        "Category": "Error",
        "Severity": "-",
        "Reports": 0,
        "Country": "-",
        "ISP": "-",
        "Recommended Action": get_recommendation("Error"),
        "Error": error_message,
    }


def style_category(value: str) -> str:
    colors = {
        "Malicious": "background-color: #ff4b4b; color: black",
        "Suspicious": "background-color: #ffa500; color: black",
        "Clean": "background-color: #90ee90; color: black",
        "Invalid": "background-color: #d3d3d3; color: black",
        "Error": "background-color: #d3d3d3; color: black",
    }

    return colors.get(value, "")


def render_sidebar() -> None:
    with st.sidebar:
        st.header("Settings")
        st.caption(f"Cache TTL: {APP_CONFIG['cache_ttl'] // 60} minutes")
        st.caption(f"Request Timeout: {APP_CONFIG['request_timeout']} seconds")
        st.caption(f"Bulk Limit: {APP_CONFIG['max_bulk_ips']} public IPs/run")

        st.divider()

        st.header("API Providers")
        st.write("- AbuseIPDB")
        st.write("- VirusTotal")


def render_single_ip_tab() -> None:
    st.header("Single IP Investigation")

    ip_input = st.text_input(
        "IP Address",
        placeholder="Example: 8.8.8.8",
    )

    if not st.button("Scan IP", use_container_width=True):
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

    category = get_category(score)
    severity = get_severity(score, reports)

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

    with st.expander("Raw AbuseIPDB Response"):
        st.json(data)


def render_single_hash_tab() -> None:
    st.header("Malware Hash Check")

    hash_input = st.text_input(
        "File Hash",
        placeholder="MD5 / SHA1 / SHA256",
    )

    if not st.button("Scan Hash", use_container_width=True):
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

    with st.expander("VirusTotal Analysis Stats"):
        st.json(stats)

    with st.expander("Raw VirusTotal Attributes"):
        st.json(data)


def render_bulk_tab() -> None:
    st.header("Bulk IP Analyzer & Reporting")

    bulk_input = st.text_area(
        "Input IP List",
        height=260,
        placeholder="One public IP per line\n8.8.8.8\n1.1.1.1",
    )

    if not st.button("Analyze & Generate Report", use_container_width=True):
        return

    targets, duplicate_count = parse_bulk_ips(bulk_input)

    if not targets:
        st.warning("List IP kosong.")
        return

    valid_count = sum(1 for item in targets if item["valid"])

    if valid_count > APP_CONFIG["max_bulk_ips"]:
        st.error(
            f"Terlalu banyak public IP valid. "
            f"Maksimal {APP_CONFIG['max_bulk_ips']} IP per bulk scan."
        )
        return

    if duplicate_count:
        st.info(f"{duplicate_count} duplicate IP dilewati.")

    results = []
    progress = st.progress(0)
    status = st.empty()

    for index, target in enumerate(targets):
        ip_address = target["ip"]

        if not target["valid"]:
            results.append(build_invalid_row(ip_address, target["error"]))
            progress.progress((index + 1) / len(targets))
            continue

        status.write(f"Scanning {index + 1}/{len(targets)}: `{ip_address}`")

        result = check_ip_abuseipdb(
            ip_address=ip_address,
            api_key=ABUSEIPDB_API_KEY,
        )

        if result["ok"]:
            results.append(build_success_row(ip_address, result["data"]))
        else:
            results.append(build_error_row(ip_address, result["error"]))

        progress.progress((index + 1) / len(targets))

    status.empty()
    progress.empty()

    df = pd.DataFrame(results)

    malicious_count = len(df[df["Category"] == "Malicious"])
    suspicious_count = len(df[df["Category"] == "Suspicious"])
    clean_count = len(df[df["Category"] == "Clean"])
    error_count = len(df[df["Category"].isin(["Invalid", "Error"])])

    st.divider()

    col1, col2, col3, col4, col5 = st.columns(5)

    col1.metric("Total Items", len(df))
    col2.metric("Malicious", malicious_count)
    col3.metric("Suspicious", suspicious_count)
    col4.metric("Clean", clean_count)
    col5.metric("Invalid/Error", error_count)

    st.divider()

    chart1, chart2 = st.columns(2)

    with chart1:
        st.caption("Risk Distribution")
        st.bar_chart(df["Category"].value_counts())

    with chart2:
        st.caption("Country Origin")
        country_data = df[~df["Country"].isin(["-", "", None])]["Country"].value_counts()

        if country_data.empty:
            st.info("Tidak ada country data.")
        else:
            st.bar_chart(country_data)

    st.subheader("Investigation Log")

    try:
        styled_df = df.style.applymap(style_category, subset=["Category"])
        st.dataframe(styled_df, use_container_width=True)
    except Exception:
        st.dataframe(df, use_container_width=True)

    malicious_ips = df[df["Category"] == "Malicious"]["IP"].tolist()

    if malicious_ips:
        st.subheader("Blocklist Candidate")
        st.caption("Review kembali dengan internal telemetry sebelum blocking production.")
        st.code("\n".join(malicious_ips), language="text")

    error_df = df[df["Category"].isin(["Invalid", "Error"])]

    if not error_df.empty:
        with st.expander("Invalid/Error Details"):
            st.dataframe(
                error_df[["IP", "Category", "Error"]],
                use_container_width=True,
            )

    st.divider()
    st.subheader("Export Report")

    export_csv, export_pdf = st.columns(2)

    with export_csv:
        csv_data = df.to_csv(index=False).encode("utf-8")

        st.download_button(
            label="Download CSV",
            data=csv_data,
            file_name="soc_scan_results.csv",
            mime="text/csv",
            use_container_width=True,
        )

    with export_pdf:
        try:
            pdf_data = create_pdf_report(
                df=df,
                malicious_count=malicious_count,
                suspicious_count=suspicious_count,
                clean_count=clean_count,
                error_count=error_count,
            )

            st.download_button(
                label="Download PDF Report",
                data=pdf_data,
                file_name="SOC_Incident_Report.pdf",
                mime="application/pdf",
                use_container_width=True,
            )

        except Exception as error:
            st.error(f"Gagal membuat PDF: {error}")


def main() -> None:
    st.title("🛡️ SOC Analyst Toolkit")
    st.markdown("Incident Response Dashboard for IOC Reputation, Bulk Analysis, and Reporting")

    render_sidebar()

    tab_ip, tab_hash, tab_bulk = st.tabs(
        [
            "🌐 Single IP",
            "🦠 Single Hash",
            "📊 Bulk Reporting",
        ]
    )

    with tab_ip:
        render_single_ip_tab()

    with tab_hash:
        render_single_hash_tab()

    with tab_bulk:
        render_bulk_tab()


if __name__ == "__main__":
    main()
