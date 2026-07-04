from datetime import datetime
from typing import Dict, List, Optional, Tuple

import pandas as pd
import streamlit as st

from core.api import check_ip_abuseipdb
from core.charts import (
    render_country_origin_chart,
    render_risk_distribution_chart,
    render_top_isp_chart,
)
from core.config import APP_CONFIG
from core.report import create_pdf_report
from core.risk import get_category, get_recommendation, get_severity
from core.validators import parse_bulk_ips


CATEGORY_ORDER = [
    "Malicious",
    "Suspicious",
    "Clean",
    "Invalid",
    "Error",
]

SEVERITY_ORDER = [
    "High",
    "Medium",
    "Low",
    "Informational",
    "-",
]


def build_success_row(
    ip_address: str,
    data: dict,
    thresholds: dict,
) -> dict:
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
    styles = {
        "Malicious": "background-color: #ef4444; color: black",
        "Suspicious": "background-color: #facc15; color: black",
        "Clean": "background-color: #22c55e; color: black",
        "Invalid": "background-color: #9ca3af; color: black",
        "Error": "background-color: #6b7280; color: white",
    }

    return styles.get(value, "")


def style_severity(value: str) -> str:
    styles = {
        "High": "background-color: #991b1b; color: white",
        "Medium": "background-color: #b45309; color: white",
        "Low": "background-color: #1d4ed8; color: white",
        "Informational": "background-color: #166534; color: white",
    }

    return styles.get(value, "")


def sort_dataframe_by_risk(df: pd.DataFrame) -> pd.DataFrame:
    category_rank = {
        "Malicious": 1,
        "Suspicious": 2,
        "Clean": 3,
        "Invalid": 4,
        "Error": 5,
    }

    severity_rank = {
        "High": 1,
        "Medium": 2,
        "Low": 3,
        "Informational": 4,
        "-": 5,
    }

    result = df.copy()

    result["_category_rank"] = result["Category"].map(category_rank).fillna(99)
    result["_severity_rank"] = result["Severity"].map(severity_rank).fillna(99)

    result["_risk_score_sort"] = pd.to_numeric(
        result["Risk Score"],
        errors="coerce",
    ).fillna(-1)

    result["_reports_sort"] = pd.to_numeric(
        result["Reports"],
        errors="coerce",
    ).fillna(0)

    result = result.sort_values(
        by=[
            "_category_rank",
            "_severity_rank",
            "_risk_score_sort",
            "_reports_sort",
        ],
        ascending=[
            True,
            True,
            False,
            False,
        ],
    )

    return result.drop(
        columns=[
            "_category_rank",
            "_severity_rank",
            "_risk_score_sort",
            "_reports_sort",
        ],
    ).reset_index(drop=True)


def apply_thresholds(df: pd.DataFrame, thresholds: dict) -> pd.DataFrame:
    result = df.copy()

    risk_scores = pd.to_numeric(
        result["Risk Score"],
        errors="coerce",
    )

    reports = pd.to_numeric(
        result["Reports"],
        errors="coerce",
    ).fillna(0)

    valid_rows = ~result["Category"].isin(["Invalid", "Error"])

    for index in result[valid_rows].index:
        score = int(risk_scores.loc[index])
        report_count = int(reports.loc[index])

        category = get_category(
            score=score,
            malicious_threshold=thresholds["malicious_threshold"],
        )

        severity = get_severity(
            score=score,
            reports=report_count,
            high_severity_threshold=thresholds["high_severity_threshold"],
        )

        result.loc[index, "Category"] = category
        result.loc[index, "Severity"] = severity
        result.loc[index, "Recommended Action"] = get_recommendation(category)

    return result


def ordered_options(values: List[str], preferred_order: Optional[List[str]] = None) -> List[str]:
    cleaned_values = []

    for value in values:
        text = str(value).strip()

        if text in ["", "None", "nan"]:
            continue

        cleaned_values.append(text)

    unique_values = list(dict.fromkeys(cleaned_values))

    if preferred_order is None:
        return sorted(unique_values)

    ordered = [item for item in preferred_order if item in unique_values]
    remaining = sorted([item for item in unique_values if item not in preferred_order])

    return ordered + remaining


def render_filters(df: pd.DataFrame) -> pd.DataFrame:
    st.subheader("Filters")

    col1, col2, col3 = st.columns(3)

    category_options = ordered_options(
        values=df["Category"].tolist(),
        preferred_order=CATEGORY_ORDER,
    )

    severity_options = ordered_options(
        values=df["Severity"].tolist(),
        preferred_order=SEVERITY_ORDER,
    )

    country_options = ordered_options(
        values=df["Country"].tolist(),
    )

    with col1:
        selected_categories = st.multiselect(
            "Category",
            options=category_options,
            default=category_options,
            key="bulk_filter_category",
        )

    with col2:
        selected_severities = st.multiselect(
            "Severity",
            options=severity_options,
            default=severity_options,
            key="bulk_filter_severity",
        )

    with col3:
        selected_countries = st.multiselect(
            "Country",
            options=country_options,
            default=country_options,
            key="bulk_filter_country",
        )

    filtered_df = df[
        df["Category"].astype(str).isin(selected_categories)
        & df["Severity"].astype(str).isin(selected_severities)
        & df["Country"].astype(str).isin(selected_countries)
    ]

    return sort_dataframe_by_risk(filtered_df)


def get_counts(df: pd.DataFrame) -> Dict[str, int]:
    return {
        "total": len(df),
        "malicious": len(df[df["Category"] == "Malicious"]),
        "suspicious": len(df[df["Category"] == "Suspicious"]),
        "clean": len(df[df["Category"] == "Clean"]),
        "error": len(df[df["Category"].isin(["Invalid", "Error"])]),
    }


def get_overall_verdict(counts: Dict[str, int]) -> Tuple[str, str]:
    total = counts["total"]

    if total == 0:
        return "Unknown", "No IOC data available."

    malicious_ratio = counts["malicious"] / total
    suspicious_ratio = counts["suspicious"] / total

    if malicious_ratio >= 0.5:
        return (
            "High Risk",
            "Majority of IOCs are malicious. Prioritize containment, SIEM correlation, and host impact review.",
        )

    if counts["malicious"] > 0 or suspicious_ratio >= 0.3:
        return (
            "Medium Risk",
            "Some IOCs require review. Correlate with firewall, proxy, DNS, EDR, and authentication logs.",
        )

    return (
        "Low Risk",
        "No major external reputation risk detected. Keep the IOCs as context for correlation.",
    )


def get_top_value(df: pd.DataFrame, column: str) -> str:
    values = (
        df[column]
        .fillna("-")
        .astype(str)
        .str.strip()
    )

    values = values[~values.isin(["-", "", "None", "nan"])]

    if values.empty:
        return "-"

    return values.value_counts().idxmax()


def render_metrics(counts: Dict[str, int]) -> None:
    col1, col2, col3, col4, col5 = st.columns(5)

    col1.metric("Total Items", counts["total"])
    col2.metric("Malicious", counts["malicious"])
    col3.metric("Suspicious", counts["suspicious"])
    col4.metric("Clean", counts["clean"])
    col5.metric("Invalid/Error", counts["error"])


def render_overall_verdict(counts: Dict[str, int]) -> None:
    verdict, message = get_overall_verdict(counts)

    if verdict == "High Risk":
        st.error(f"Overall Verdict: {verdict} — {message}")
    elif verdict == "Medium Risk":
        st.warning(f"Overall Verdict: {verdict} — {message}")
    elif verdict == "Low Risk":
        st.success(f"Overall Verdict: {verdict} — {message}")
    else:
        st.info(f"Overall Verdict: {verdict} — {message}")


def render_ioc_summary(df: pd.DataFrame, counts: Dict[str, int]) -> None:
    if counts["total"] == 0:
        st.info("IOC Summary: tidak ada data.")
        return

    top_country = get_top_value(df, "Country")
    top_isp = get_top_value(df, "ISP")
    malicious_ratio = counts["malicious"] / counts["total"]

    st.info(
        f"IOC Summary: Top country `{top_country}` | "
        f"Top ISP `{top_isp}` | "
        f"Malicious ratio `{malicious_ratio:.1%}` | "
        f"Suspicious `{counts['suspicious']}` | "
        f"Clean `{counts['clean']}`"
    )


def render_confidence_note() -> None:
    st.caption(
        "Note: External reputation data should be validated with internal telemetry "
        "before containment, blocking, or escalation decisions."
    )


def render_investigation_log(df: pd.DataFrame) -> None:
    st.subheader("Investigation Log")

    try:
        styled_df = (
            df.style
            .map(style_category, subset=["Category"])
            .map(style_severity, subset=["Severity"])
        )

        st.dataframe(
            styled_df,
            use_container_width=True,
            height=420,
        )

    except Exception:
        try:
            styled_df = (
                df.style
                .applymap(style_category, subset=["Category"])
                .applymap(style_severity, subset=["Severity"])
            )

            st.dataframe(
                styled_df,
                use_container_width=True,
                height=420,
            )

        except Exception:
            st.dataframe(
                df,
                use_container_width=True,
                height=420,
            )


def get_malicious_ips(df: pd.DataFrame) -> List[str]:
    return sorted(
        df[df["Category"] == "Malicious"]["IP"]
        .dropna()
        .astype(str)
        .unique()
        .tolist()
    )


def render_blocklist(malicious_ips: List[str]) -> None:
    if not malicious_ips:
        return

    st.subheader("Blocklist Candidate")
    st.caption("Review kembali dengan internal telemetry sebelum blocking production.")
    st.code("\n".join(malicious_ips), language="text")

    st.download_button(
        label="Download Blocklist TXT",
        data="\n".join(malicious_ips).encode("utf-8"),
        file_name="malicious_ip_blocklist.txt",
        mime="text/plain",
        use_container_width=True,
    )


def render_siem_queries(malicious_ips: List[str]) -> None:
    if not malicious_ips:
        return

    quoted_double = ", ".join([f'"{ip}"' for ip in malicious_ips])
    quoted_single = ", ".join([f"'{ip}'" for ip in malicious_ips])

    st.subheader("SIEM Hunting Queries")

    tab_splunk, tab_sentinel, tab_qradar, tab_elastic = st.tabs(
        [
            "Splunk SPL",
            "Sentinel KQL",
            "QRadar AQL",
            "Elastic KQL",
        ]
    )

    with tab_splunk:
        st.code(
            f"""index=*
(src_ip IN ({quoted_double})
OR dest_ip IN ({quoted_double})
OR source_ip IN ({quoted_double})
OR destination_ip IN ({quoted_double})
OR client_ip IN ({quoted_double}))
| stats count by src_ip dest_ip source_ip destination_ip client_ip""",
            language="text",
        )

    with tab_sentinel:
        st.code(
            f"""CommonSecurityLog
| where SourceIP in ({quoted_double})
   or DestinationIP in ({quoted_double})
| summarize EventCount=count() by SourceIP, DestinationIP, DeviceVendor, DeviceProduct""",
            language="text",
        )

    with tab_qradar:
        st.code(
            f"""SELECT sourceip, destinationip, QIDNAME(qid) AS event_name, COUNT(*) AS event_count
FROM events
WHERE sourceip IN ({quoted_single})
OR destinationip IN ({quoted_single})
GROUP BY sourceip, destinationip, qid
LAST 24 HOURS""",
            language="sql",
        )

    with tab_elastic:
        st.code(
            f"""source.ip:({quoted_double}) OR destination.ip:({quoted_double}) OR client.ip:({quoted_double}) OR server.ip:({quoted_double})""",
            language="text",
        )


def render_error_details(df: pd.DataFrame) -> None:
    error_df = df[df["Category"].isin(["Invalid", "Error"])]

    if error_df.empty:
        return

    with st.expander("Invalid/Error Details"):
        st.dataframe(
            error_df[["IP", "Category", "Error"]],
            use_container_width=True,
        )


def render_exports(df: pd.DataFrame, counts: Dict[str, int]) -> None:
    st.divider()
    st.subheader("Export Report")

    col1, col2 = st.columns(2)

    with col1:
        st.download_button(
            label="Download Filtered CSV",
            data=df.to_csv(index=False).encode("utf-8"),
            file_name="soc_scan_results_filtered.csv",
            mime="text/csv",
            use_container_width=True,
        )

    with col2:
        try:
            pdf_data = create_pdf_report(
                df=df,
                malicious_count=counts["malicious"],
                suspicious_count=counts["suspicious"],
                clean_count=counts["clean"],
                error_count=counts["error"],
            )

            st.download_button(
                label="Download Filtered PDF Report",
                data=pdf_data,
                file_name="SOC_Incident_Report_Filtered.pdf",
                mime="application/pdf",
                use_container_width=True,
            )

        except Exception as error:
            st.error(f"Gagal membuat PDF: {error}")


def run_bulk_scan(
    bulk_input: str,
    api_key: str,
    thresholds: dict,
) -> Optional[pd.DataFrame]:
    targets, duplicate_count = parse_bulk_ips(bulk_input)

    if not targets:
        st.warning("List IP kosong.")
        return None

    valid_count = sum(1 for item in targets if item["valid"])

    if valid_count > APP_CONFIG["max_bulk_ips"]:
        st.error(
            f"Terlalu banyak public IP valid. "
            f"Maksimal {APP_CONFIG['max_bulk_ips']} IP per bulk scan."
        )
        return None

    if duplicate_count:
        st.info(f"{duplicate_count} duplicate IP dilewati.")

    results = []
    progress = st.progress(0)
    status = st.empty()

    for index, target in enumerate(targets):
        ip_address = target["ip"]

        if not target["valid"]:
            results.append(
                build_invalid_row(
                    ip_address=ip_address,
                    error_message=target["error"],
                )
            )

            progress.progress((index + 1) / len(targets))
            continue

        status.write(f"Scanning {index + 1}/{len(targets)}: `{ip_address}`")

        result = check_ip_abuseipdb(
            ip_address=ip_address,
            api_key=api_key,
        )

        if result["ok"]:
            results.append(
                build_success_row(
                    ip_address=ip_address,
                    data=result["data"],
                    thresholds=thresholds,
                )
            )
        else:
            results.append(
                build_error_row(
                    ip_address=ip_address,
                    error_message=result["error"],
                )
            )

        progress.progress((index + 1) / len(targets))

    status.empty()
    progress.empty()

    return pd.DataFrame(results)


def render_bulk_dashboard(df: pd.DataFrame) -> None:
    sorted_df = sort_dataframe_by_risk(df)
    filtered_df = render_filters(sorted_df)

    if filtered_df.empty:
        st.warning("Tidak ada data yang cocok dengan filter saat ini.")
        return

    counts = get_counts(filtered_df)

    st.divider()

    render_metrics(counts)
    st.caption(f"Showing {len(filtered_df)} of {len(sorted_df)} scanned items after filters.")

    render_overall_verdict(counts)
    render_ioc_summary(filtered_df, counts)
    render_confidence_note()

    st.divider()

    col1, col2 = st.columns(2)

    with col1:
        render_risk_distribution_chart(filtered_df)

    with col2:
        render_country_origin_chart(filtered_df)

    render_top_isp_chart(filtered_df)

    render_investigation_log(filtered_df)

    malicious_ips = get_malicious_ips(filtered_df)

    render_blocklist(malicious_ips)
    render_siem_queries(malicious_ips)
    render_error_details(filtered_df)
    render_exports(filtered_df, counts)


def render_bulk_tab(api_key: str, thresholds: dict) -> None:
    st.header("Bulk IP Analyzer & Reporting")

    if "bulk_results_df" not in st.session_state:
        st.session_state["bulk_results_df"] = None

    bulk_input = st.text_area(
        "Input IP List",
        height=260,
        placeholder="One public IP per line\n8.8.8.8\n1.1.1.1",
    )

    col1, col2 = st.columns([3, 1])

    with col1:
        scan_bulk = st.button(
            "Analyze & Generate Report",
            use_container_width=True,
            key="scan_bulk",
        )

    with col2:
        clear_results = st.button(
            "Clear Results",
            use_container_width=True,
            key="clear_bulk_results",
        )

    if clear_results:
        st.session_state["bulk_results_df"] = None
        st.info("Bulk results cleared.")
        return

    if scan_bulk:
        scanned_df = run_bulk_scan(
            bulk_input=bulk_input,
            api_key=api_key,
            thresholds=thresholds,
        )

        if scanned_df is not None:
            st.session_state["bulk_results_df"] = scanned_df

    stored_df = st.session_state.get("bulk_results_df")

    if stored_df is None:
        st.info("Masukkan daftar public IP lalu klik Analyze & Generate Report.")
        return

    updated_df = apply_thresholds(
        df=stored_df,
        thresholds=thresholds,
    )

    render_bulk_dashboard(updated_df)
