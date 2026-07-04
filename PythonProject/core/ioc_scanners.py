from datetime import datetime

import streamlit as st

from core.api import check_domain_virustotal, check_url_virustotal
from core.validators import validate_domain, validate_url


def get_vt_counts(attributes: dict) -> dict:
    stats = attributes.get("last_analysis_stats", {})

    return {
        "malicious": int(stats.get("malicious", 0) or 0),
        "suspicious": int(stats.get("suspicious", 0) or 0),
        "harmless": int(stats.get("harmless", 0) or 0),
        "undetected": int(stats.get("undetected", 0) or 0),
        "timeout": int(stats.get("timeout", 0) or 0),
    }


def get_vt_category(counts: dict) -> str:
    if counts["malicious"] > 0:
        return "Malicious"

    if counts["suspicious"] > 0:
        return "Suspicious"

    return "Clean"


def get_vt_severity(counts: dict) -> str:
    if counts["malicious"] >= 5:
        return "High"

    if counts["malicious"] > 0:
        return "Medium"

    if counts["suspicious"] > 0:
        return "Low"

    return "Informational"


def get_vt_recommendation(category: str, ioc_type: str) -> str:
    if category == "Malicious":
        return (
            f"Treat this {ioc_type} as malicious. Correlate with proxy, DNS, EDR, "
            "email gateway, and firewall logs before containment."
        )

    if category == "Suspicious":
        return (
            f"Review this {ioc_type} manually. Check related DNS, proxy, browser, "
            "and endpoint telemetry before blocking."
        )

    return (
        f"No immediate blocking required for this {ioc_type}. Keep as context "
        "and validate with internal telemetry."
    )


def render_vt_verdict(category: str, severity: str, counts: dict) -> None:
    message = (
        f"{category.upper()} | Severity: {severity} | "
        f"Malicious: {counts['malicious']} | Suspicious: {counts['suspicious']}"
    )

    if category == "Malicious":
        st.error(f"🚨 {message}")
    elif category == "Suspicious":
        st.warning(f"⚠️ {message}")
    else:
        st.success(f"✅ {message}")


def render_vt_metrics(attributes: dict, counts: dict) -> None:
    reputation = int(attributes.get("reputation", 0) or 0)

    col1, col2, col3, col4, col5 = st.columns(5)

    col1.metric("Malicious", counts["malicious"])
    col2.metric("Suspicious", counts["suspicious"])
    col3.metric("Harmless", counts["harmless"])
    col4.metric("Undetected", counts["undetected"])
    col5.metric("Reputation", reputation)


def render_categories(attributes: dict) -> None:
    categories = attributes.get("categories", {})

    if not categories:
        return

    with st.expander("Vendor Categories"):
        st.json(categories)


def render_domain_metadata(domain: str, attributes: dict) -> None:
    registrar = attributes.get("registrar", "-")
    reputation = attributes.get("reputation", "-")
    last_dns_records = attributes.get("last_dns_records", [])

    col1, col2, col3 = st.columns(3)

    col1.metric("Domain", domain)
    col2.metric("Registrar", registrar)
    col3.metric("Reputation", reputation)

    if last_dns_records:
        with st.expander("Last DNS Records"):
            st.json(last_dns_records[:10])


def render_url_metadata(url_value: str, attributes: dict) -> None:
    final_url = attributes.get("last_final_url", url_value)
    title = attributes.get("title", "-")
    reputation = attributes.get("reputation", "-")

    st.code(final_url, language="text")

    col1, col2 = st.columns(2)

    col1.metric("Title", title)
    col2.metric("Reputation", reputation)


def render_raw_vt_response(attributes: dict) -> None:
    with st.expander("Raw VirusTotal Attributes"):
        st.json(attributes)


def render_domain_tab(api_key: str) -> None:
    st.header("Domain Reputation Scanner")

    domain_input = st.text_input(
        "Domain",
        placeholder="example.com",
        help="Mendukung domain normal dan defanged domain seperti example[.]com.",
    )

    if not st.button("Scan Domain", use_container_width=True, key="scan_domain"):
        return

    is_valid, normalized_domain, error_message = validate_domain(domain_input)

    if not is_valid:
        st.warning(error_message)
        return

    with st.spinner("Checking domain reputation in VirusTotal..."):
        result = check_domain_virustotal(
            domain=normalized_domain,
            api_key=api_key,
        )

    if not result["ok"]:
        st.error(result["error"])
        return

    attributes = result["data"]

    if attributes.get("not_found"):
        st.warning("Domain tidak ditemukan di VirusTotal.")
        return

    counts = get_vt_counts(attributes)
    category = get_vt_category(counts)
    severity = get_vt_severity(counts)

    render_vt_verdict(category, severity, counts)
    render_vt_metrics(attributes, counts)

    st.subheader("Domain Metadata")
    render_domain_metadata(normalized_domain, attributes)

    st.subheader("Recommended Action")
    st.info(get_vt_recommendation(category, "domain"))

    st.caption(
        f"Scan time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | "
        "Validate external reputation with internal DNS, proxy, and endpoint logs."
    )

    render_categories(attributes)
    render_raw_vt_response(attributes)


def render_url_tab(api_key: str) -> None:
    st.header("URL Reputation Scanner")

    url_input = st.text_input(
        "URL",
        placeholder="https://example.com/login",
        help="Mendukung URL normal dan defanged URL seperti hxxps://example[.]com/login.",
    )

    if not st.button("Scan URL", use_container_width=True, key="scan_url"):
        return

    is_valid, normalized_url, error_message = validate_url(url_input)

    if not is_valid:
        st.warning(error_message)
        return

    with st.spinner("Checking URL reputation in VirusTotal..."):
        result = check_url_virustotal(
            url_value=normalized_url,
            api_key=api_key,
        )

    if not result["ok"]:
        st.error(result["error"])
        return

    attributes = result["data"]

    if attributes.get("not_found"):
        st.warning(
            "URL tidak ditemukan di VirusTotal. "
            "Jika ingin melakukan submit URL baru untuk analysis, fitur submit bisa ditambahkan di versi berikutnya."
        )
        return

    counts = get_vt_counts(attributes)
    category = get_vt_category(counts)
    severity = get_vt_severity(counts)

    render_vt_verdict(category, severity, counts)
    render_vt_metrics(attributes, counts)

    st.subheader("URL Metadata")
    render_url_metadata(normalized_url, attributes)

    st.subheader("Recommended Action")
    st.info(get_vt_recommendation(category, "URL"))

    st.caption(
        f"Scan time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | "
        "Validate external reputation with proxy, browser, DNS, email, and EDR telemetry."
    )

    render_categories(attributes)
    render_raw_vt_response(attributes)
