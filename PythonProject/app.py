import streamlit as st
import requests
import pandas as pd
import time
from datetime import datetime
from fpdf import FPDF

import streamlit as st

# --- KONFIGURASI API KEY (SECURE) ---
# Kode ini akan mencari key di file secrets.toml (di laptop) 
# ATAU di menu Secrets (kalau nanti di-upload ke Cloud)

try:
    ABUSEIPDB_API_KEY = st.secrets["ABUSEIPDB_API_KEY"]
    VIRUSTOTAL_API_KEY = st.secrets["VIRUSTOTAL_API_KEY"]
except FileNotFoundError:
    st.error("File .streamlit/secrets.toml tidak ditemukan! Buat file tersebut untuk menyimpan API Key.")
    st.stop()


# --- CLASS PDF GENERATOR ---
class PDF(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 15)
        self.cell(0, 10, 'SOC Incident Report', 0, 1, 'C')
        self.set_font('Arial', 'I', 10)
        self.cell(0, 10, f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', 0, 1, 'C')
        self.ln(5)

    def chapter_title(self, title):
        self.set_font('Arial', 'B', 12)
        self.set_fill_color(200, 220, 255)
        self.cell(0, 10, title, 0, 1, 'L', 1)
        self.ln(4)

    def chapter_body(self, body):
        self.set_font('Arial', '', 10)
        self.multi_cell(0, 10, body)
        self.ln()


# --- FUNGSI HELPER DENGAN CACHING (HEMAT KUOTA) ---
# TTL=3600 artinya data disimpan selama 1 jam. Jika scan IP sama dlm 1 jam, API tidak dipanggil.
@st.cache_data(ttl=3600, show_spinner=False)
def check_ip_abuseipdb(ip_address):
    url = 'https://api.abuseipdb.com/api/v2/check'
    querystring = {'ipAddress': ip_address.strip(), 'maxAgeInDays': '90'}
    headers = {'Accept': 'application/json', 'Key': ABUSEIPDB_API_KEY}
    try:
        response = requests.get(url, headers=headers, params=querystring)
        if response.status_code == 200:
            return response.json()['data']
        return None
    except:
        return None


@st.cache_data(ttl=3600, show_spinner=False)
def check_hash_virustotal(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash.strip()}"
    headers = {"accept": "application/json", "x-apikey": VIRUSTOTAL_API_KEY}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()['data']['attributes']
        elif response.status_code == 404:
            return {"not_found": True}
        return {"error": f"Error {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def get_risk_category(score):
    if score >= 50:
        return "Malicious"
    elif score > 0:
        return "Suspicious"
    return "Clean"


def create_pdf(dataframe, mal, susp, clean):
    pdf = PDF()
    pdf.add_page()

    # Executive Summary
    pdf.chapter_title("Executive Summary")
    summary_text = (f"Total Targets Scanned: {len(dataframe)}\n"
                    f"Malicious IPs: {mal}\n"
                    f"Suspicious IPs: {susp}\n"
                    f"Clean IPs: {clean}")
    pdf.chapter_body(summary_text)

    # Detailed Table
    pdf.chapter_title("Detailed Investigation Log")
    pdf.set_font('Arial', 'B', 9)

    # Table Header
    col_width = [40, 20, 30, 60, 15]  # Lebar kolom
    headers = ['IP Address', 'Score', 'Category', 'ISP', 'CC']

    for i in range(len(headers)):
        pdf.cell(col_width[i], 10, headers[i], 1, 0, 'C')
    pdf.ln()

    # Table Content
    pdf.set_font('Arial', '', 8)
    for index, row in dataframe.iterrows():
        # Truncate ISP name if too long
        isp = (row['ISP'][:25] + '..') if len(str(row['ISP'])) > 25 else str(row['ISP'])

        pdf.cell(col_width[0], 10, str(row['IP']), 1)
        pdf.cell(col_width[1], 10, str(row['Risk Score']), 1, 0, 'C')
        pdf.cell(col_width[2], 10, str(row['Category']), 1, 0, 'C')
        pdf.cell(col_width[3], 10, isp, 1)
        pdf.cell(col_width[4], 10, str(row['Country']), 1, 0, 'C')
        pdf.ln()

    return pdf.output(dest='S').encode('latin-1')


# --- UI UTAMA ---
st.set_page_config(page_title="SOC L2 Dashboard", page_icon="🛡️", layout="wide")

st.title("🛡️ SOC Analyst Toolkit (Pro Version)")
st.markdown("Incident Response Dashboard")

tab1, tab2, tab3 = st.tabs(["🌐 Single IP", "🦠 Single Hash", "📊 Reporting"])

# === TAB 1: SINGLE IP ===
with tab1:
    st.header("Single IP Investigation")
    ip_input = st.text_input("IP Address:", placeholder="Ex: 118.99.x.x", key="ip_s")
    if st.button("Scan IP", key="btn_ip"):
        if ip_input:
            with st.spinner('Checking (Cached)...'):
                data = check_ip_abuseipdb(ip_input)
            if data:
                score = data['abuseConfidenceScore']
                if score >= 50:
                    st.error(f"🚨 MALICIOUS! Score: {score}%")
                elif score > 0:
                    st.warning(f"⚠️ SUSPICIOUS. Score: {score}%")
                else:
                    st.success(f"✅ CLEAN. Score: {score}%")

                c1, c2, c3 = st.columns(3)
                c1.metric("ISP", data.get('isp', '-'))
                c2.metric("Country", data.get('countryCode', '-'))
                c3.metric("Reports", data.get('totalReports', 0))
                st.json(data)

# === TAB 2: SINGLE HASH ===
with tab2:
    st.header("Malware Hash Check")
    hash_input = st.text_input("File Hash:", placeholder="MD5/SHA1/SHA256", key="hash_s")
    if st.button("Scan Hash", key="btn_hash"):
        if hash_input:
            with st.spinner('Checking VT (Cached)...'):
                res = check_hash_virustotal(hash_input)
            if "last_analysis_stats" in res:
                stats = res['last_analysis_stats']
                mal = stats['malicious']
                if mal > 0:
                    st.error(f"🚨 DETECTED! {mal} Engines.")
                else:
                    st.success("✅ CLEAN.")
                st.json(stats)
            elif "not_found" in res:
                st.warning("Hash not found.")
            else:
                st.error("API Error.")

# === TAB 3: BULK SCAN DASHBOARD ===
with tab3:
    st.header("🚀 Bulk Analyzer & Reporting")

    col_input, col_result = st.columns([1, 2])

    with col_input:
        bulk_input = st.text_area("Input IP List (One per line):", height=300,
                                  placeholder="192.168.1.1\n8.8.8.8\n...")
        scan_btn = st.button("🚀 Analyze & Generate Report", use_container_width=True)

    if scan_btn and bulk_input:
        ip_list = [x.strip() for x in bulk_input.split('\n') if x.strip()]

        if len(ip_list) > 0:
            results = []
            progress = st.progress(0)
            status = st.empty()

            for i, ip in enumerate(ip_list):
                status.write(f"Scanning {i + 1}/{len(ip_list)}: `{ip}`...")
                data = check_ip_abuseipdb(ip)

                if data:
                    score = data['abuseConfidenceScore']
                    results.append({
                        "IP": ip,
                        "Risk Score": score,
                        "Category": get_risk_category(score),
                        "ISP": data['isp'],
                        "Country": data['countryCode'],
                        "Reports": data['totalReports']
                    })
                else:
                    results.append(
                        {"IP": ip, "Risk Score": -1, "Category": "Error", "ISP": "-", "Country": "-", "Reports": 0})

                progress.progress((i + 1) / len(ip_list))
                # Tidak perlu time.sleep lama-lama karena ada caching
                if i % 5 == 0: time.sleep(0.1)

            status.empty()
            progress.empty()

            # --- DASHBOARD ---
            df = pd.DataFrame(results)

            st.divider()
            malicious_count = len(df[df['Category'] == 'Malicious'])
            suspicious_count = len(df[df['Category'] == 'Suspicious'])
            clean_count = len(df[df['Category'] == 'Clean'])

            m1, m2, m3, m4 = st.columns(4)
            m1.metric("Total Targets", len(df))
            m2.metric("🚨 Malicious", malicious_count)
            m3.metric("⚠️ Suspicious", suspicious_count)
            m4.metric("✅ Clean", clean_count)

            # Chart
            c1, c2 = st.columns(2)
            with c1:
                st.caption("Risk Distribution")
                st.bar_chart(df['Category'].value_counts(), color=["#ff4b4b"])
            with c2:
                st.caption("Country Origin")
                st.bar_chart(df['Country'].value_counts())

            # Data Table
            st.subheader("📋 Log Data")


            def highlight_risk(val):
                color = '#ff4b4b' if val == 'Malicious' else '#ffa500' if val == 'Suspicious' else '#90ee90'
                return f'background-color: {color}; color: black'


            try:
                st.dataframe(
                    df.style.applymap(lambda x: highlight_risk(x) if x in ['Malicious', 'Suspicious', 'Clean'] else '',
                                      subset=['Category']), use_container_width=True)
            except:
                st.dataframe(df, use_container_width=True)

            # --- EXPORT SECTION ---
            st.divider()
            st.subheader("🖨️ Export Report")

            col_pdf, col_csv = st.columns(2)

            with col_csv:
                # CSV Download
                csv = df.to_csv(index=False).encode('utf-8')
                st.download_button(
                    label="📥 Download CSV (Raw Data)",
                    data=csv,
                    file_name="scan_results.csv",
                    mime="text/csv",
                    use_container_width=True
                )

            with col_pdf:
                # PDF Generation
                try:
                    pdf_bytes = create_pdf(df, malicious_count, suspicious_count, clean_count)
                    st.download_button(
                        label="📄 Download PDF (Official Report)",
                        data=pdf_bytes,
                        file_name="SOC_Incident_Report.pdf",
                        mime="application/pdf",
                        use_container_width=True
                    )
                except Exception as e:
                    st.error(f"Gagal membuat PDF: {e}")

        else:

            st.warning("List IP kosong.")
