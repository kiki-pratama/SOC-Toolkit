# 🛡️ SOC Analyst Toolkit (v2.0 Pro)

**Internal Tool for Incident Response, IOC Enrichment & Threat Hunting**  
**Developed by: kiki**

SOC Analyst Toolkit adalah dashboard investigasi keamanan siber berbasis **Python + Streamlit** yang dirancang untuk mempercepat proses triage insiden, IOC enrichment, dan threat hunting.

Aplikasi ini mengintegrasikan threat intelligence dari **AbuseIPDB** dan **VirusTotal** untuk membantu analyst melakukan pengecekan reputasi IP, analisis hash malware, bulk IOC analysis, visualisasi risiko, pembuatan report, serta generator query SIEM.

---

## 🚀 Fitur Utama

### 🌐 Single IP Scanner
Melakukan pengecekan reputasi IP menggunakan AbuseIPDB.

Fitur:
- Abuse confidence score
- ISP / Provider
- Country origin
- Usage type
- Total reports
- Category: `Clean`, `Suspicious`, `Malicious`
- Severity: `Informational`, `Low`, `Medium`, `High`
- Recommended action untuk SOC analyst

---

### 🦠 Malware Hash Checker
Melakukan pengecekan file hash menggunakan VirusTotal.

Mendukung format:
- MD5
- SHA1
- SHA256

Output:
- Malicious detection count
- Suspicious detection count
- Harmless count
- Undetected count
- Raw VirusTotal analysis data

---

### 📊 Bulk IP Analyzer
Melakukan analisis massal daftar IP address dengan input copy-paste.

Fitur:
- Bulk scan public IP
- Validasi IP otomatis
- Private / reserved / invalid IP tidak dikirim ke AbuseIPDB
- Duplicate IP otomatis dilewati
- Batas maksimal bulk scan untuk menjaga kuota API
- Progress indicator saat scanning
- Session state agar hasil tidak hilang saat filter digunakan

---

### 🎯 Risk-Based Dashboard
Dashboard otomatis mengelompokkan hasil berdasarkan risiko.

Output utama:
- Total Items
- Malicious count
- Suspicious count
- Clean count
- Invalid/Error count
- Overall Risk Verdict
- IOC Summary
- Top country
- Top ISP / Provider
- Malicious ratio

---

### 📈 Visualisasi Dark Theme Friendly
Dashboard menggunakan chart berbasis Altair dengan warna custom.

Visualisasi:
- **Risk Distribution**
  - Malicious: merah
  - Suspicious: kuning
  - Clean: hijau
  - Invalid/Error: abu-abu
- **Country Origin**
  - Horizontal bar chart
  - Warna cyan/biru agar cocok dengan dark theme
- **Top ISP / Provider**
  - Menampilkan provider atau ISP terbanyak dari IOC

---

### 🔎 Investigation Log
Tabel hasil investigasi otomatis diurutkan berdasarkan risiko.

Urutan prioritas:
1. Malicious
2. Suspicious
3. Clean
4. Invalid
5. Error

Sorting mempertimbangkan:
- Category
- Severity
- Risk Score
- Total Reports

Tabel juga dilengkapi warna pada:
- Category
- Severity

---

### 🧰 Filter Investigation
Dashboard mendukung filtering interaktif berdasarkan:

- Category
- Severity
- Country

Filter ini membantu analyst fokus pada IOC tertentu tanpa perlu melakukan scan ulang.

---

### 🚫 Blocklist Candidate
Jika ditemukan IP malicious, aplikasi otomatis membuat daftar blocklist candidate.

Fitur:
- Copy-paste malicious IP list
- Download blocklist dalam format `.txt`
- Catatan validasi agar analyst tetap melakukan korelasi dengan telemetry internal sebelum blocking

---

### 🧪 SIEM Hunting Query Generator
Aplikasi otomatis membuat query hunting untuk IP malicious.

Mendukung format:

- Splunk SPL
- Microsoft Sentinel KQL
- QRadar AQL
- Elastic KQL

Contoh use case:
- Correlation dengan firewall log
- Proxy log
- DNS log
- EDR telemetry
- Authentication log

---

### 📄 Automated Reporting
Aplikasi dapat menghasilkan report untuk dokumentasi incident response.

Export yang tersedia:
- CSV
- PDF SOC Incident Report
- Filtered CSV
- Filtered PDF Report
- Malicious IP blocklist `.txt`

---

### ⚡ Smart Caching
Hasil scan disimpan sementara menggunakan Streamlit cache.

Default:
- Cache TTL: 1 jam

Manfaat:
- Menghemat kuota API
- Mempercepat scan ulang IOC yang sama
- Mengurangi request berulang ke AbuseIPDB dan VirusTotal

---

### ⚙️ Adjustable Risk Threshold
Threshold risiko dapat disesuaikan melalui sidebar.

Setting:
- Malicious Threshold
- High Severity Threshold

Default:
- Malicious Threshold: `50`
- High Severity Threshold: `75`

---

## 🧱 Struktur Project

```text
PythonProject/
├── app.py
├── requirements.txt
├── runtime.txt
├── README.md
├── .gitignore
├── .streamlit/
│   └── secrets.toml
└── core/
    ├── __init__.py
    ├── api.py
    ├── charts.py
    ├── config.py
    ├── dashboard.py
    ├── report.py
    ├── risk.py
    └── validators.py
