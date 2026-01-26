# 🛡️ SOC Analyst Toolkit (v3.0 Pro)

**Internal Tool for Incident Response & Threat Hunting** *Developed by: SOC L2 Team*

Aplikasi ini adalah dashboard investigasi keamanan siber berbasis Python yang dirancang untuk mempercepat proses triase (triage) insiden. Mengintegrasikan Threat Intelligence dari **AbuseIPDB** dan **VirusTotal** untuk analisis otomatis.

---

## 🚀 Fitur Utama

* **🌐 Single IP Scanner**: Cek reputasi IP, ISP, dan Negara secara instan.
* **🦠 Malware Hash Checker**: Verifikasi file berbahaya menggunakan database VirusTotal (MD5/SHA1/SHA256).
* **📊 Bulk Analyzer**: Analisis massal log firewall (copy-paste list IP) dengan visualisasi grafik.
* **⚡ Smart Caching**: Menyimpan hasil scan di memori selama 1 jam untuk menghemat kuota API dan mempercepat loading.
* **📄 Automated Reporting**: Generate laporan PDF resmi ("SOC Incident Report") dan export CSV untuk keperluan audit/manajemen.

---

## 🛠️ Prasyarat (Requirements)

Pastikan komputer sudah terinstal:
* **Python 3.8+**
* Koneksi Internet (untuk akses API)

---

## 📥 Instalasi

1.  **Siapkan Project**
    Pastikan semua file (`app.py`, `README.md`) berada dalam satu folder.

2.  **Install Library**
    Buka terminal/CMD di folder project, lalu jalankan perintah berikut untuk menginstal dependensi:
    
    ```bash
    py -m pip install streamlit pandas requests fpdf
    ```
    *(Atau jika menggunakan requirements.txt: `py -m pip install -r requirements.txt`)*

3.  **Konfigurasi API Key**
    Buka file `app.py` menggunakan Text Editor atau PyCharm. Edit bagian atas file:

    ```python
    # Masukkan API Key asli Anda di sini
    ABUSEIPDB_API_KEY = 'MASUKKAN_KEY_ABUSEIPDB_DISINI'
    VIRUSTOTAL_API_KEY = 'MASUKKAN_KEY_VIRUSTOTAL_DISINI'
    ```
    *Note: API Key bisa didapatkan gratis di website AbuseIPDB dan VirusTotal.*

---

## 🖥️ Cara Menjalankan

Untuk memulai aplikasi, jalankan perintah berikut di terminal:

```bash

py -m streamlit run app.py
