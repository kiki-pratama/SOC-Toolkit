import streamlit as st


APP_CONFIG = {
    "page_title": "SOC L2 Dashboard",
    "page_icon": "🛡️",
    "cache_ttl": 3600,
    "request_timeout": 15,
    "max_bulk_ips": 50,
}


def load_secret(key_name: str) -> str:
    try:
        return st.secrets[key_name]
    except FileNotFoundError:
        st.error("File `.streamlit/secrets.toml` tidak ditemukan.")
        st.stop()
    except KeyError:
        st.error(f"Secret `{key_name}` belum dikonfigurasi.")
        st.stop()


def load_api_keys() -> tuple[str, str]:
    abuseipdb_api_key = load_secret("ABUSEIPDB_API_KEY")
    virustotal_api_key = load_secret("VIRUSTOTAL_API_KEY")

    return abuseipdb_api_key, virustotal_api_key
