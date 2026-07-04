from typing import Any, Dict

import requests
import streamlit as st

from core.config import APP_CONFIG


def success(data: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "ok": True,
        "data": data,
        "error": "",
    }


def failure(message: str) -> Dict[str, Any]:
    return {
        "ok": False,
        "data": {},
        "error": message,
    }


@st.cache_data(ttl=APP_CONFIG["cache_ttl"], show_spinner=False)
def check_ip_abuseipdb(ip_address: str, api_key: str) -> Dict[str, Any]:
    url = "https://api.abuseipdb.com/api/v2/check"

    headers = {
        "Accept": "application/json",
        "Key": api_key,
    }

    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": "90",
    }

    try:
        response = requests.get(
            url,
            headers=headers,
            params=params,
            timeout=APP_CONFIG["request_timeout"],
        )

        if response.status_code == 200:
            return success(response.json().get("data", {}))

        if response.status_code == 401:
            return failure("Unauthorized. Cek API key AbuseIPDB.")

        if response.status_code == 429:
            return failure("Rate limit AbuseIPDB tercapai.")

        if response.status_code == 422:
            return failure("Request AbuseIPDB tidak valid.")

        return failure(f"AbuseIPDB error HTTP {response.status_code}.")

    except requests.exceptions.Timeout:
        return failure("Request timeout ke AbuseIPDB.")

    except requests.exceptions.RequestException as error:
        return failure(f"Request error ke AbuseIPDB: {error}")


@st.cache_data(ttl=APP_CONFIG["cache_ttl"], show_spinner=False)
def check_hash_virustotal(file_hash: str, api_key: str) -> Dict[str, Any]:
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"

    headers = {
        "accept": "application/json",
        "x-apikey": api_key,
    }

    try:
        response = requests.get(
            url,
            headers=headers,
            timeout=APP_CONFIG["request_timeout"],
        )

        if response.status_code == 200:
            attributes = response.json().get("data", {}).get("attributes", {})
            return success(attributes)

        if response.status_code == 404:
            return success({"not_found": True})

        if response.status_code == 401:
            return failure("Unauthorized. Cek API key VirusTotal.")

        if response.status_code == 429:
            return failure("Rate limit VirusTotal tercapai.")

        return failure(f"VirusTotal error HTTP {response.status_code}.")

    except requests.exceptions.Timeout:
        return failure("Request timeout ke VirusTotal.")

    except requests.exceptions.RequestException as error:
        return failure(f"Request error ke VirusTotal: {error}")
