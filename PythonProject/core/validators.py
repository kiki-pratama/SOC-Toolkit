import ipaddress
import re


def validate_public_ip(ip_text: str) -> tuple[bool, str, str]:
    ip_text = ip_text.strip()

    if not ip_text:
        return False, "", "IP kosong."

    try:
        ip_obj = ipaddress.ip_address(ip_text)
    except ValueError:
        return False, ip_text, "Format IP tidak valid."

    if not ip_obj.is_global:
        return False, str(ip_obj), "IP bukan public routable IP."

    return True, str(ip_obj), ""


def validate_hash(hash_text: str) -> tuple[bool, str, str]:
    normalized_hash = hash_text.strip().lower()

    hash_patterns = {
        "MD5": r"^[a-f0-9]{32}$",
        "SHA1": r"^[a-f0-9]{40}$",
        "SHA256": r"^[a-f0-9]{64}$",
    }

    for hash_type, pattern in hash_patterns.items():
        if re.fullmatch(pattern, normalized_hash):
            return True, normalized_hash, hash_type

    return False, normalized_hash, "Format hash tidak valid. Gunakan MD5, SHA1, atau SHA256."


def parse_bulk_ips(raw_text: str) -> tuple[list[dict], int]:
    rows = []
    seen_ips = set()
    duplicate_count = 0

    for line in raw_text.splitlines():
        raw_ip = line.strip()

        if not raw_ip:
            continue

        is_valid, normalized_ip, error_message = validate_public_ip(raw_ip)

        if not is_valid:
            rows.append(
                {
                    "ip": raw_ip,
                    "valid": False,
                    "error": error_message,
                }
            )
            continue

        if normalized_ip in seen_ips:
            duplicate_count += 1
            continue

        seen_ips.add(normalized_ip)

        rows.append(
            {
                "ip": normalized_ip,
                "valid": True,
                "error": "",
            }
        )

    return rows, duplicate_count
