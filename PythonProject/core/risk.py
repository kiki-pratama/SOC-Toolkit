def get_category(score: int) -> str:
    if score >= 50:
        return "Malicious"

    if score > 0:
        return "Suspicious"

    return "Clean"


def get_severity(score: int, reports: int) -> str:
    if score >= 75 or reports >= 50:
        return "High"

    if score >= 50:
        return "Medium"

    if score > 0:
        return "Low"

    return "Informational"


def get_recommendation(category: str) -> str:
    recommendations = {
        "Malicious": (
            "Block IP, correlate with SIEM logs, check affected hosts, "
            "and escalate if confirmed."
        ),
        "Suspicious": (
            "Monitor, enrich with proxy/firewall/DNS/authentication logs, "
            "and review related activity."
        ),
        "Clean": (
            "No immediate action. Keep as context and correlate with internal telemetry."
        ),
        "Invalid": "Fix IOC format before investigation.",
        "Error": "Manual review required. API request failed.",
    }

    return recommendations.get(category, "Manual review required.")
