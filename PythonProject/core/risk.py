def get_category(score: int, malicious_threshold: int = 50) -> str:
    if score >= malicious_threshold:
        return "Malicious"

    if score > 0:
        return "Suspicious"

    return "Clean"


def get_severity(
    score: int,
    reports: int,
    high_severity_threshold: int = 75,
) -> str:
    if score >= high_severity_threshold or reports >= 50:
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
