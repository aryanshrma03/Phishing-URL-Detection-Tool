from dataclasses import dataclass

@dataclass
class RiskResult:
    score: int
    label: str
    findings: list[dict]
    recommendations: list[str]

def calculate_risk(findings: list[dict]) -> RiskResult:
    score = min(100, sum(item["points"] for item in findings))

    if score >= 75:
        label = "Critical Risk"
    elif score >= 50:
        label = "High Risk"
    elif score >= 25:
        label = "Medium Risk"
    else:
        label = "Low Risk"

    recommendations = []

    if score == 0:
        recommendations.append("No local heuristic warning was triggered, but still verify the domain before visiting.")
    else:
        recommendations.append("Do not enter passwords, OTPs, card details, or recovery codes unless the destination is trusted.")

    if any(item["name"] == "No HTTPS" for item in findings):
        recommendations.append("Prefer HTTPS and verify that the hostname is the expected domain.")

    if any(item["name"] == "IP Address Host" for item in findings):
        recommendations.append("Be cautious with links that use raw IP addresses instead of recognizable domains.")

    if any(item["name"] in {"URL Shortener", "Redirect Parameter"} for item in findings):
        recommendations.append("Reveal and verify the final destination before opening the link.")

    if any(item["name"] == "Punycode / IDN" for item in findings):
        recommendations.append("Inspect internationalized domains carefully for lookalike characters.")

    if not recommendations:
        recommendations.append("Verify the domain independently before trusting the link.")

    return RiskResult(
        score=score,
        label=label,
        findings=findings,
        recommendations=recommendations,
    )
