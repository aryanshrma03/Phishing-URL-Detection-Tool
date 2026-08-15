import re
from urllib.parse import unquote

from analyzer.url_parser import ParsedURL

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly",
    "buff.ly", "cutt.ly", "rb.gy", "shorturl.at", "tiny.one",
}

SUSPICIOUS_TLDS = {
    "zip", "mov", "click", "top", "work", "download", "country",
    "gq", "tk", "ml", "ga", "cf", "xyz", "buzz", "cam", "rest",
}

SUSPICIOUS_KEYWORDS = {
    "login", "verify", "verification", "secure", "account", "update",
    "password", "signin", "bank", "wallet", "payment", "invoice",
    "confirm", "suspended", "unlock", "credential", "recover",
}

REDIRECT_PARAMETERS = {
    "url", "redirect", "redirect_url", "redirect_uri", "return",
    "return_url", "next", "target", "dest", "destination",
}

def _finding(name, severity, reason, points):
    return {
        "name": name,
        "severity": severity,
        "reason": reason,
        "points": points,
    }

def analyze_heuristics(parsed: ParsedURL) -> list[dict]:
    if not parsed.is_valid:
        return [_finding(
            "Invalid URL",
            "Critical",
            "The supplied value could not be parsed as a normal HTTP/HTTPS URL.",
            100,
        )]

    findings = []
    host = parsed.hostname
    decoded = unquote(parsed.normalized).lower()

    if parsed.is_ip:
        findings.append(_finding(
            "IP Address Host",
            "High",
            "The URL uses a raw IP address instead of a conventional domain name.",
            25,
        ))

    if parsed.scheme != "https":
        findings.append(_finding(
            "No HTTPS",
            "Medium",
            "The URL does not use HTTPS, so traffic may not be protected in transit.",
            12,
        ))

    if "@" in parsed.normalized:
        findings.append(_finding(
            "@ Symbol",
            "High",
            "An @ symbol can obscure the actual destination hostname.",
            25,
        ))

    if len(parsed.normalized) >= 180:
        findings.append(_finding(
            "Very Long URL",
            "Medium",
            "Unusually long URLs can hide suspicious paths, parameters, or encoded content.",
            10,
        ))
    elif len(parsed.normalized) >= 100:
        findings.append(_finding(
            "Long URL",
            "Low",
            "The URL is longer than typical links.",
            5,
        ))

    labels = [part for part in host.split(".") if part]
    if len(labels) >= 5:
        findings.append(_finding(
            "Excessive Subdomains",
            "Medium",
            "The hostname contains an unusually large number of labels.",
            12,
        ))

    if host.startswith("xn--") or ".xn--" in host:
        findings.append(_finding(
            "Punycode / IDN",
            "Medium",
            "The hostname contains internationalized-domain encoding that can be used in lookalike domains.",
            15,
        ))

    tld = labels[-1] if labels else ""
    if tld in SUSPICIOUS_TLDS:
        findings.append(_finding(
            "Suspicious TLD",
            "Medium",
            f".{tld} is included in the local suspicious-TLD heuristic list.",
            10,
        ))

    if host.count("-") >= 3:
        findings.append(_finding(
            "Many Hyphens",
            "Low",
            "Multiple hyphens in a hostname can be associated with deceptive domain construction.",
            7,
        ))

    digit_count = sum(char.isdigit() for char in host)
    if digit_count >= 5:
        findings.append(_finding(
            "Numeric-Heavy Host",
            "Low",
            "The hostname contains an unusually high number of digits.",
            7,
        ))

    if parsed.port not in (None, 80, 443):
        findings.append(_finding(
            "Non-Standard Port",
            "Medium",
            f"The URL uses port {parsed.port}, which is uncommon for ordinary web links.",
            12,
        ))

    keyword_hits = sorted({
        keyword for keyword in SUSPICIOUS_KEYWORDS
        if keyword in decoded
    })
    if len(keyword_hits) >= 2:
        findings.append(_finding(
            "Suspicious Keywords",
            "Medium",
            "The URL contains multiple security/account-related terms: "
            + ", ".join(keyword_hits[:6]) + ".",
            14,
        ))
    elif keyword_hits:
        findings.append(_finding(
            "Security Keyword",
            "Low",
            f"The URL contains a security-related keyword: {keyword_hits[0]}.",
            5,
        ))

    if "%" in parsed.normalized:
        encoded_count = parsed.normalized.count("%")
        if encoded_count >= 4:
            findings.append(_finding(
                "Heavy URL Encoding",
                "Medium",
                "The URL contains multiple percent-encoded characters.",
                10,
            ))

    parameter_names = {
        key.lower().strip()
        for key, _ in parsed.query_parameters
    }
    redirect_hits = sorted(parameter_names & REDIRECT_PARAMETERS)
    if redirect_hits:
        findings.append(_finding(
            "Redirect Parameter",
            "Medium",
            "The query contains redirect-like parameters: " + ", ".join(redirect_hits) + ".",
            12,
        ))

    if len(parsed.query_parameters) >= 8:
        findings.append(_finding(
            "Many Query Parameters",
            "Low",
            "The URL contains a large number of query parameters.",
            5,
        ))

    if parsed.fragment and len(parsed.fragment) > 80:
        findings.append(_finding(
            "Large Fragment",
            "Low",
            "The URL contains a large fragment that may conceal client-side data.",
            4,
        ))

    if host in SHORTENERS:
        findings.append(_finding(
            "URL Shortener",
            "Medium",
            "Shortened links hide the final destination until redirected.",
            15,
        ))

    return findings
