from dataclasses import dataclass
from urllib.parse import parse_qsl, urlparse
import ipaddress
import re

@dataclass
class ParsedURL:
    original: str
    normalized: str
    scheme: str
    hostname: str
    port: int | None
    path: str
    query: str
    fragment: str
    query_parameters: list[tuple[str, str]]
    is_ip: bool
    is_valid: bool

def normalize_url(url: str) -> str:
    value = url.strip()
    if not value:
        return ""
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value):
        value = "https://" + value
    return value

def is_ip_address(hostname: str) -> bool:
    if not hostname:
        return False
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False

def parse_url(url: str) -> ParsedURL:
    normalized = normalize_url(url)
    parsed = urlparse(normalized)

    hostname = parsed.hostname or ""
    try:
        port = parsed.port
    except ValueError:
        port = None

    valid = bool(
        parsed.scheme in {"http", "https"}
        and hostname
        and not any(char.isspace() for char in normalized)
    )

    return ParsedURL(
        original=url,
        normalized=normalized,
        scheme=parsed.scheme.lower(),
        hostname=hostname.lower(),
        port=port,
        path=parsed.path,
        query=parsed.query,
        fragment=parsed.fragment,
        query_parameters=parse_qsl(parsed.query, keep_blank_values=True),
        is_ip=is_ip_address(hostname),
        is_valid=valid,
    )
