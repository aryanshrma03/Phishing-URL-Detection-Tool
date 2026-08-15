import hashlib
import json
import os
import urllib.error
import urllib.request
from urllib.parse import quote

class VirusTotalError(Exception):
    """Raised when VirusTotal lookup fails."""

def lookup_url(url: str, timeout: int = 10) -> dict:
    api_key = os.getenv("VT_API_KEY")
    if not api_key:
        raise VirusTotalError("VT_API_KEY is not configured.")

    url_id = hashlib.sha256(url.encode("utf-8")).hexdigest()

    request = urllib.request.Request(
        f"https://www.virustotal.com/api/v3/urls/{quote(url_id)}",
        headers={
            "x-apikey": api_key,
            "Accept": "application/json",
        },
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {"data": None, "message": "URL not present in VirusTotal records."}
        raise VirusTotalError(f"VirusTotal HTTP error: {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
        raise VirusTotalError(str(exc)) from exc
