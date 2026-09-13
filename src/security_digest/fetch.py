"""Small, bounded HTTP client for public feeds."""
from __future__ import annotations
import json, time
from datetime import date
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

class FetchError(RuntimeError): pass

def get(url: str, headers: dict[str, str], timeout: int, retries: int, params: dict | None = None) -> bytes:
    if params:
        url += ("&" if "?" in url else "?") + urlencode(params)
    last = None
    for attempt in range(retries + 1):
        try:
            request = Request(url, headers=headers)
            with urlopen(request, timeout=timeout) as response:
                if response.status >= 400: raise FetchError(f"HTTP {response.status}")
                return response.read()
        except (HTTPError, URLError, TimeoutError, FetchError) as exc:
            last = exc
            if attempt < retries: time.sleep(0.4 * (2 ** attempt))
    raise FetchError(str(last))

def nvd_params(start: date, end: date) -> dict[str, str | int]:
    """Build the bounded published-date query accepted by NVD CVE API 2.0.

    NVD accepts ISO 8601 timestamps with millisecond precision.  Its documented
    maximum date range is 120 days; the CLI's 31-day maximum is inside that
    limit, but keep this guard here for callers of this module as well.
    """
    if end < start:
        raise FetchError("NVD pubEndDate must not precede pubStartDate")
    if (end - start).days > 120:
        raise FetchError("NVD published-date windows cannot exceed 120 days")
    return {
        "pubStartDate": f"{start.isoformat()}T00:00:00.000",
        "pubEndDate": f"{end.isoformat()}T23:59:59.999",
        "resultsPerPage": 2000,
    }

def fetch_source(source: dict, start, end, settings: dict) -> object:
    headers = {"User-Agent": settings["user_agent"], "Accept": "application/json, application/rss+xml, application/xml"}
    kind, url = source["type"], source.get("url", "")
    timeout, retries = int(settings.get("timeout_seconds", 15)), int(settings.get("retries", 2))
    params = None
    if kind == "nvd":
        params = nvd_params(start, end)
        if __import__("os").environ.get("NVD_API_KEY"): headers["apiKey"] = __import__("os").environ["NVD_API_KEY"]
    elif kind == "github":
        params = {"per_page": 100, "sort": "published", "direction": "desc"}
        if __import__("os").environ.get("GITHUB_TOKEN"): headers["Authorization"] = "Bearer " + __import__("os").environ["GITHUB_TOKEN"]
    elif kind == "msrc":
        url = __import__("os").environ.get("MSRC_API_BASE", "")
        if not url: raise FetchError("MSRC_API_BASE is not configured (no undocumented endpoint is used)")
        if __import__("os").environ.get("MSRC_API_TOKEN"): headers["Authorization"] = "Bearer " + __import__("os").environ["MSRC_API_TOKEN"]
    data = get(url, headers, timeout, retries, params)
    return data.decode("utf-8") if kind == "rss" else json.loads(data)
