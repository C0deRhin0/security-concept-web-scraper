from datetime import date

import pytest

from security_digest.fetch import FetchError, fetch_source, nvd_params


def test_nvd_params_use_api_datetime_format_and_full_day():
    assert nvd_params(date(2026, 9, 19), date(2026, 9, 19)) == {
        "pubStartDate": "2026-09-19T00:00:00.000",
        "pubEndDate": "2026-09-19T23:59:59.999",
        "resultsPerPage": 2000,
    }


def test_nvd_params_enforce_documented_window_limit():
    with pytest.raises(FetchError, match="cannot exceed 120 days"):
        nvd_params(date(2026, 1, 1), date(2026, 5, 2))


def test_nvd_fetch_passes_constructed_params(monkeypatch):
    received = {}

    def fake_get(url, headers, timeout, retries, params):
        received.update(url=url, headers=headers, timeout=timeout, retries=retries, params=params)
        return b'{"vulnerabilities": []}'

    monkeypatch.delenv("NVD_API_KEY", raising=False)
    monkeypatch.setattr("security_digest.fetch.get", fake_get)
    source = {"id": "nvd", "type": "nvd", "url": "https://services.nvd.nist.gov/rest/json/cves/2.0"}
    settings = {"user_agent": "test-agent", "timeout_seconds": 7, "retries": 0}

    assert fetch_source(source, date(2026, 9, 19), date(2026, 9, 19), settings) == {"vulnerabilities": []}
    assert received["params"] == nvd_params(date(2026, 9, 19), date(2026, 9, 19))
    assert received["url"] == source["url"]


def test_owasp_source_uses_verified_atom_feed():
    import json
    from pathlib import Path

    config = json.loads(Path("config/sources.json").read_text(encoding="utf-8"))
    owasp = next(source for source in config["sources"] if source["id"] == "owasp")
    assert owasp["url"] == "https://cheatsheetseries.owasp.org/News.xml"
