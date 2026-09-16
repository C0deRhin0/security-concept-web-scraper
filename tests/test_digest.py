from datetime import date
from security_digest.digest import filter_dedupe
from security_digest.normalize import kev, nvd, risk

def test_risk_thresholds():
    assert risk(9.0) == "Critical"
    assert risk(7.0) == "High"
    assert risk(4.0) == "Medium"

def test_normalize_and_window_dedupes():
    record = kev({"vulnerabilities":[{"cveID":"CVE-X","vendorProject":"V","product":"P","vulnerabilityName":"Issue","dateAdded":"2026-09-19","requiredAction":"Patch"}]})[0]
    items = filter_dedupe([record, record], date(2026,9,19), date(2026,9,19))
    assert len(items) == 1 and items[0]["risk_level"] == "Critical"

def test_nvd_normalizer():
    result=nvd({"vulnerabilities":[{"cve":{"id":"CVE-X","published":"2026-09-19T00:00:00","descriptions":[],"metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":8}}]}}}]})
    assert result[0]["risk_level"] == "High"
# Document the next adjustment for test digest module
