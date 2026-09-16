"""Convert public source formats into a compact, explainable common record."""
from __future__ import annotations
from datetime import date, datetime
from email.utils import parsedate_to_datetime
from xml.etree import ElementTree as ET

def parse_date(value: str | None) -> date | None:
    if not value: return None
    try: return datetime.fromisoformat(value.replace("Z", "+00:00")).date()
    except ValueError:
        try: return parsedate_to_datetime(value).date()
        except (TypeError, ValueError): return None

def item(title, source, when, risk, affected, why, action, url, key):
    return {"title": title, "source": source, "date": when.isoformat() if when else "unknown", "risk_level": risk,
            "affected_product_vendor": affected or "Not specified", "why_it_matters": why, "recommended_action": action,
            "url": url, "dedupe_key": key.lower()}

def risk(score=None, exploited=False):
    if exploited: return "Critical"
    if score is not None:
        if score >= 9: return "Critical"
        if score >= 7: return "High"
        if score >= 4: return "Medium"
    return "Informational"

def kev(data):
    return [item(f"{x['vendorProject']} {x['product']}: {x['vulnerabilityName']}", "CISA KEV", parse_date(x.get("dateAdded")), "Critical",
      f"{x['vendorProject']} — {x['product']}", "CISA lists this vulnerability as known exploited in the wild.",
      x.get("requiredAction", "Apply vendor mitigation."), "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", x["cveID"])
      for x in data.get("vulnerabilities", [])]

def nvd(data):
    out=[]
    for wrap in data.get("vulnerabilities", []):
        c=wrap.get("cve", {}); metrics=c.get("metrics", {}); metric=next(iter(metrics.get("cvssMetricV31", []) or metrics.get("cvssMetricV30", []) or metrics.get("cvssMetricV2", [])), {})
        score=metric.get("cvssData", {}).get("baseScore"); desc=next((d.get("value") for d in c.get("descriptions", []) if d.get("lang")=="en"), "NVD vulnerability record.")
        refs=c.get("references", []); url=refs[0]["url"] if refs else f"https://nvd.nist.gov/vuln/detail/{c.get('id','')}"
        out.append(item(f"{c.get('id')}: {desc[:120]}", "NVD", parse_date(c.get("published")), risk(score), "See NVD configurations/vendor advisories", desc, "Assess exposure; prioritize patching based on asset inventory and vendor guidance.", url, c.get("id", url)))
    return out

def github(data):
    out=[]
    for a in data:
        score=(a.get("cvss") or {}).get("score"); ident=a.get("ghsa_id", a.get("html_url", "")); cves=", ".join(a.get("cve_id") and [a["cve_id"]] or [])
        out.append(item(a.get("summary", ident), "GitHub Security Advisories", parse_date(a.get("published_at")), risk(score), a.get("vulnerabilities", [{}])[0].get("package", {}).get("name", "Open-source dependency"), a.get("description", "GitHub advisory."), "Update to a patched version and check dependency inventory.", a.get("html_url", "https://github.com/advisories/"), ident + cves))
    return out

def rss(text, label):
    root=ET.fromstring(text); out=[]
    for node in root.findall(".//item") + root.findall(".//{http://www.w3.org/2005/Atom}entry"):
        get=lambda *names: next((node.findtext(n) for n in names if node.findtext(n)), None)
        title=get("title", "{http://www.w3.org/2005/Atom}title") or "Untitled security news"
        url=get("link") or next((e.get("href") for e in node.findall("{http://www.w3.org/2005/Atom}link") if e.get("href")), "")
        when=get("pubDate", "{http://www.w3.org/2005/Atom}updated", "{http://www.w3.org/2005/Atom}published")
        out.append(item(title, label, parse_date(when), "Informational", "Not specified", "Curated security news; review relevance to your environment.", "Review and act on applicable vendor guidance.", url, url or title))
    return out

def normalize(source, data):
    return {"json": kev, "nvd": nvd, "github": github, "rss": lambda d: rss(d, source["id"])}.get(source["type"], lambda _: [])(data)
