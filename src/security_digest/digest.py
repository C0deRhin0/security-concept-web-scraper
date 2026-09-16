from __future__ import annotations
from datetime import date

def filter_dedupe(items, start, end):
    seen=set(); result=[]
    for x in items:
        d = date.fromisoformat(x["date"]) if x["date"] != "unknown" else None
        if d and not (start <= d <= end): continue
        key=x["dedupe_key"]
        if key in seen: continue
        seen.add(key); result.append(x)
    order={"Critical":0,"High":1,"Medium":2,"Informational":3}
    return sorted(result, key=lambda x:(order.get(x["risk_level"], 9), x["date"]), reverse=False)

def markdown(items, errors, start, end):
    lines=[f"# Daily Security Digest — {start.isoformat()} to {end.isoformat()}", "", "Risk: Critical = known exploited or CVSS ≥9; High = CVSS ≥7; Medium = CVSS ≥4; otherwise Informational.", ""]
    if errors: lines += ["## Source fetch notes", ""] + [f"- {e}" for e in errors] + [""]
    if not items: lines += ["No matching items were found."]
    for x in items:
        lines += [f"## {x['title']}", f"- **Source:** {x['source']}", f"- **Date:** {x['date']}", f"- **Risk level:** {x['risk_level']}", f"- **Affected product/vendor:** {x['affected_product_vendor']}", f"- **Why it matters:** {x['why_it_matters']}", f"- **Recommended action:** {x['recommended_action']}", f"- **URL:** {x['url']}", ""]
    return "\n".join(lines)
