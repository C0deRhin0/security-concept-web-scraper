# Source policy

| Source | Method | Purpose / limitation |
| --- | --- | --- |
| CISA KEV | Published JSON feed | Known exploited vulnerabilities; treated as Critical. |
| NVD | Documented CVE 2.0 API | Public CVE enrichment; millisecond ISO-8601 published-date window, limited to 120 days by NVD. |
| GitHub | Public Security Advisories API | Dependency advisory awareness; results are locally windowed. |
| OWASP Cheat Sheet Series, Krebs | Their published Atom/RSS feeds | Contextual news, marked Informational. The OWASP root `/feed` and `/feed.xml` URLs return 404, so OWASP uses its published `https://cheatsheetseries.owasp.org/News.xml` Atom feed. |
| CSO, Dark Reading | Curated links only | Landing pages are recorded for human review; HTML is not scraped. |
| Microsoft MSRC | Disabled configuration placeholder | Enable only with a documented endpoint and permitted credentials. |

Respect upstream rate limits, terms, and attribution. The project fetches only
configured public endpoints and does not attempt authentication unless the user
places an optional token in their local environment.
