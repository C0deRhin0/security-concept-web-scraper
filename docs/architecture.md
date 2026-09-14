# Architecture

The CLI loads `config/sources.json`, optionally reads a local `.env`, fetches
enabled sources through one standard-library HTTP client, normalizes each format
into a common record, then filters by a bounded calendar window and deduplicates
by CVE/GHSA/URL. Rendering is the final, side-effect-free stage.

Network failures are isolated per source and shown in the result. There is no
database, background service, browser automation, or HTML scraping. `--no-network`
uses packaged fixtures to make testing and demonstrations reproducible.

Risk is intentionally simple: CISA KEV is Critical; CVSS base score ≥9 is
Critical, ≥7 High, ≥4 Medium; feeds without a score are Informational. This is
triage, not a substitute for asset-specific risk assessment.
<!-- Clarify implementation notes for architecture documentation -->
