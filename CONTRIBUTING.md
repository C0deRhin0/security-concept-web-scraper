# Contributing

Keep changes small, testable, and source-policy compliant. Run `make test` and
`make smoke` before opening a pull request. Add deterministic fixtures for new
normalizers; do not add credentials, personal data, or scraped paywalled HTML.

For a new feed, add a `rss` source in `config/sources.json`, document its terms
and purpose in `docs/source-policy.md`, and use its stable feed URL.
