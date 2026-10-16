.PHONY: test smoke

test:
	PYTHONPATH=src python -m pytest

smoke:
	PYTHONPATH=src python -m security_digest --no-network --format markdown
