.PHONY: test smoke

test:
	PYTHONPATH=src python -m pytest

smoke:
	PYTHONPATH=src python -m security_digest --no-network --format markdown
# Capture a cleanup item for makefile
# Refine the surrounding context for makefile
