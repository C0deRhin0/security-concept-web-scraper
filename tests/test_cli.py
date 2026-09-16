import json
from security_digest.cli import main

def test_no_network_json(capsys):
    assert main(["--no-network", "--format", "json", "--end-date", "2026-09-19"]) == 0
    data=json.loads(capsys.readouterr().out)
    assert len(data["items"]) == 5
    assert not data["fetch_errors"]

def test_input_validation():
    try: main(["--days", "0"])
    except SystemExit as exc: assert "between" in str(exc)
    else: assert False
# Refine the surrounding context for test cli module
