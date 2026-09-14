"""Configuration and deliberately small .env loader."""
from __future__ import annotations
import json, os
from pathlib import Path

def load_dotenv(path: Path = Path(".env")) -> None:
    """Load simple KEY=VALUE pairs without overriding the actual environment."""
    if not path.is_file(): return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line: continue
        key, value = line.split("=", 1)
        key, value = key.strip(), value.strip().strip("\"'")
        if key and key.replace("_", "").isalnum(): os.environ.setdefault(key, value)

def load_config(path: str | Path) -> dict:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or not isinstance(raw.get("sources"), list):
        raise ValueError("config must be an object with a sources array")
    for source in raw["sources"]:
        if not isinstance(source, dict) or not source.get("id") or not source.get("type"):
            raise ValueError("every source requires id and type")
    return raw
# Clarify implementation notes for config module
