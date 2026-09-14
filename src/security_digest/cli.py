from __future__ import annotations
import argparse, json
from datetime import date, timedelta
from importlib.resources import files
from pathlib import Path
from .config import load_config, load_dotenv
from .fetch import fetch_source
from .normalize import normalize
from .digest import filter_dedupe, markdown

def args_parser():
    p=argparse.ArgumentParser(description="Build a local daily security digest.")
    p.add_argument("--config", default="config/sources.json")
    p.add_argument("--days", type=int, default=1, help="Recent calendar days (1-31).")
    p.add_argument("--end-date", help="YYYY-MM-DD; defaults to today.")
    p.add_argument("--format", choices=("markdown","json"), default="markdown")
    p.add_argument("--output", help="Output file; defaults to stdout.")
    p.add_argument("--no-network", action="store_true", help="Use bundled deterministic fixtures.")
    return p

def main(argv=None):
    a=args_parser().parse_args(argv)
    if not 1 <= a.days <= 31: raise SystemExit("--days must be between 1 and 31")
    try: end=date.fromisoformat(a.end_date) if a.end_date else date.today()
    except ValueError: raise SystemExit("--end-date must be YYYY-MM-DD")
    start=end-timedelta(days=a.days-1); load_dotenv(); cfg=load_config(a.config); all_items=[]; errors=[]
    for source in cfg["sources"]:
        if not source.get("enabled", True) or source["type"] == "curated-link": continue
        try:
            if a.no_network:
                name={"json":"kev.json","nvd":"nvd.json","github":"github.json"}.get(source["type"])
                if source["type"] == "rss": name = f"{source['id']}.xml"
                if not name: raise RuntimeError("no fixture for source")
                raw=(files("security_digest") / "fixtures" / name).read_text(encoding="utf-8")
                data=raw if source["type"] == "rss" else json.loads(raw)
            else: data=fetch_source(source,start,end,cfg)
            all_items.extend(normalize(source,data))
        except Exception as exc: errors.append(f"{source['id']}: {exc}")
    items=filter_dedupe(all_items,start,end)
    payload={"window":{"start":start.isoformat(),"end":end.isoformat()},"items":[{k:v for k,v in x.items() if k!="dedupe_key"} for x in items],"fetch_errors":errors}
    rendered=json.dumps(payload, indent=2)+"\n" if a.format=="json" else markdown(items,errors,start,end)
    if a.output: Path(a.output).write_text(rendered,encoding="utf-8")
    else: print(rendered)
    return 0

if __name__ == "__main__": main()
# Review follow-up details for cli module
