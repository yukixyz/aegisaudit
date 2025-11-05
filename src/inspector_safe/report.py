from pathlib import Path
import json
from datetime import datetime
from typing import Any, Dict

REPORT_DIR = Path("reports")
REPORT_DIR.mkdir(parents=True, exist_ok=True)

def save_report(data: Dict[str, Any], name: str = None) -> Path:
    now = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    filename = f"report_{now}.json" if not name else name
    path = REPORT_DIR / filename
    with path.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    return path
