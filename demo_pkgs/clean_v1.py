import datetime
import json
import os
from pathlib import Path


config_path = Path(__file__).with_name("demo_config.json")
if not config_path.exists():
    config_path.write_text(json.dumps({"app": "release-clock"}) + "\n", encoding="utf-8")
config = json.loads(config_path.read_text(encoding="utf-8"))
timezone = os.getenv("APP_TIMEZONE", "UTC")
stamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
print(f"{config['app']} ready at {stamp} ({timezone})")