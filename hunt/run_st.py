"""Spec-driven fuzzing of the lifecycle API on the real Docker runtime.

python -m hunt.run_st [extra st args...]
Starts the server, creates one live sandbox that path parameters are pointed at,
runs schemathesis with every check, then deletes whatever the run created.
"""
import os
import subprocess
import sys
from pathlib import Path

from hunt.common import BASE, ROOT, API_KEY, client, create_body, inventory, log, purge, server

HERE = Path(__file__).resolve().parent

with server(log="/tmp/osb-hunt/server-st.log"):
    c = client()
    live = c.post("/sandboxes", json=create_body(timeout=1800)).json()["id"]
    log("live sandbox", live)
    env = {**os.environ, "HUNT_LIVE_SANDBOX": live, "SCHEMATHESIS_HOOKS": "hunt.st.hooks",
           "PYTHONPATH": str(ROOT)}
    cmd = [str(HERE / ".venv/bin/st"), "run", str(ROOT / "specs/sandbox-lifecycle.yml"),
           "--url", BASE, "-H", f"OPEN-SANDBOX-API-KEY: {API_KEY}",
           "--checks", "all", "--report", "ndjson,junit", "--report-dir", "/tmp/osb-hunt/st-report",
           *sys.argv[1:]]
    log(" ".join(cmd))
    rc = subprocess.call(cmd, env=env)
    log("rc", rc, "inventory before purge", inventory())
purge()
