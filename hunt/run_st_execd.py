"""Spec-driven fuzzing of execd (specs/execd-api.yaml) inside a real Docker sandbox.

python -m hunt.run_st_execd [extra st args...]
Talks to execd directly on its published host port. Jupyter (/code*) and
isolated-session routes are excluded: the busybox sandbox has neither.
"""
import subprocess
import sys
from pathlib import Path

from hunt.common import ROOT, client, create_body, docker_client, log, purge, server

HERE = Path(__file__).resolve().parent

with server(log="/tmp/osb-hunt/server-st-execd.log"):
    c = client()
    sid = c.post("/sandboxes", json=create_body(timeout=1800)).json()["id"]
    ctr = docker_client().containers.list(filters={"label": f"opensandbox.io/id={sid}"})[0]
    port = ctr.labels["opensandbox.io/embedding-proxy-port"]
    base = f"http://127.0.0.1:{port}"
    log("execd at", base, "sandbox", sid)
    cmd = [str(HERE / ".venv/bin/st"), "run", str(ROOT / "specs/execd-api.yaml"), "--url", base,
           "--checks", "all", "--exclude-path-regex", "^/(code|v1/isolated)",
           "--report", "ndjson", "--report-dir", "/tmp/osb-hunt/st-execd", *sys.argv[1:]]
    rc = subprocess.call(cmd)
    log("execd still alive:", subprocess.call(["curl", "-s", "-o", "/dev/null", base + "/ping"]) == 0)
purge()
