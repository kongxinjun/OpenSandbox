"""Shared helpers: launch a real lifecycle server, talk to it, inspect Docker."""
from __future__ import annotations

import contextlib
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import docker
import httpx

ROOT = Path(__file__).resolve().parents[1]
# Colima on this Mac; docker-py does not read docker contexts.
os.environ.setdefault("DOCKER_HOST", f"unix://{Path.home()}/.colima/default/docker.sock")
SERVER_DIR = Path(os.environ.get("HUNT_SERVER_DIR", ROOT / "server"))
API_KEY = "hunt-key"
PORT = int(os.environ.get("HUNT_PORT", "18080"))
BASE = f"http://127.0.0.1:{PORT}/v1"
IMAGE = os.environ.get("HUNT_IMAGE", "busybox:latest")
ENTRY = ["sh", "-c", "sleep 3600"]


def client(timeout: float = 120.0) -> httpx.Client:
    return httpx.Client(base_url=BASE, headers={"OPEN-SANDBOX-API-KEY": API_KEY}, timeout=timeout)


@contextlib.contextmanager
def server(config: str = "docker.toml", env: dict | None = None, log: str = "/tmp/osb-hunt/server.log"):
    """Run the lifecycle server as a subprocess for the duration of the block."""
    import socket
    with socket.socket() as probe:
        if probe.connect_ex(("127.0.0.1", PORT)) == 0:
            # purge() and the fixed port assume one hunt run per daemon at a time.
            raise RuntimeError(f"port {PORT} busy: another hunt run is active")
    cfg = Path(__file__).resolve().parent / "config" / config
    Path("/tmp/osb-hunt/mounts").mkdir(parents=True, exist_ok=True)
    full_env = {**os.environ, "SANDBOX_CONFIG_PATH": str(cfg), **(env or {})}
    full_env.pop("VIRTUAL_ENV", None)
    with open(log, "ab") as fh:
        proc = subprocess.Popen(
            ["uv", "run", "--frozen", "python", "-m", "opensandbox_server.main"],
            cwd=SERVER_DIR, env=full_env, stdout=fh, stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    try:
        deadline = time.time() + 90
        while time.time() < deadline:
            if proc.poll() is not None:
                raise RuntimeError(f"server exited rc={proc.returncode}; see {log}")
            with contextlib.suppress(httpx.HTTPError):
                r = httpx.get(f"http://127.0.0.1:{PORT}/health", timeout=2)
                if r.status_code < 500:
                    break
            time.sleep(0.5)
        else:
            raise RuntimeError("server did not become healthy")
        yield proc
    finally:
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(proc.pid, signal.SIGTERM)
        try:
            proc.wait(15)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)


def docker_client():
    return docker.from_env()


def inventory(dc=None) -> dict:
    """Everything OpenSandbox owns on the Docker daemon, keyed by sandbox id."""
    dc = dc or docker_client()
    out: dict = {"containers": {}, "volumes": [], "networks": []}
    for c in dc.containers.list(all=True, filters={"label": "opensandbox.io/id"}):
        sid = c.labels.get("opensandbox.io/id")
        out["containers"].setdefault(sid, []).append((c.name, c.status))
    for v in dc.volumes.list():
        labels = v.attrs.get("Labels") or {}
        if any(k.startswith("opensandbox.io/") for k in labels):
            out["volumes"].append(v.name)
    for n in dc.networks.list():
        labels = n.attrs.get("Labels") or {}
        if any(k.startswith("opensandbox.io/") for k in labels) or n.name.startswith("opensandbox"):
            out["networks"].append(n.name)
    return out


def purge(dc=None):
    """Remove every OpenSandbox-owned container/volume/network (cleanup between runs)."""
    dc = dc or docker_client()
    for c in dc.containers.list(all=True, filters={"label": "opensandbox.io/id"}):
        with contextlib.suppress(Exception):
            c.remove(force=True)
    inv = inventory(dc)
    for name in inv["volumes"]:
        with contextlib.suppress(Exception):
            dc.volumes.get(name).remove(force=True)
    for name in inv["networks"]:
        with contextlib.suppress(Exception):
            dc.networks.get(name).remove()


def create_body(**over) -> dict:
    body = {
        "image": {"uri": IMAGE},
        "entrypoint": ENTRY,
        "timeout": 600,
        "resourceLimits": {"cpu": "500m", "memory": "256Mi"},
    }
    body.update(over)
    return body


def wait_state(c: httpx.Client, sid: str, states: set[str], timeout: float = 60) -> dict:
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        r = c.get(f"/sandboxes/{sid}")
        if r.status_code == 404:
            last = {"status": {"state": "<404>"}}
            if "<404>" in states:
                return last
        else:
            last = r.json()
            if last.get("status", {}).get("state") in states:
                return last
        time.sleep(0.5)
    raise TimeoutError(f"{sid} never reached {states}; last={last}")


def log(*a):
    print(*a, file=sys.stderr, flush=True)
