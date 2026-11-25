"""Fail the k-th Docker Engine API call of a lifecycle operation, for every k.

python -m hunt.fault_sweep --op create|create_pvc|delete|pause|resume|renew [--status 500]

Runs DockerSandboxService in-process against the real daemon. Every HTTP request
docker-py sends goes through APIClient.request; the k-th one (counted from the
start of the operation) is answered with a synthetic error response instead, so
docker-py raises the same APIError/NotFound it would for a real daemon failure.
After each faulted run, the fault is cleared and invariants are checked:

  * create: a failed create leaves no container, sidecar, or auto-created volume
    for that sandbox id and no reserved host ports; a successful one is listable.
  * delete/pause/resume/renew: GET agrees with the container state, the
    operation can be retried to completion, and a final delete leaves nothing.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import traceback
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

from hunt.common import ROOT, inventory, purge

os.environ["SANDBOX_CONFIG_PATH"] = str(Path(__file__).resolve().parent / "config" / "docker.toml")
sys.path.insert(0, str(ROOT / "server"))

import docker  # noqa: E402
from docker.api.client import APIClient  # noqa: E402
from fastapi import HTTPException  # noqa: E402

from opensandbox_server.api.schema import (  # noqa: E402
    CreateSandboxRequest,
    RenewSandboxExpirationRequest,
)
from opensandbox_server.config import load_config  # noqa: E402
from opensandbox_server.services.docker import port_allocator  # noqa: E402
from opensandbox_server.services.docker.docker_service import DockerSandboxService  # noqa: E402

_orig_request = APIClient.request


class Fault:
    target: int | None = None
    count = 0
    status = 500
    log: list[str] = []


def _faulty_request(self, method, url, *args, **kwargs):
    Fault.count += 1
    path = url.split("/v1.", 1)[-1] if "/v1." in url else url
    Fault.log.append(f"{method} {path}")
    if Fault.target is not None and Fault.count == Fault.target:
        resp = requests.Response()
        resp.status_code = Fault.status
        resp._content = json.dumps({"message": f"hunt: injected {Fault.status} on call {Fault.count}"}).encode()
        resp.headers["Content-Type"] = "application/json"
        resp.url = url
        resp.request = requests.Request(method, url).prepare()
        return resp
    return _orig_request(self, method, url, *args, **kwargs)


APIClient.request = _faulty_request


def arm(k: int | None):
    Fault.target = k
    Fault.count = 0
    Fault.log = []


def body(pvc: str | None = None) -> CreateSandboxRequest:
    raw = {
        "image": {"uri": "busybox:latest"},
        "entrypoint": ["sh", "-c", "sleep 3600"],
        "timeout": 600,
        "resourceLimits": {"cpu": "500m", "memory": "256Mi"},
    }
    if pvc:
        raw["volumes"] = [{"name": "data", "mountPath": "/data",
                           "pvc": {"claimName": pvc, "createIfNotExists": True,
                                   "deleteOnSandboxTermination": True}}]
    return CreateSandboxRequest.model_validate(raw)


def container_state(dc, sid):
    cs = dc.containers.list(all=True, filters={"label": f"opensandbox.io/id={sid}"})
    if not cs:
        return None
    st = cs[0].attrs["State"]
    if st.get("Paused"):
        return "Paused"
    if st.get("Running"):
        return "Running"
    # Exited containers surface as Stopped/Failed/Terminated depending on exit code.
    return "Exited"


def call(fn, *a):
    try:
        r = fn(*a)
        if asyncio.iscoroutine(r):
            r = asyncio.run(r)
        return "ok", r
    except HTTPException as e:
        return f"http{e.status_code}", e.detail
    except Exception as e:  # noqa: BLE001
        return f"exc:{type(e).__name__}", str(e)[:200]


def check_clean(dc, sid, problems, k, what, pvc=None):
    inv = inventory(dc)
    if sid and sid in inv["containers"]:
        problems.append((k, what, f"containers left: {inv['containers'][sid]}"))
    if pvc and pvc in [v.name for v in dc.volumes.list()]:
        problems.append((k, what, f"auto-created volume {pvc} left"))
    if port_allocator._RESERVED_HOST_PORTS:
        problems.append((k, what, f"reserved ports leaked: {sorted(port_allocator._RESERVED_HOST_PORTS)}"))


def sweep(op: str, status: int, max_k: int | None):
    dc = docker.from_env()
    purge(dc)
    svc = DockerSandboxService(load_config())
    pvc = "hunt-pvc-sweep" if op == "create_pvc" else None
    problems: list = []

    def setup():
        arm(None)
        resp = asyncio.run(svc.create_sandbox(body()))
        if op == "resume":
            svc.pause_sandbox(resp.id)
        return resp.id

    # Count the calls of a clean run.
    if op.startswith("create"):
        arm(None)
        ok, resp = call(svc.create_sandbox, body(pvc))
        total = Fault.count
        clean_log = list(Fault.log)
        assert ok == "ok", resp
        arm(None)
        svc.delete_sandbox(resp.id)
    else:
        sid = setup()
        arm(None)
        fn = {"delete": svc.delete_sandbox, "pause": svc.pause_sandbox, "resume": svc.resume_sandbox,
              "renew": lambda s: svc.renew_expiration(s, RenewSandboxExpirationRequest(
                  expiresAt=datetime.now(timezone.utc) + timedelta(hours=1)))}[op]
        ok, _ = call(fn, sid)
        total = Fault.count
        clean_log = list(Fault.log)
        arm(None)
        call(svc.delete_sandbox, sid)
    purge(dc)
    print(f"# op={op} clean run makes {total} Docker API calls", file=sys.stderr)
    for i, line in enumerate(clean_log, 1):
        print(f"#   {i:3d} {line}", file=sys.stderr)

    for k in range(1, min(total, max_k or total) + 1):
        arm(None)
        try:
            if op.startswith("create"):
                arm(k)
                outcome, detail = call(svc.create_sandbox, body(pvc))
                failed_call = Fault.log[k - 1] if len(Fault.log) >= k else "?"
                arm(None)
                sid = detail.id if outcome == "ok" else None
                if outcome != "ok":
                    # Which sandbox id did the failed create use? Look for anything labelled.
                    leftovers = {s for s in inventory(dc)["containers"]}
                    for s in leftovers:
                        problems.append((k, failed_call, f"create failed ({outcome}) but containers remain for {s}: {inventory(dc)['containers'][s]}"))
                    check_clean(dc, None, problems, k, failed_call, pvc)
                else:
                    got = call(svc.get_sandbox, sid)
                    if got[0] != "ok" or got[1].status.state != "Running":
                        problems.append((k, failed_call, f"create ok but GET says {got}"))
                    call(svc.delete_sandbox, sid)
                    check_clean(dc, sid, problems, k, failed_call, pvc)
                print(f"k={k:3d} {failed_call:60s} -> {outcome}", file=sys.stderr)
            else:
                sid = setup()
                fn = {"delete": svc.delete_sandbox, "pause": svc.pause_sandbox, "resume": svc.resume_sandbox,
                      "renew": lambda s: svc.renew_expiration(s, RenewSandboxExpirationRequest(
                          expiresAt=datetime.now(timezone.utc) + timedelta(hours=1)))}[op]
                arm(k)
                outcome, detail = call(fn, sid)
                failed_call = Fault.log[k - 1] if len(Fault.log) >= k else "?"
                arm(None)
                actual = container_state(dc, sid)
                got = call(svc.get_sandbox, sid)
                reported = got[1].status.state if got[0] == "ok" else got[0]
                if actual is None and reported != "http404":
                    problems.append((k, failed_call, f"container gone but GET -> {reported}"))
                if actual == "Exited" and reported in ("Stopped", "Failed", "Terminated"):
                    pass
                elif actual is not None and reported != actual:
                    problems.append((k, failed_call, f"container {actual} but GET -> {reported}"))
                if outcome != "ok":
                    retry = call(fn, sid)
                    if op == "delete" and retry[0] not in ("ok", "http404"):
                        problems.append((k, failed_call, f"delete retry -> {retry}"))
                    if op in ("pause", "resume") and retry[0] != "ok" and not (
                        retry[0] == "http409" and container_state(dc, sid) == {"pause": "Paused", "resume": "Running"}[op]
                    ):
                        problems.append((k, failed_call, f"{op} retry -> {retry}; state now {container_state(dc, sid)}"))
                final = call(svc.delete_sandbox, sid)
                if final[0] not in ("ok", "http404"):
                    problems.append((k, failed_call, f"final delete -> {final}"))
                check_clean(dc, sid, problems, k, failed_call)
                print(f"k={k:3d} {failed_call:60s} -> {outcome} (container {actual}, GET {reported})", file=sys.stderr)
        except Exception:  # noqa: BLE001
            problems.append((k, "harness", traceback.format_exc(limit=3)))
        finally:
            arm(None)
            purge(dc)
            port_allocator._RESERVED_HOST_PORTS.clear()
    return problems


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--op", required=True)
    ap.add_argument("--status", type=int, default=500)
    ap.add_argument("--max-k", type=int)
    a = ap.parse_args()
    Fault.status = a.status
    problems = sweep(a.op, a.status, a.max_k)
    print(f"\n== {len(problems)} invariant violations ==")
    for p in problems:
        print(p)


if __name__ == "__main__":
    main()
