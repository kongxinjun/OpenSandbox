"""P03: Docker snapshot (docker commit, pause=True) leaks a transient Paused state.

While the snapshot worker runs `docker commit`, the daemon freezes the container.
GET reports the sandbox as Paused although nobody paused it, POST /pause answers
409 SANDBOX_NOT_RUNNING, and POST /resume is accepted and unfreezes the container
in the middle of the commit (the snapshot is then no longer point-in-time).
Run: python -m hunt.probes.p03_snapshot_reports_paused
"""
import time

import httpx

from hunt.common import client, create_body, log, server

with server(log="/tmp/osb-hunt/server-p03.log"):
    c = client()
    sid = c.post("/sandboxes", json=create_body()).json()["id"]
    snap = None
    try:
        ep = c.get(f"/sandboxes/{sid}/endpoints/44772").json()
        url = "http://" + ep["endpoint"]
        # A big writable layer makes the commit last long enough to observe.
        with httpx.stream("POST", url + "/command", headers=ep.get("headers") or {},
                          json={"command": "dd if=/dev/urandom of=/big bs=1M count=400 2>/dev/null; sync; echo done"},
                          timeout=300) as s:
            for _ in s.iter_lines():
                pass
        r = c.post(f"/sandboxes/{sid}/snapshots", json={})
        snap = r.json()["id"]
        log("snapshot", r.status_code, r.json()["status"]["state"])
        seen = []
        resumed = None
        deadline = time.time() + 120
        while time.time() < deadline:
            st = c.get(f"/sandboxes/{sid}").json()["status"]["state"]
            seen.append(st)
            if st == "Paused" and resumed is None:
                p = c.post(f"/sandboxes/{sid}/pause")
                rs = c.post(f"/sandboxes/{sid}/resume")
                resumed = (p.status_code, p.json().get("code") if p.content else None, rs.status_code)
                log("while snapshotting: GET=Paused, pause ->", resumed[:2], "resume ->", resumed[2])
            ss = c.get(f"/snapshots/{snap}").json()["status"]["state"]
            if ss in ("Ready", "Failed"):
                log("snapshot finished:", ss, c.get(f"/snapshots/{snap}").json()["status"].get("message", "")[:160])
                break
            time.sleep(0.2)
        log("sandbox states observed:", sorted(set(seen)), "final:", c.get(f"/sandboxes/{sid}").json()["status"]["state"])
    finally:
        c.delete(f"/sandboxes/{sid}")
        if snap:
            c.delete(f"/snapshots/{snap}")
