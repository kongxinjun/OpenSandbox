"""P04: what survives a server restart on the Docker runtime.

Create sandboxes, mutate them (renew, metadata patch, pause, short expiry), restart
the server, and compare GET/list before and after. Also checks that an expiry that
passes while the server is down is enforced once it is back.
Run: python -m hunt.probes.p04_restart_persistence
"""
import time
from datetime import datetime, timedelta, timezone

from hunt.common import client, create_body, inventory, log, purge, server

purge()
iso = lambda dt: dt.isoformat()  # noqa: E731
with server(log="/tmp/osb-hunt/server-p04a.log"):
    c = client()
    a = c.post("/sandboxes", json=create_body(metadata={"team": "a"})).json()["id"]
    b = c.post("/sandboxes", json=create_body()).json()["id"]
    d = c.post("/sandboxes", json=create_body()).json()["id"]
    renew_to = datetime.now(timezone.utc) + timedelta(minutes=37)
    log("renew a", c.post(f"/sandboxes/{a}/renew-expiration", json={"expiresAt": iso(renew_to)}).status_code)
    log("patch a", c.patch(f"/sandboxes/{a}/metadata", json={"team": None, "env": "prod"}).status_code)
    log("pause b", c.post(f"/sandboxes/{b}/pause").status_code)
    soon = datetime.now(timezone.utc) + timedelta(seconds=8)
    log("shorten d", c.post(f"/sandboxes/{d}/renew-expiration", json={"expiresAt": iso(soon)}).status_code)
    before = {s: c.get(f"/sandboxes/{s}").json() for s in (a, b)}
time.sleep(12)  # d expires while the server is down
with server(log="/tmp/osb-hunt/server-p04b.log"):
    c = client()
    for s in (a, b):
        after = c.get(f"/sandboxes/{s}").json()
        for k in ("expiresAt", "metadata", "status"):
            x, y = before[s].get(k), after.get(k)
            if k == "status":
                x, y = x["state"], y["state"]
            log(f"{s[:8]} {k}: before={x} after={y} {'OK' if x == y else 'DIFF'}")
    r = c.get(f"/sandboxes/{d}")
    log("d (expired while down):", r.status_code, r.json().get("status", {}).get("state") if r.status_code == 200 else "")
    time.sleep(5)
    log("d after 5s:", c.get(f"/sandboxes/{d}").status_code, "containers:", inventory()["containers"].get(d))
    for s in (a, b, d):
        c.delete(f"/sandboxes/{s}")
purge()
