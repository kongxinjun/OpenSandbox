"""P06 (Kubernetes): deleting a sandbox while its create request waits for the Pod.

The create keeps polling a Stopping / vanished BatchSandbox until
POD_READY_TIMEOUT and then answers 504 "Timeout waiting ... Last state: Stopping".
Needs the kind setup from hunt/README.md (controller running on the host).
Run: HUNT_PORT=18081 python -m hunt.probes.p06_k8s_delete_during_create
"""
import concurrent.futures as cf
import time

from hunt.common import client, create_body, log, server

with server(config="k8s.toml", log="/tmp/osb-hunt/server-p06.log"):
    c = client(timeout=240)
    with cf.ThreadPoolExecutor(1) as ex:
        # An image that never pulls keeps the sandbox Pending long enough to delete it.
        t0 = time.time()
        fut = ex.submit(c.post, "/sandboxes", json=create_body(image={"uri": "busybox:does-not-exist"}))
        victim = None
        while time.time() - t0 < 30 and not victim:
            items = c.get("/sandboxes", params={"pageSize": 200}).json()["items"]
            victim = items[0]["id"] if items else None
            time.sleep(0.5)
        log("delete", victim, c.delete(f"/sandboxes/{victim}").status_code, f"at {time.time()-t0:.1f}s")
        r = fut.result()
        log("create returned", r.status_code, f"after {time.time()-t0:.1f}s:", r.text[:160])
