"""One lifecycle round on the Kubernetes runtime (kind + host-run controller).

HUNT_PORT=18081 hunt/.venv/bin/python -m hunt.k8s_round
Checks: create/get/list/patch/renew/delete, double delete, concurrent deletes,
delete while the create request is still waiting for the Pod, a create whose
image cannot be pulled, and a renew that shortens expiry. After each case the
BatchSandbox and Pods for that sandbox must be gone (or present) as the API says.
"""
import concurrent.futures as cf
import json
import os
import subprocess
import time
from datetime import datetime, timedelta, timezone

from hunt.common import client, create_body, log, server

os.environ.setdefault("KUBECONFIG", "/tmp/osb-hunt/kind.kubeconfig")
NS = "opensandbox"


def kubectl(*args):
    r = subprocess.run(["kubectl", "-n", NS, *args], capture_output=True, text=True)
    return r.stdout


def k8s_objects(sid):
    bs = json.loads(kubectl("get", "batchsandboxes", "-o", "json") or '{"items":[]}')["items"]
    pods = json.loads(kubectl("get", "pods", "-o", "json") or '{"items":[]}')["items"]
    mine = lambda o: sid in json.dumps(o["metadata"].get("labels", {})) or sid in o["metadata"]["name"]  # noqa: E731
    return [b["metadata"]["name"] for b in bs if mine(b)], [p["metadata"]["name"] for p in pods if mine(p)]


def wait_gone(sid, timeout=60):
    deadline = time.time() + timeout
    while time.time() < deadline:
        bs, pods = k8s_objects(sid)
        if not bs and not pods:
            return True
        time.sleep(1)
    return k8s_objects(sid)


problems = []
with server(config="k8s.toml", log="/tmp/osb-hunt/server-k8s.log"):
    c = client(timeout=240)
    # 1. basic round
    t0 = time.time()
    r = c.post("/sandboxes", json=create_body(metadata={"team": "k8s"}))
    log("create", r.status_code, f"{time.time()-t0:.1f}s", r.text[:200])
    if r.status_code != 202:
        problems.append(("create", r.status_code, r.text[:300]))
    else:
        sid = r.json()["id"]
        g = c.get(f"/sandboxes/{sid}").json()
        log("get", g["status"], g.get("metadata"))
        lst = c.get("/sandboxes", params={"metadata": "team=k8s"}).json()
        if sid not in [i["id"] for i in lst["items"]]:
            problems.append(("list metadata filter", lst))
        p = c.patch(f"/sandboxes/{sid}/metadata", json={"team": None, "env": "x"})
        log("patch", p.status_code, p.json().get("metadata"))
        if (p.json().get("metadata") or {}) != {"env": "x"}:
            problems.append(("patch", p.json().get("metadata")))
        g2 = c.get(f"/sandboxes/{sid}").json().get("metadata")
        if (g2 or {}) != {"env": "x"}:
            problems.append(("patch then get", g2))
        soon = datetime.now(timezone.utc) + timedelta(seconds=8)
        rr = c.post(f"/sandboxes/{sid}/renew-expiration", json={"expiresAt": soon.isoformat()})
        log("renew shorten", rr.status_code, rr.text[:120])
        time.sleep(15)
        ge = c.get(f"/sandboxes/{sid}")
        log("after expiry", ge.status_code, ge.json().get("status") if ge.status_code == 200 else "")
        gone = wait_gone(sid, 60)
        log("k8s objects after expiry gone:", gone)
        if gone is not True:
            problems.append(("expiry left objects", gone))
        d = c.delete(f"/sandboxes/{sid}")
        log("delete after expiry", d.status_code, d.text[:120])

    # 2. concurrent deletes
    sid = c.post("/sandboxes", json=create_body()).json()["id"]
    with cf.ThreadPoolExecutor(3) as ex:
        codes = sorted(f.result().status_code for f in [ex.submit(c.delete, f"/sandboxes/{sid}") for _ in range(3)])
    log("concurrent deletes", codes)
    if any(code >= 500 for code in codes):
        problems.append(("concurrent delete", codes))
    gone = wait_gone(sid)
    if gone is not True:
        problems.append(("concurrent delete left", gone))
    log("after concurrent delete GET", c.get(f"/sandboxes/{sid}").status_code, gone)

    # 3. delete while create is still waiting for the Pod
    with cf.ThreadPoolExecutor(1) as ex:
        fut = ex.submit(c.post, "/sandboxes", json=create_body(image={"uri": "busybox:does-not-exist"}))
        victim = None
        deadline = time.time() + 30
        while time.time() < deadline and not victim:
            items = c.get("/sandboxes", params={"pageSize": 200}).json()["items"]
            pend = [i for i in items if i["status"]["state"] not in ("Running",)]
            victim = pend[0]["id"] if pend else None
            time.sleep(0.5)
        if victim:
            dd = c.delete(f"/sandboxes/{victim}")
            log("delete during pending create", dd.status_code)
        res = fut.result()
        log("pending create returned", res.status_code, res.text[:200])
        if victim:
            gone = wait_gone(victim)
            log("objects after delete-during-create:", gone)
            if gone is not True:
                problems.append(("delete during create left", gone))
    # 4. image that cannot be pulled, nobody deletes it
    # Upstream a15f5c970: a Pending sandbox that cannot pull reports IMAGE_PULL_FAILING.
    seen_reasons = set()
    with cf.ThreadPoolExecutor(1) as ex:
        t0 = time.time()
        fut = ex.submit(lambda: client(timeout=240).post("/sandboxes", json=create_body(image={"uri": "busybox:no-such-tag"})))
        while not fut.done():
            for i in c.get("/sandboxes", params={"pageSize": 200}).json()["items"]:
                if i["status"]["state"] == "Pending":
                    seen_reasons.add((i["status"].get("reason"), (i["status"].get("message") or "")[:120]))
            time.sleep(2)
        r = fut.result()
    log("unpullable image create", r.status_code, f"{time.time()-t0:.1f}s", r.text[:250])
    log("Pending reasons seen while it waited:", seen_reasons)
    if not any(reason == "IMAGE_PULL_FAILING" for reason, _ in seen_reasons):
        problems.append(("no IMAGE_PULL_FAILING while pull fails", seen_reasons))
    items = c.get("/sandboxes", params={"pageSize": 200}).json()["items"]
    log("sandboxes listed after failed create:", [(i["id"][:8], i["status"]["state"]) for i in items])
    for i in items:
        c.delete(f"/sandboxes/{i['id']}")
log("left in namespace:", kubectl("get", "batchsandboxes,pods", "--no-headers").strip() or "<nothing>")
print("PROBLEMS:", json.dumps(problems, default=str, indent=1))
