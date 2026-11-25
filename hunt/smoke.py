"""Create -> get -> endpoint -> execd ping -> pause -> resume -> delete on the real Docker runtime."""
import httpx

from hunt.common import client, create_body, inventory, log, server, wait_state

with server():
    c = client()
    r = c.post("/sandboxes", json=create_body())
    log("create", r.status_code, r.text[:300])
    sid = r.json()["id"]
    log("get", c.get(f"/sandboxes/{sid}").json()["status"])
    ep = c.get(f"/sandboxes/{sid}/endpoints/44772").json()
    log("endpoint", ep)
    url = ep["endpoint"] if ep["endpoint"].startswith("http") else "http://" + ep["endpoint"]
    log("execd ping", httpx.get(url + "/ping", headers=ep.get("headers") or {}, timeout=10).status_code)
    log("pause", c.post(f"/sandboxes/{sid}/pause").status_code, wait_state(c, sid, {"Paused"})["status"]["state"])
    log("resume", c.post(f"/sandboxes/{sid}/resume").status_code, wait_state(c, sid, {"Running"})["status"]["state"])
    log("delete", c.delete(f"/sandboxes/{sid}").status_code, c.get(f"/sandboxes/{sid}").status_code)
    log("inventory", inventory())
