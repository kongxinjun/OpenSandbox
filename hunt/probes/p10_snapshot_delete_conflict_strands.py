"""Docker: DELETE /snapshots/{id} while a sandbox restored from it still runs.

The service marks the record Deleting before removing the image; the image
removal answers 409 (a container uses it) and the record is left Deleting.

    hunt/.venv/bin/python -m hunt.probes.p10_snapshot_delete_conflict_strands
"""
import json
import time

from hunt.common import client, create_body, docker_client, log, purge, server, wait_state


def main():
    purge()
    with server():
        c = client(300)
        src = c.post("/sandboxes", json=create_body()).json()["id"]
        wait_state(c, src, {"Running"})
        snap = c.post(f"/sandboxes/{src}/snapshots", json={"name": "p10"}).json()["id"]
        for _ in range(60):
            s = c.get(f"/snapshots/{snap}").json()
            if s["status"]["state"] in ("Ready", "Failed"):
                break
            time.sleep(1)
        log("snapshot:", s["status"]["state"])
        body = create_body(); body.pop("image"); body["snapshotId"] = snap
        restored = c.post("/sandboxes", json=body).json()["id"]
        wait_state(c, restored, {"Running"}, 90)

        r = c.delete(f"/snapshots/{snap}")
        log("DELETE snapshot while restored sandbox runs:", r.status_code, r.text[:200])
        g = c.get(f"/snapshots/{snap}")
        log("GET snapshot after the 409:", g.status_code, json.dumps(g.json().get("status"))[:200])
        r2 = c.post("/sandboxes", json=body)
        log("restore again from it:", r2.status_code, r2.text[:200])
        lst = c.get("/snapshots", params={"sandboxId": src}).json()
        log("list:", [(x["id"][:8], x["status"]["state"]) for x in lst.get("items", [])])

        c.delete(f"/sandboxes/{restored}")
        if r2.status_code == 202:
            c.delete(f"/sandboxes/{r2.json()['id']}")
        wait_state(c, restored, {"<404>"})
        c.delete(f"/sandboxes/{src}")
    # No further DELETE from the client: restart the server and look again.
    with server():
        c = client(300)
        time.sleep(2)
        g = c.get(f"/snapshots/{snap}")
        log("after a server restart, with no second DELETE:", g.status_code, g.text[:160],
            "| image present:", any(f"opensandbox-snapshots:{snap}" in t for i in docker_client().images.list() for t in i.tags))
    purge()


if __name__ == "__main__":
    main()
