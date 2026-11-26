"""Docker: renew / snapshot / delete / restore racing a sandbox's expiry.

Each trial shortens a sandbox's expiry to a few seconds, then fires the
operation at expiry + offset (offsets sweep across the boundary). Invariants:

* renew answered 200 => the sandbox is alive afterwards with the new expiresAt;
  otherwise it is gone (404) and no container/sidecar remains.
* snapshot answered 202 => the snapshot ends Ready (image present) or Failed
  (no image left behind); never stuck in Creating.
* no `opensandbox-snapshots:*` image without a snapshot record, no container
  of a deleted sandbox.

    hunt/.venv/bin/python -m hunt.expiry_race [--trials 8] [--ops renew snapshot ...]
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import json
import time
from datetime import datetime, timedelta, timezone

from hunt.common import client, create_body, docker_client, inventory, log, purge, server, wait_state

FINDINGS: list[str] = []


def now():
    return datetime.now(timezone.utc)


def shorten(c, sid, seconds):
    when = now() + timedelta(seconds=seconds)
    r = c.post(f"/sandboxes/{sid}/renew-expiration", json={"expiresAt": when.isoformat()})
    assert r.status_code == 200, r.text
    return datetime.fromisoformat(r.json()["expiresAt"].replace("Z", "+00:00"))


def at(t: datetime):
    d = (t - now()).total_seconds()
    if d > 0:
        time.sleep(d)


def containers_of(sid):
    dc = docker_client()
    return [x.name for x in dc.containers.list(all=True, filters={"label": f"opensandbox.io/id={sid}"})] + \
           [x.name for x in dc.containers.list(all=True, filters={"label": f"opensandbox.io/egress-sidecar-for={sid}"})]


def settle(c, sid, secs=12):
    """Wait for the expiry sweeper to act, then return (GET status, containers)."""
    deadline = time.time() + secs
    while time.time() < deadline:
        r = c.get(f"/sandboxes/{sid}")
        if r.status_code == 404:
            break
        time.sleep(0.5)
    return r.status_code, containers_of(sid)


def snapshot_images():
    dc = docker_client()
    return sorted(t for i in dc.images.list() for t in i.tags if t.startswith("opensandbox-snapshots:"))


def trial_renew(c, offset, policy):
    sid = c.post("/sandboxes", json=create_body(**policy)).json()["id"]
    wait_state(c, sid, {"Running"}, 90)
    exp = shorten(c, sid, 4)
    at(exp + timedelta(seconds=offset))
    target = now() + timedelta(seconds=600)
    r = c.post(f"/sandboxes/{sid}/renew-expiration", json={"expiresAt": target.isoformat()})
    time.sleep(6)
    g = c.get(f"/sandboxes/{sid}")
    conts = containers_of(sid)
    line = f"renew offset={offset:+.2f} -> {r.status_code}; GET {g.status_code}; containers={conts}"
    bad = (r.status_code == 200 and (g.status_code != 200 or not conts)) or \
          (g.status_code == 404 and conts) or (g.status_code == 200 and g.json()["status"]["state"] != "Running")
    if bad:
        FINDINGS.append(line + f" body={r.text[:200]} get={g.text[:200]}")
    log(("BAD " if bad else "ok  ") + line)
    if g.status_code == 200:
        c.delete(f"/sandboxes/{sid}")


def trial_snapshot(c, offset, policy):
    sid = c.post("/sandboxes", json=create_body(**policy)).json()["id"]
    wait_state(c, sid, {"Running"}, 90)
    exp = shorten(c, sid, 4)
    at(exp + timedelta(seconds=offset))
    r = c.post(f"/sandboxes/{sid}/snapshots", json={"name": f"exp{offset}"})
    snap_state, snap_id, snap = None, None, {}
    if r.status_code == 202:
        snap_id = r.json()["id"]
        for _ in range(90):
            snap = c.get(f"/snapshots/{snap_id}").json()
            snap_state = snap.get("status", {}).get("state")
            if snap_state in ("Ready", "Failed"):
                break
            time.sleep(1)
    gs, conts = settle(c, sid)
    imgs = snapshot_images()
    has_img = bool(snap_id) and f"opensandbox-snapshots:{snap_id}" in imgs
    line = (f"snapshot offset={offset:+.2f} -> {r.status_code}; snap={snap_state} img={has_img}; "
            f"sandbox GET {gs} containers={conts}")
    bad = (r.status_code == 202 and snap_state not in ("Ready", "Failed")) or \
          (snap_state == "Ready" and not has_img) or (snap_state == "Failed" and has_img) or (gs == 404 and conts)
    if bad:
        FINDINGS.append(line + f" snap={json.dumps(snap)[:300]}")
    log(("BAD " if bad else "ok  ") + line + (f" reason={snap.get('status', {}).get('message', '')[:100]}" if snap_state == "Failed" else ""))
    if snap_id:
        c.delete(f"/snapshots/{snap_id}")
    if gs == 200:
        c.delete(f"/sandboxes/{sid}")


def trial_delete(c, offset, policy):
    sid = c.post("/sandboxes", json=create_body(**policy)).json()["id"]
    wait_state(c, sid, {"Running"}, 90)
    exp = shorten(c, sid, 4)
    at(exp + timedelta(seconds=offset))
    r = c.delete(f"/sandboxes/{sid}")
    gs, conts = settle(c, sid, 6)
    line = f"delete offset={offset:+.2f} -> {r.status_code}; GET {gs} containers={conts}"
    bad = r.status_code not in (204, 404) or gs != 404 or bool(conts)
    if bad:
        FINDINGS.append(line + f" body={r.text[:200]}")
    log(("BAD " if bad else "ok  ") + line)


def trial_pause(c, offset, policy):
    sid = c.post("/sandboxes", json=create_body(**policy)).json()["id"]
    wait_state(c, sid, {"Running"}, 90)
    exp = shorten(c, sid, 4)
    at(exp + timedelta(seconds=offset))
    r = c.post(f"/sandboxes/{sid}/pause")
    gs, conts = settle(c, sid)
    line = f"pause offset={offset:+.2f} -> {r.status_code}; GET {gs} containers={conts}"
    bad = (gs == 404 and conts) or gs == 200
    if bad:
        FINDINGS.append(line + f" body={r.text[:200]} get={c.get(f'/sandboxes/{sid}').text[:200]}")
    log(("BAD " if bad else "ok  ") + line)
    if gs == 200:
        c.delete(f"/sandboxes/{sid}")


def concurrent_snapshots(c, policy, n=4):
    sid = c.post("/sandboxes", json=create_body(**policy)).json()["id"]
    wait_state(c, sid, {"Running"}, 90)
    with cf.ThreadPoolExecutor(n) as ex:
        rs = list(ex.map(lambda i: client(300).post(f"/sandboxes/{sid}/snapshots", json={"name": f"c{i}"}), range(n)))
    ids = [r.json()["id"] for r in rs if r.status_code == 202]
    states = {}
    for sn in ids:
        for _ in range(120):
            s = c.get(f"/snapshots/{sn}").json()["status"]
            if s["state"] in ("Ready", "Failed"):
                break
            time.sleep(1)
        states[sn] = (s["state"], s.get("message", "")[:80])
    g = c.get(f"/sandboxes/{sid}").json()["status"]["state"]
    imgs = snapshot_images()
    missing = [s for s, (st, _) in states.items() if st == "Ready" and f"opensandbox-snapshots:{s}" not in imgs]
    line = f"concurrent snapshots codes={[r.status_code for r in rs]} states={list(states.values())} sandbox={g} missing_images={missing}"
    bad = g != "Running" or missing or any(st not in ("Ready", "Failed") for st, _ in states.values())
    log(("BAD " if bad else "ok  ") + line)
    if bad:
        FINDINGS.append(line)
    # restore while deleting the snapshot
    if ids:
        body = create_body(**policy); body.pop("image"); body["snapshotId"] = ids[0]
        with cf.ThreadPoolExecutor(2) as ex:
            f1 = ex.submit(lambda: client(300).post("/sandboxes", json=body))
            time.sleep(0.05)
            f2 = ex.submit(lambda: client(300).delete(f"/snapshots/{ids[0]}"))
            r1, r2 = f1.result(), f2.result()
        restored = r1.json().get("id") if r1.status_code == 202 else None
        st = wait_state(c, restored, {"Running", "Failed"}, 90)["status"] if restored else None
        snap_after = c.get(f"/snapshots/{ids[0]}").status_code
        line = f"restore||delete-snapshot: restore={r1.status_code} {st and st['state']} delete={r2.status_code} snapshot_get={snap_after}"
        log("info " + line + f" {r2.text[:160]}")
        if restored:
            c.delete(f"/sandboxes/{restored}")
    for sn in ids:
        c.delete(f"/snapshots/{sn}")
    c.delete(f"/sandboxes/{sid}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ops", nargs="*", default=["renew", "snapshot", "delete", "pause", "concurrent"])
    ap.add_argument("--offsets", nargs="*", type=float, default=[-1.0, -0.4, -0.1, 0.0, 0.1, 0.3, 0.6, 1.0, 1.6])
    ap.add_argument("--egress", action="store_true", help="sandboxes with a networkPolicy (sidecar)")
    a = ap.parse_args()
    policy = {"networkPolicy": {"defaultAction": "allow"}} if a.egress else {}
    purge()
    imgs_before = set(snapshot_images())
    with server("docker-egress.toml" if a.egress else "docker.toml"):
        c = client(300)
        fns = {"renew": trial_renew, "snapshot": trial_snapshot, "delete": trial_delete, "pause": trial_pause}
        for op in a.ops:
            if op == "concurrent":
                concurrent_snapshots(c, policy)
                continue
            for off in a.offsets:
                try:
                    fns[op](c, off, policy)
                except Exception as e:  # noqa: BLE001
                    FINDINGS.append(f"{op} offset={off} EXC {e!r}")
                    log(f"EXC {op} {off} {e!r}")
        time.sleep(3)
        leftover_records = c.get("/snapshots", params={"pageSize": 200}).json()
    leaked = sorted(set(snapshot_images()) - imgs_before)
    log("snapshot records left:", json.dumps(leftover_records)[:400])
    log("snapshot images left:", leaked)
    log("inventory:", inventory())
    purge()
    print("\nFINDINGS:" if FINDINGS else "\nno findings", *FINDINGS, sep="\n  ")


if __name__ == "__main__":
    main()
