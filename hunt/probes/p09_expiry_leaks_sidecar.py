"""Docker: an operation racing expiry leaves the egress sidecar behind.

Shortens a networkPolicy sandbox's expiry to 4 s, fires OP at expiry+OFFSET,
then after the sandbox is 404 waits WAIT seconds and lists containers labelled
opensandbox.io/egress-sidecar-for=<id>.

    hunt/.venv/bin/python -m hunt.probes.p09_expiry_leaks_sidecar [--op pause] [--trials 6]
"""
import argparse
import time
from datetime import datetime, timedelta, timezone

from hunt.common import client, create_body, docker_client, log, purge, server, wait_state


def sidecars(sid):
    return [(x.name, x.status) for x in docker_client().containers.list(
        all=True, filters={"label": f"opensandbox.io/egress-sidecar-for={sid}"})]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--op", default="pause", choices=["pause", "snapshot", "resume", "none"])
    ap.add_argument("--trials", type=int, default=6)
    ap.add_argument("--wait", type=float, default=30)
    ap.add_argument("--offsets", nargs="*", type=float, default=[-0.5, -0.3, -0.2, -0.1, 0.0, 0.1])
    a = ap.parse_args()
    purge()
    leaked = []
    with server("docker-egress.toml"):
        c = client(300)
        for i in range(a.trials):
            off = a.offsets[i % len(a.offsets)]
            sid = c.post("/sandboxes", json=create_body(networkPolicy={"defaultAction": "allow"})).json()["id"]
            wait_state(c, sid, {"Running"}, 90)
            if a.op == "resume":
                c.post(f"/sandboxes/{sid}/pause"); wait_state(c, sid, {"Paused"})
            exp = datetime.fromisoformat(c.post(f"/sandboxes/{sid}/renew-expiration", json={
                "expiresAt": (datetime.now(timezone.utc) + timedelta(seconds=4)).isoformat()}).json()["expiresAt"].replace("Z", "+00:00"))
            time.sleep(max(0, (exp - datetime.now(timezone.utc)).total_seconds() + off))
            code = None
            if a.op == "pause":
                code = c.post(f"/sandboxes/{sid}/pause").status_code
            elif a.op == "resume":
                code = c.post(f"/sandboxes/{sid}/resume").status_code
            elif a.op == "snapshot":
                code = c.post(f"/sandboxes/{sid}/snapshots", json={}).status_code
            wait_state(c, sid, {"<404>"}, 60)
            time.sleep(a.wait)
            sc = sidecars(sid)
            log(f"trial {i} offset={off:+.1f} {a.op}->{code}: sandbox 404, after {a.wait:.0f}s sidecars={sc}")
            if sc:
                leaked.append((sid, sc))
    log(f"leaked sidecars: {len(leaked)}/{a.trials}", leaked)
    for sid, _ in leaked:
        for x in docker_client().containers.list(all=True, filters={"label": f"opensandbox.io/egress-sidecar-for={sid}"}):
            x.remove(force=True)
    purge()


if __name__ == "__main__":
    main()
