"""Egress sidecar on the Docker runtime: enforcement and policy API edge cases.

Needs `hunt/egress-image/build.sh` (osb-hunt/egress:dev) and outbound internet
from the Docker VM. Runs the server with hunt/config/docker-egress.toml.

    hunt/.venv/bin/python -m hunt.egress_probe [--only NAME ...]
"""
from __future__ import annotations

import argparse
import json
import time

from hunt.common import client, create_body, docker_client, inventory, log, purge, server, wait_state

RESULTS: list[tuple[str, bool, str]] = []
ALLOWED = "example.com"
DENIED = "www.wikipedia.org"


def report(name, ok, detail=""):
    RESULTS.append((name, ok, detail))
    print(f"{'PASS' if ok else 'FAIL'} {name} {detail}"[:3000], flush=True)


def sh(sid: str, cmd: str, timeout=20) -> tuple[int, str]:
    dc = docker_client()
    main = [c for c in dc.containers.list(filters={"label": f"opensandbox.io/id={sid}"})
            if "egress" not in c.name]
    res = main[0].exec_run(["sh", "-c", f"timeout {timeout} sh -c '{cmd}'"], demux=False)
    return res.exit_code, (res.output or b"").decode(errors="replace")


def reach(sid, host, port=80) -> bool:
    code, _ = sh(sid, f"nc -z -w 3 {host} {port}", timeout=8)
    return code == 0


def resolves(sid, host) -> bool:
    code, out = sh(sid, f"nslookup {host}", timeout=8)
    return code == 0 and "Address" in out.split("Name:", 1)[-1]


def new_sandbox(c, policy, **over):
    r = c.post("/sandboxes", json=create_body(networkPolicy=policy, **over))
    if r.status_code != 202:
        raise RuntimeError(f"create {r.status_code} {r.text[:400]}")
    sid = r.json()["id"]
    wait_state(c, sid, {"Running"}, timeout=90)
    return sid


def t_basic_enforcement(c):
    sid = new_sandbox(c, {"defaultAction": "deny", "egress": [{"action": "allow", "target": ALLOWED}]})
    a, d = reach(sid, ALLOWED), reach(sid, DENIED)
    report("deny_default_allow_one", a and not d, f"allowed={a} denied_reachable={d}")
    g = c.get(f"/sandboxes/{sid}/networkpolicy")
    report("get_policy_shape", g.status_code == 200, f"{g.status_code} {g.text[:300]}")
    return sid


def t_patch_semantics(c, sid):
    base = c.get(f"/sandboxes/{sid}/networkpolicy").json()
    r = c.patch(f"/sandboxes/{sid}/networkpolicy", json=[
        {"action": "deny", "target": ALLOWED},
        {"action": "allow", "target": ALLOWED},   # same target later in payload: first wins
        {"action": "allow", "target": "1.1.1.1"},
    ])
    body = r.json() if r.headers.get("content-type", "").startswith("application/json") else r.text
    log("patch ->", r.status_code, json.dumps(body)[:600])
    g = c.get(f"/sandboxes/{sid}/networkpolicy").json()
    log("after patch GET", json.dumps(g)[:600])
    rules = (g.get("policy") or g).get("egress") or []
    tgt = [(x.get("target"), x.get("action")) for x in rules]
    ok = (ALLOWED, "deny") in tgt and (ALLOWED, "allow") not in tgt and ("1.1.1.1", "allow") in tgt
    report("patch_first_in_payload_wins_and_replaces_in_place", r.status_code == 200 and ok, f"rules={tgt} base={json.dumps(base)[:200]}")
    report("patch_enforced_deny", not reach(sid, ALLOWED), "")
    report("patch_enforced_ip_allow", reach(sid, "1.1.1.1", 80), "")


def t_put_replace(c, sid):
    r = c.put(f"/sandboxes/{sid}/networkpolicy", json={"defaultAction": "allow", "egress": [{"action": "deny", "target": DENIED}]})
    log("put ->", r.status_code, r.text[:400])
    a, d = reach(sid, ALLOWED), reach(sid, DENIED)
    report("put_replace_enforced", r.status_code == 200 and a and not d, f"allowed={a} denied_reachable={d}")


def t_validation_edges(c, sid):
    cases = {
        "empty_target_no_ports": [{"action": "allow"}],
        "ports_only": [{"action": "allow", "ports": [443]}],
        "port_0": [{"action": "allow", "target": "a.example", "ports": [0]}],
        "port_65536": [{"action": "allow", "target": "a.example", "ports": [65536]}],
        "dup_ports": [{"action": "allow", "target": "a.example", "ports": [80, 80]}],
        "257_ports": [{"action": "allow", "target": "a.example", "ports": list(range(1, 258))}],
        "wild_bare": [{"action": "allow", "target": "*"}],
        "wild_dot": [{"action": "allow", "target": "*."}],
        "double_wild": [{"action": "allow", "target": "*.*.example.com"}],
        "trailing_dot": [{"action": "allow", "target": "example.org."}],
        "upper": [{"action": "allow", "target": "EXAMPLE.NET"}],
        "cidr_all": [{"action": "allow", "target": "0.0.0.0/0"}],
        "cidr_bad": [{"action": "allow", "target": "10.0.0.0/33"}],
        "ipv6": [{"action": "allow", "target": "2606:4700:4700::1111"}],
        "ipv6_cidr": [{"action": "allow", "target": "::/0"}],
        "url_target": [{"action": "allow", "target": "http://example.com/x"}],
        "space": [{"action": "allow", "target": " example.com "}],
        "unicode": [{"action": "allow", "target": "bücher.example"}],
        "bad_action": [{"action": "maybe", "target": "a.example"}],
        "very_long": [{"action": "allow", "target": ("a" * 63 + ".") * 5 + "com"}],
        "empty_patch": [],
    }
    rows = []
    for name, rules in cases.items():
        r = c.patch(f"/sandboxes/{sid}/networkpolicy", json=rules)
        body = r.text[:160]
        rows.append((name, r.status_code, body))
        if r.status_code >= 500:
            report(f"validate_{name}", False, f"{r.status_code} {body}")
    log("validation matrix:")
    for row in rows:
        log("  ", *row)
    report("validation_no_5xx", all(s < 500 for _, s, _ in rows), "")
    g = c.get(f"/sandboxes/{sid}/networkpolicy")
    report("policy_readable_after_edges", g.status_code == 200, f"{g.status_code} {g.text[:200]}")


def t_pause_resume_keeps_policy(c):
    sid = new_sandbox(c, {"defaultAction": "deny", "egress": [{"action": "allow", "target": ALLOWED}]})
    c.patch(f"/sandboxes/{sid}/networkpolicy", json=[{"action": "allow", "target": "1.1.1.1"}])
    before = c.get(f"/sandboxes/{sid}/networkpolicy").json()
    c.post(f"/sandboxes/{sid}/pause"); wait_state(c, sid, {"Paused"})
    pp = c.get(f"/sandboxes/{sid}/networkpolicy")
    pt = c.patch(f"/sandboxes/{sid}/networkpolicy", json=[{"action": "allow", "target": "8.8.8.8"}])
    c.post(f"/sandboxes/{sid}/resume"); wait_state(c, sid, {"Running"})
    time.sleep(1)
    after = c.get(f"/sandboxes/{sid}/networkpolicy").json()
    a, d, ip = reach(sid, ALLOWED), reach(sid, DENIED), reach(sid, "1.1.1.1")
    report("pause_resume_keeps_runtime_policy", before == after and a and ip and not d,
           f"paused_get={pp.status_code} paused_patch={pt.status_code}:{pt.text[:120]} same={before == after} allowed={a} ip={ip} denied={d}")
    return sid


def t_restart_sidecar(c):
    sid = new_sandbox(c, {"defaultAction": "deny", "egress": [{"action": "allow", "target": ALLOWED}]})
    c.patch(f"/sandboxes/{sid}/networkpolicy", json=[{"action": "allow", "target": "1.1.1.1"}])
    dc = docker_client()
    eg = dc.containers.list(filters={"label": f"opensandbox.io/egress-sidecar-for={sid}"})
    if not eg:
        report("sidecar_restart", False, "no sidecar container found: " + str(inventory()))
        return
    eg[0].restart(timeout=5)
    time.sleep(4)
    g = c.get(f"/sandboxes/{sid}/networkpolicy")
    ip, d = reach(sid, "1.1.1.1"), reach(sid, DENIED)
    report("sidecar_restart_keeps_runtime_patch", g.status_code == 200 and ip and not d,
           f"(informational if policy persistence is off) get={g.status_code} {g.text[:240]} ip={ip} denied_reachable={d}")


def t_snapshot_restore_policy(c):
    sid = new_sandbox(c, {"defaultAction": "deny", "egress": [{"action": "allow", "target": ALLOWED}]})
    r = c.post(f"/sandboxes/{sid}/snapshots", json={"name": "egress-snap"})
    if r.status_code not in (200, 201, 202):
        report("snapshot_with_policy", False, f"{r.status_code} {r.text[:200]}")
        return
    snap = r.json()["id"]
    for _ in range(120):
        s = c.get(f"/snapshots/{snap}").json()
        if s.get("status", {}).get("state") in ("Ready", "Failed"):
            break
        time.sleep(1)
    log("snapshot", json.dumps(s)[:300])
    body = create_body(networkPolicy={"defaultAction": "deny", "egress": [{"action": "allow", "target": "1.1.1.1"}]})
    body.pop("image")
    body["snapshotId"] = snap
    r2 = c.post("/sandboxes", json=body)
    log("restore", r2.status_code, r2.text[:300])
    if r2.status_code == 202:
        sid2 = r2.json()["id"]
        wait_state(c, sid2, {"Running"}, timeout=90)
        ip, a = reach(sid2, "1.1.1.1"), reach(sid2, ALLOWED)
        report("restore_uses_new_policy", ip and not a, f"ip={ip} old_allowed_reachable={a}")
    c.delete(f"/snapshots/{snap}")


TESTS = ["basic", "pause", "restart", "snapshot"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", nargs="*")
    a = ap.parse_args()
    purge()
    with server("docker-egress.toml"):
        c = client(180)
        want = set(a.only or TESTS)
        if "basic" in want:
            sid = t_basic_enforcement(c)
            t_patch_semantics(c, sid)
            t_put_replace(c, sid)
            t_validation_edges(c, sid)
        for name, fn in [("pause", t_pause_resume_keeps_policy), ("restart", t_restart_sidecar),
                         ("snapshot", t_snapshot_restore_policy)]:
            if name in want:
                try:
                    fn(c)
                except Exception as e:  # noqa: BLE001
                    report(name, False, f"EXC {e!r}")
        for s in c.get("/sandboxes", params={"pageSize": 100}).json().get("items", []):
            c.delete(f"/sandboxes/{s['id']}")
    time.sleep(2)
    log("inventory after:", inventory())
    purge()
    fails = [r for r in RESULTS if not r[1]]
    print(f"\n{len(RESULTS) - len(fails)} pass, {len(fails)} fail")


if __name__ == "__main__":
    main()
