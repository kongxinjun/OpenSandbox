"""Hypothesis state machine over the lifecycle API on the real Docker runtime.

HUNT_EXAMPLES=20 HUNT_STEPS=15 hunt/.venv/bin/python -m pytest hunt/test_lifecycle_sm.py -x -s

A model tracks every sandbox the machine created (state, metadata, expiry).
Rules: create, delete, pause, resume, renew, patch metadata, list/filter,
snapshot, short-timeout expiry, and concurrent pairs of mutations on one sandbox.
After every step: GET agrees with the model and with the container on the
daemon, list totals and filters agree with the model, deleted sandboxes are 404
and have no containers left, and status codes match the documented ones.
"""
from __future__ import annotations

import concurrent.futures as cf
import os
import time
from datetime import datetime, timedelta, timezone

import pytest
from hypothesis import HealthCheck, settings, strategies as st
from hypothesis.stateful import Bundle, RuleBasedStateMachine, consumes, invariant, precondition, rule

from hunt.common import client, create_body, docker_client, purge, server

KEYS = st.sampled_from(["team", "env", "owner", "a.b", "x-y"])
VALS = st.text(alphabet="abcxyz019-_.", min_size=1, max_size=8).filter(lambda v: v[0].isalnum() and v[-1].isalnum())
DOC = {  # documented status codes per operation (lifecycle spec)
    "create": {202, 400, 409, 429, 500}, "delete": {204, 404, 409, 500},
    "pause": {202, 404, 409, 500}, "resume": {202, 404, 409, 500},
    "renew": {200, 400, 404, 409, 500}, "patch": {200, 400, 404, 409, 500},
    "snapshot": {202, 400, 404, 409, 500, 501},
}


@pytest.fixture(scope="module", autouse=True)
def live_server():
    purge()
    with server(log="/tmp/osb-hunt/server-sm.log"):
        yield
    purge()


class Lifecycle(RuleBasedStateMachine):
    sandboxes = Bundle("sandboxes")

    def __init__(self):
        super().__init__()
        self.c = client()
        self.dc = docker_client()
        self.model: dict[str, dict] = {}
        self.gone: set[str] = set()
        self.snapshots: set[str] = set()

    # --- helpers -------------------------------------------------------
    def expect(self, op, r, allowed):
        assert r.status_code in DOC[op], f"{op}: undocumented {r.status_code} {r.text[:200]}"
        assert r.status_code in allowed, f"{op}: expected {allowed}, got {r.status_code} {r.text[:300]}"
        if r.status_code >= 400:
            j = r.json()
            assert set(j) == {"code", "message"}, f"{op}: error body not ErrorResponse: {j}"

    def container_state(self, sid):
        cs = self.dc.containers.list(all=True, filters={"label": f"opensandbox.io/id={sid}"})
        if not cs:
            return None
        s = cs[0].attrs["State"]
        return "Paused" if s.get("Paused") else ("Running" if s.get("Running") else "Exited")

    def settle_expired(self):
        now = datetime.now(timezone.utc)
        for sid, m in list(self.model.items()):
            if m["expires"] and m["expires"] < now - timedelta(seconds=8):
                # Expiry is timer-driven; give it a moment, then it must be gone.
                self.model.pop(sid)
                self.gone.add(sid)

    # --- rules ---------------------------------------------------------
    @rule(target=sandboxes, meta=st.dictionaries(KEYS, VALS, max_size=3),
          short=st.booleans())
    def create(self, meta, short):
        if len(self.model) >= 4:
            return None
        r = self.c.post("/sandboxes", json=create_body(metadata=meta or None, timeout=600))
        self.expect("create", r, {202})
        j = r.json()
        sid = j["id"]
        assert j["status"]["state"] == "Running"
        assert j.get("metadata", {}) == meta or (not meta and not j.get("metadata"))
        exp = None
        if short:
            # timeout has a 60 s floor; renew may shorten, so use it for a quick expiry.
            soon = datetime.now(timezone.utc) + timedelta(seconds=5)
            rr = self.c.post(f"/sandboxes/{sid}/renew-expiration", json={"expiresAt": soon.isoformat()})
            self.expect("renew", rr, {200})
            exp = soon
        self.model[sid] = {"state": "Running", "meta": dict(meta), "expires": exp}
        return sid

    @rule(sid=consumes(sandboxes))
    def delete(self, sid):
        if sid is None:
            return
        r = self.c.delete(f"/sandboxes/{sid}")
        if sid in self.model:
            self.expect("delete", r, {204})
            self.model.pop(sid)
            self.gone.add(sid)
        else:
            self.expect("delete", r, {404, 204})
        r2 = self.c.delete(f"/sandboxes/{sid}")
        self.expect("delete", r2, {404})

    @rule(sid=sandboxes)
    def pause(self, sid):
        if sid is None or sid not in self.model:
            return
        r = self.c.post(f"/sandboxes/{sid}/pause")
        if self.model[sid]["state"] == "Running":
            self.expect("pause", r, {202})
            self.model[sid]["state"] = "Paused"
        else:
            self.expect("pause", r, {409})

    @rule(sid=sandboxes)
    def resume(self, sid):
        if sid is None or sid not in self.model:
            return
        r = self.c.post(f"/sandboxes/{sid}/resume")
        if self.model[sid]["state"] == "Paused":
            self.expect("resume", r, {202})
            self.model[sid]["state"] = "Running"
        else:
            self.expect("resume", r, {409})

    @rule(sid=sandboxes, delta=st.integers(-120, 1200))
    def renew(self, sid, delta):
        if sid is None or sid not in self.model:
            return
        when = datetime.now(timezone.utc) + timedelta(seconds=delta)
        r = self.c.post(f"/sandboxes/{sid}/renew-expiration", json={"expiresAt": when.isoformat()})
        if delta <= 0:
            self.expect("renew", r, {400})
            return
        self.expect("renew", r, {200})
        got = datetime.fromisoformat(r.json()["expiresAt"].replace("Z", "+00:00"))
        assert abs((got - when).total_seconds()) < 1
        self.model[sid]["expires"] = got if delta < 30 else None

    @rule(sid=sandboxes, patch=st.dictionaries(KEYS, st.one_of(st.none(), VALS), max_size=3))
    def patch_meta(self, sid, patch):
        if sid is None or sid not in self.model:
            return
        r = self.c.patch(f"/sandboxes/{sid}/metadata", json=patch)
        self.expect("patch", r, {200})
        m = self.model[sid]["meta"]
        for k, v in patch.items():
            if v is None:
                m.pop(k, None)
            else:
                m[k] = v
        assert (r.json().get("metadata") or {}) == m, (r.json().get("metadata"), m)

    @rule(sid=sandboxes)
    def snapshot(self, sid):
        if sid is None or sid not in self.model:
            return
        r = self.c.post(f"/sandboxes/{sid}/snapshots", json={})
        self.expect("snapshot", r, {202, 409, 501})
        if r.status_code == 202:
            snap = r.json()["id"]
            self.snapshots.add(snap)
            # Known (probe p03): docker commit freezes the container meanwhile. Wait it out.
            deadline = time.time() + 120
            while time.time() < deadline:
                ss = self.c.get(f"/snapshots/{snap}").json()["status"]["state"]
                if ss != "Creating":
                    break
                time.sleep(0.3)
            assert ss == "Ready", ss

    @rule(sid=sandboxes, pair=st.sampled_from([
        ("pause", "pause"), ("resume", "resume"), ("pause", "delete"), ("delete", "delete"),
        ("renew", "delete"), ("patch", "delete"), ("pause", "resume"), ("patch", "patch")]))
    def concurrent(self, sid, pair):
        if sid is None or sid not in self.model:
            return
        when = (datetime.now(timezone.utc) + timedelta(minutes=20)).isoformat()
        calls = {
            "pause": lambda: self.c.post(f"/sandboxes/{sid}/pause"),
            "resume": lambda: self.c.post(f"/sandboxes/{sid}/resume"),
            "delete": lambda: self.c.delete(f"/sandboxes/{sid}"),
            "renew": lambda: self.c.post(f"/sandboxes/{sid}/renew-expiration", json={"expiresAt": when}),
            "patch": lambda: self.c.patch(f"/sandboxes/{sid}/metadata", json={"team": "conc"}),
        }
        with cf.ThreadPoolExecutor(2) as ex:
            futs = [ex.submit(calls[p]) for p in pair]
            res = [f.result() for f in futs]
        codes = [r.status_code for r in res]
        for p, r in zip(pair, res):
            assert r.status_code < 500, f"concurrent {pair}: {p} -> {r.status_code} {r.text[:300]}"
            op = "patch" if p == "patch" else p
            assert r.status_code in DOC[op], f"concurrent {pair}: {p} undocumented {r.status_code}"
        # Re-derive the model from what the server now reports.
        g = self.c.get(f"/sandboxes/{sid}")
        if g.status_code == 404:
            assert "delete" in pair, f"{pair} {codes}: sandbox vanished"
            self.model.pop(sid)
            self.gone.add(sid)
            return
        state = g.json()["status"]["state"]
        if "delete" in pair:
            assert False, f"{pair} {codes}: delete returned but sandbox still {state}"
        if pair == ("pause", "pause"):
            assert sorted(codes) == [202, 409] or self.model[sid]["state"] == "Paused", codes
        self.model[sid]["state"] = state
        if "patch" in pair:
            self.model[sid]["meta"]["team"] = "conc"
        if "renew" in pair:
            self.model[sid]["expires"] = None

    # --- invariants ----------------------------------------------------
    @invariant()
    def agrees(self):
        self.settle_expired()
        for sid, m in self.model.items():
            r = self.c.get(f"/sandboxes/{sid}")
            if r.status_code == 404 and m["expires"]:
                continue
            assert r.status_code == 200, (sid, r.status_code, r.text[:200])
            j = r.json()
            state = j["status"]["state"]
            if state != m["state"] and m["expires"] and datetime.now(timezone.utc) > m["expires"]:
                continue
            assert state == m["state"], (sid, state, m)
            assert (j.get("metadata") or {}) == m["meta"], (sid, j.get("metadata"), m["meta"])
            cs = self.container_state(sid)
            assert cs == m["state"], f"{sid}: API {state} but container {cs}"
        for sid in self.gone:
            r = self.c.get(f"/sandboxes/{sid}")
            if r.status_code != 404:
                assert False, f"deleted/expired {sid} still answers {r.status_code} {r.text[:200]}"
            assert self.container_state(sid) is None, f"deleted {sid} container left"

    @invariant()
    def listing(self):
        r = self.c.get("/sandboxes", params={"pageSize": 200})
        assert r.status_code == 200
        listed = {i["id"]: i for i in r.json()["items"]}
        pg = r.json()["pagination"]
        assert pg["totalItems"] == len(listed), pg
        for sid, m in self.model.items():
            if m["expires"]:
                continue
            assert sid in listed, f"{sid} missing from list"
        for sid in self.gone:
            assert sid not in listed, f"deleted {sid} still listed"
        for st_name in ("Running", "Paused"):
            r = self.c.get("/sandboxes", params={"state": st_name, "pageSize": 200})
            ids = {i["id"] for i in r.json()["items"]}
            for sid, m in self.model.items():
                if m["expires"]:
                    continue
                assert (sid in ids) == (m["state"] == st_name), (st_name, sid, m["state"])
        # metadata filter
        for sid, m in self.model.items():
            if m["meta"] and not m["expires"]:
                k, v = next(iter(m["meta"].items()))
                r = self.c.get("/sandboxes", params={"metadata": f"{k}={v}", "pageSize": 200})
                ids = {i["id"] for i in r.json()["items"]}
                assert sid in ids, f"metadata filter {k}={v} misses {sid}"
                break

    def teardown(self):
        for sid in list(self.model):
            self.c.delete(f"/sandboxes/{sid}")
        for snap in self.snapshots:
            self.c.delete(f"/snapshots/{snap}")
        purge(self.dc)


Lifecycle.TestCase.settings = settings(
    max_examples=int(os.environ.get("HUNT_EXAMPLES", "10")),
    stateful_step_count=int(os.environ.get("HUNT_STEPS", "12")),
    deadline=None,
    suppress_health_check=list(HealthCheck),
)
TestLifecycle = Lifecycle.TestCase
