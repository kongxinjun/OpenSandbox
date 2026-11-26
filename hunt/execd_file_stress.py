"""Concurrent mixed filesystem operations against execd (pair with a -race build).

Random upload / download / mv / delete / info / list / search / replace / chmod /
mkdir on a small set of paths from many threads. Flags any 5xx whose message is
not a plain "file vanished under us" race, and checks every completed download
equals one of the blobs ever uploaded (no torn or mixed content).

    EXECD_BASE=http://127.0.0.1:45772 hunt/.venv/bin/python -m hunt.execd_file_stress --seconds 60
"""
from __future__ import annotations

import argparse
import collections
import concurrent.futures as cf
import json
import random
import threading
import time

from hunt.execd_probe import BASE, HDR, upload  # noqa: F401
import httpx

ROOT = "/tmp/osb-hunt/execd-host/stress"
NAMES = [f"{ROOT}/d{i}/f{j}.txt" for i in range(3) for j in range(4)]
BLOBS = [(f"blob-{k}-".encode() * (1 + k * 997))[: 1 + k * 7919] for k in range(12)]
stats = collections.Counter()
odd: list[str] = []
lock = threading.Lock()


def note(op, r):
    key = f"{op}:{r.status_code}"
    with lock:
        stats[key] += 1
        if r.status_code >= 500:
            msg = r.text[:200]
            benign = any(s in msg for s in ("no such file", "not exist", "ENOENT", "not found"))
            if not benign and len(odd) < 40:
                odd.append(f"{op} {r.status_code} {msg}")


def worker(seed, until):
    rnd = random.Random(seed)
    cl = httpx.Client(base_url=BASE, headers=HDR, timeout=60)
    while time.time() < until:
        p = rnd.choice(NAMES)
        op = rnd.choice(["up", "up", "down", "mv", "del", "info", "list", "search", "replace", "chmod", "mkdir", "rmdir"])
        try:
            if op == "up":
                note(op, upload(cl, p, rnd.choice(BLOBS)))
            elif op == "down":
                r = cl.get("/files/download", params={"path": p})
                note(op, r)
                if r.status_code == 200 and r.content not in BLOBS and b"REPLACED" not in r.content:
                    with lock:
                        odd.append(f"torn download {p} len={len(r.content)} head={r.content[:40]!r}")
            elif op == "mv":
                q = rnd.choice(NAMES)
                note(op, cl.post("/files/mv", json=[{"src": p, "dest": q}]))
            elif op == "del":
                note(op, cl.delete("/files", params={"path": p}))
            elif op == "info":
                note(op, cl.get("/files/info", params={"path": p}))
            elif op == "list":
                note(op, cl.get("/directories/list", params={"path": ROOT, "depth": 3}))
            elif op == "search":
                note(op, cl.get("/files/search", params={"path": ROOT, "pattern": "*.txt"}))
            elif op == "replace":
                note(op, cl.post("/files/replace", json={p: {"old": "blob", "new": "REPLACED"}}))
            elif op == "chmod":
                note(op, cl.post("/files/permissions", json={p: {"mode": rnd.choice([600, 644, 755])}}))
            elif op == "mkdir":
                note(op, cl.post("/directories", json={p.rsplit("/", 1)[0]: {"mode": 755}}))
            elif op == "rmdir":
                note(op, cl.delete("/directories", params={"path": p.rsplit("/", 1)[0]}))
        except httpx.HTTPError as e:
            with lock:
                stats[f"{op}:EXC"] += 1
                if len(odd) < 40:
                    odd.append(f"{op} EXC {e!r}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seconds", type=int, default=60)
    ap.add_argument("--threads", type=int, default=24)
    a = ap.parse_args()
    until = time.time() + a.seconds
    with cf.ThreadPoolExecutor(a.threads) as ex:
        list(ex.map(lambda s: worker(s, until), range(a.threads)))
    print(json.dumps(dict(sorted(stats.items())), indent=0))
    print("odd:", *odd, sep="\n  ")


if __name__ == "__main__":
    main()
