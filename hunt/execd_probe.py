"""Dynamic execd probes: streaming, background logs, files, disconnects, sessions.

Runs against any execd base URL, e.g. a `go build -race` execd on the host
(`EXECD_BASE=http://127.0.0.1:45772`) or execd inside a sandbox (direct port).
Each check prints PASS / FAIL with the evidence; FAILs are candidates, not bugs,
until reproduced by a minimal probe.

    hunt/.venv/bin/python -m hunt.execd_probe [--only NAME ...] [--workdir DIR]
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import hashlib
import json
import os
import socket
import time
import urllib.parse

import httpx

BASE = os.environ.get("EXECD_BASE", "http://127.0.0.1:45772")
TOKEN = os.environ.get("EXECD_TOKEN", "")
HDR = {"X-EXECD-ACCESS-TOKEN": TOKEN} if TOKEN else {}
WORK = "/tmp/osb-hunt/execd-host/work"
RESULTS: list[tuple[str, bool, str]] = []


def c(timeout=120.0) -> httpx.Client:
    return httpx.Client(base_url=BASE, headers=HDR, timeout=timeout)


def report(name: str, ok: bool, detail: str = ""):
    RESULTS.append((name, ok, detail))
    print(f"{'PASS' if ok else 'FAIL'} {name} {detail}"[:2000], flush=True)


def sse(cl: httpx.Client, path: str, body: dict) -> list[dict]:
    events = []
    with cl.stream("POST", path, json=body) as r:
        if r.status_code != 200:
            return [{"type": "_http", "status": r.status_code, "body": r.read().decode(errors="replace")}]
        for line in r.iter_lines():
            line = line.strip()
            if not line:
                continue
            if line.startswith("data:"):
                line = line[5:].strip()
            events.append(json.loads(line))
    return events


def joined(events, kind):
    return "".join(e.get("text", "") for e in events if e["type"] == kind)


def run(cmd, **kw):
    with c() as cl:
        return sse(cl, "/command", {"command": cmd, **kw})


# ---------------------------------------------------------------- streaming

def t_stream_integrity():
    n = 300000
    ev = run(f"seq 1 {n}")
    out = joined(ev, "stdout")
    want = "".join(f"{i}\n" for i in range(1, n + 1))
    report("stream_seq_integrity", out == want, f"len={len(out)} want={len(want)} types={sorted({e['type'] for e in ev})}")


def t_stream_interleave():
    ev = run("for i in $(seq 1 2000); do echo o$i; echo e$i >&2; done")
    o, e = joined(ev, "stdout"), joined(ev, "stderr")
    ok = o == "".join(f"o{i}\n" for i in range(1, 2001)) and e == "".join(f"e{i}\n" for i in range(1, 2001))
    report("stream_interleave", ok, f"o={len(o)} e={len(e)}")


def t_line_endings():
    ev = run(r"printf 'a\r\nb\rc\n\nlast'")
    out = joined(ev, "stdout")
    report("stream_line_endings", out == "a\r\nb\rc\n\nlast", repr(out))


def t_long_line():
    # > 16 MiB single line must be split and rejoin exactly.
    size = 17 * 1024 * 1024 + 123
    ev = run(f"head -c {size} /dev/zero | tr '\\0' 'x'; echo")
    out = joined(ev, "stdout")
    report("stream_long_line", out == "x" * size + "\n", f"len={len(out)} want={size + 1} events={sum(e['type'] == 'stdout' for e in ev)}")


def t_binary_output():
    ev = run("printf '\\xff\\xfe\\x00abc\\n'")
    out = joined(ev, "stdout")
    report("stream_binary_bytes", True, f"(informational) got={out!r}")


def t_exit_codes():
    ev0 = run("true")
    done = [e for e in ev0 if e["type"] == "execution_complete"]
    ok0 = bool(done) and done[-1].get("exit_code") == 0
    ev3 = run("exit 7")
    err = [e for e in ev3 if e["type"] == "error"]
    ok3 = bool(err) and err[-1]["error"].get("evalue") == "7"
    report("exit_codes", ok0 and ok3, f"ok={done[-1] if done else ev0} err={err[-1] if err else ev3}")


def t_timeout():
    t = time.time()
    ev = run("sleep 30", timeout=1000)
    dt = time.time() - t
    err = [e for e in ev if e["type"] == "error"]
    ok = dt < 5 and err and err[-1]["error"].get("ename") == "CommandTimeout"
    report("timeout_kills", bool(ok), f"dt={dt:.1f} last={ev[-1]}")


def t_timeout_kills_children():
    marker = f"osbchild{int(time.time()*1000)}"
    run(f"(sh -c 'sleep 60; echo {marker}' &) ; sleep 30", timeout=1000)
    time.sleep(0.5)
    ps = run(f"ps ax -o pid,command | grep {marker} | grep -v grep || true")
    left = joined(ps, "stdout").strip()
    report("timeout_kills_children", left == "", f"left={left!r} (informational: orphaned grandchildren)")


def t_concurrent_commands():
    def one(i):
        ev = run(f"for j in $(seq 1 200); do echo c{i}-$j; done")
        return i, joined(ev, "stdout")
    bad = []
    with cf.ThreadPoolExecutor(48) as ex:
        for i, out in ex.map(one, range(96)):
            if out != "".join(f"c{i}-{j}\n" for j in range(1, 201)):
                bad.append((i, len(out), out[:80]))
    report("concurrent_foreground", not bad, f"bad={bad[:3]}")


def t_disconnect_foreground():
    # Client walks away mid-stream: does the command keep running / leak?
    marker = f"osbdisc{int(time.time()*1000)}"
    with c() as cl:
        with cl.stream("POST", "/command", json={"command": f"sh -c 'while true; do echo {marker}; sleep 0.05; done'"}) as r:
            for i, _ in enumerate(r.iter_lines()):
                if i > 10:
                    break
    time.sleep(2)
    ps = run(f"ps ax -o pid,command | grep {marker} | grep -v grep || true")
    left = joined(ps, "stdout").strip()
    report("disconnect_kills_foreground", left == "", f"left={left[:200]!r}")
    if left:
        run(f"pkill -f {marker} || true")


# ---------------------------------------------------------------- background

def t_background_logs():
    n = 200000
    ev = run(f"seq 1 {n}; echo tail >&2", background=True)
    cid = next(e["text"] for e in ev if e["type"] == "init")
    with c() as cl:
        for _ in range(200):
            st = cl.get(f"/command/status/{cid}").json()
            if not st.get("running"):
                break
            time.sleep(0.05)
        got, cursor, polls = b"", 0, 0
        while True:
            r = cl.get(f"/command/{cid}/logs", params={"cursor": cursor})
            polls += 1
            nxt = int(r.headers.get("EXECD-COMMANDS-TAIL-CURSOR", "-1"))
            got += r.content
            if nxt == cursor or polls > 50:
                break
            if nxt < cursor:
                report("background_cursor_monotonic", False, f"{cursor}->{nxt}")
                break
            cursor = nxt
        want = "".join(f"{i}\n" for i in range(1, n + 1)) + "tail\n"
        report("background_logs_complete", got.decode() == want, f"got={len(got)} want={len(want)} status={st} polls={polls}")
        # cursor past the end
        r = cl.get(f"/command/{cid}/logs", params={"cursor": 10**12})
        report("background_cursor_past_end", r.status_code in (200, 400, 416), f"{r.status_code} {r.text[:100]} hdr={r.headers.get('EXECD-COMMANDS-TAIL-CURSOR')}")
        r = cl.get(f"/command/{cid}/logs", params={"cursor": -1})
        report("background_cursor_negative", r.status_code == 400, f"{r.status_code} {r.text[:100]}")


def t_background_incremental():
    ev = run("for i in $(seq 1 30); do echo L$i; sleep 0.05; done", background=True)
    cid = next(e["text"] for e in ev if e["type"] == "init")
    got, cursor = "", 0
    with c() as cl:
        deadline = time.time() + 20
        while time.time() < deadline:
            r = cl.get(f"/command/{cid}/logs", params={"cursor": cursor})
            got += r.text
            cursor = int(r.headers["EXECD-COMMANDS-TAIL-CURSOR"])
            st = cl.get(f"/command/status/{cid}").json()
            if not st["running"]:
                r = cl.get(f"/command/{cid}/logs", params={"cursor": cursor})
                got += r.text
                break
            time.sleep(0.03)
    want = "".join(f"L{i}\n" for i in range(1, 31))
    report("background_incremental_polls", got == want, f"got={got!r}"[:300])


def t_interrupt():
    ev = run("sleep 60", background=True)
    cid = next(e["text"] for e in ev if e["type"] == "init")
    with c() as cl:
        r = cl.delete("/command", params={"id": cid})
        time.sleep(1)
        st = cl.get(f"/command/status/{cid}").json()
        report("interrupt_background", r.status_code == 200 and not st["running"], f"{r.status_code} {st}")
        r = cl.delete("/command", params={"id": "nope-" + cid})
        report("interrupt_unknown_id", r.status_code in (400, 404), f"{r.status_code} {r.text[:120]}")


def t_interrupt_foreground():
    with c() as cl, cf.ThreadPoolExecutor(1) as ex:
        holder = {}

        def go():
            evs = []
            with cl.stream("POST", "/command", json={"command": "sleep 60"}) as r:
                for line in r.iter_lines():
                    if line.strip():
                        e = json.loads(line)
                        evs.append(e)
                        if e["type"] == "init":
                            holder["id"] = e["text"]
            return evs
        fut = ex.submit(go)
        for _ in range(50):
            if "id" in holder:
                break
            time.sleep(0.05)
        t = time.time()
        with c() as c2:
            r = c2.delete("/command", params={"id": holder["id"]})
        evs = fut.result(timeout=20)
        report("interrupt_foreground_ends_stream", time.time() - t < 5, f"{r.status_code} last={evs[-1]}")


# ---------------------------------------------------------------- files

def upload(cl, path, data: bytes, extra_meta=None):
    meta = {"path": path, **(extra_meta or {})}
    files = [("metadata", ("metadata", json.dumps(meta), "application/json")),
             ("file", ("f", data, "application/octet-stream"))]
    return cl.post("/files/upload", files=files)


def t_upload_download_large():
    data = os.urandom(64 * 1024 * 1024)
    p = f"{WORK}/big.bin"
    with c(600) as cl:
        r = upload(cl, p, data)
        h = hashlib.sha256()
        n = 0
        with cl.stream("GET", "/files/download", params={"path": p}) as d:
            for chunk in d.iter_bytes():
                h.update(chunk)
                n += len(chunk)
            cl_hdr = d.headers.get("content-length")
        report("upload_download_64MiB", r.status_code == 200 and h.hexdigest() == hashlib.sha256(data).hexdigest(),
               f"up={r.status_code} n={n} cl={cl_hdr}")


def t_ranges():
    data = bytes(range(256)) * 40
    p = f"{WORK}/range.bin"
    with c() as cl:
        upload(cl, p, data)
        cases = {
            "bytes=0-0": (206, data[0:1]),
            "bytes=10-19": (206, data[10:20]),
            "bytes=-10": (206, data[-10:]),
            "bytes=10200-": (206, data[10200:]),
            "bytes=0-99999": (206, data[0:]),
            f"bytes={len(data)}-": (416, None),
            "bytes=5-2": (416, None),
            "bytes=abc": (416, None),
        }
        bad = []
        for rng, (st, body) in cases.items():
            r = cl.get("/files/download", params={"path": p}, headers={"Range": rng})
            if r.status_code != st or (body is not None and r.content != body):
                bad.append((rng, r.status_code, len(r.content), r.headers.get("content-range"), r.text[:80] if r.status_code >= 400 else ""))
            elif st == 416 and "json" not in r.headers.get("content-type", ""):
                bad.append((rng, "416-not-json", r.headers.get("content-type"), r.text[:80]))
        r = cl.get("/files/download", params={"path": p}, headers={"Range": "bytes=0-1,5-6"})
        report("download_ranges", not bad, f"bad={bad} multi={r.status_code},{r.headers.get('content-type')}")


def t_line_read():
    p = f"{WORK}/lines.txt"
    with c() as cl:
        upload(cl, p, b"".join(b"line%d\n" % i for i in range(1, 101)))
        r = cl.get("/files/download", params={"path": p, "offset": 98, "limit": 5})
        r2 = cl.get("/files/download", params={"path": p, "offset": 200, "limit": 5})
        r3 = cl.get("/files/download", params={"path": p, "offset": 1, "limit": 1}, headers={"Range": "bytes=0-1"})
        report("download_line_read", r.text == "line98\nline99\nline100\n", f"{r.status_code} {r.text!r} past_end={r2.status_code}:{r2.text[:60]!r} with_range={r3.status_code}")


def raw_upload_disconnect(path: str, declared: int, send: int):
    """Multipart upload over a raw socket that stops after `send` body bytes."""
    u = urllib.parse.urlparse(BASE)
    boundary = "osbhuntboundary"
    meta = json.dumps({"path": path}).encode()
    head = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"metadata\"; filename=\"metadata\"\r\n"
            f"Content-Type: application/json\r\n\r\n").encode() + meta + \
           (f"\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"f\"\r\n"
            f"Content-Type: application/octet-stream\r\n\r\n").encode()
    tail = f"\r\n--{boundary}--\r\n".encode()
    total = len(head) + declared + len(tail)
    s = socket.create_connection((u.hostname, u.port))
    req = (f"POST /files/upload HTTP/1.1\r\nHost: x\r\nContent-Type: multipart/form-data; boundary={boundary}\r\n"
           f"Content-Length: {total}\r\n" + "".join(f"{k}: {v}\r\n" for k, v in HDR.items()) + "\r\n").encode()
    s.sendall(req + head)
    chunk = b"N" * 65536
    sent = 0
    while sent < send:
        k = min(len(chunk), send - sent)
        s.sendall(chunk[:k])
        sent += k
    s.close()


def t_upload_disconnect_preserves():
    p = f"{WORK}/precious.txt"
    orig = b"ORIGINAL-CONTENT\n" * 1000
    with c() as cl:
        upload(cl, p, orig)
        for declared, send in [(1 << 20, 1 << 19), (100 << 20, 40 << 20)]:
            raw_upload_disconnect(p, declared, send)
            time.sleep(1)
            r = cl.get("/files/download", params={"path": p})
            if r.content != orig:
                report("upload_disconnect_preserves_target", False, f"declared={declared} sent={send} now={len(r.content)} head={r.content[:30]!r}")
                return
        leftovers = [f for f in os.listdir(WORK) if f.startswith(".osb-upload-")] if os.path.isdir(WORK) else "n/a"
        report("upload_disconnect_preserves_target", True, f"staging leftovers={leftovers}")


def t_download_disconnect():
    p = f"{WORK}/big.bin"
    pid = os.environ.get("EXECD_PID")
    before = len(os.listdir(f"/dev/fd")) if False else None
    with c() as cl:
        for _ in range(30):
            with cl.stream("GET", "/files/download", params={"path": p}) as d:
                for chunk in d.iter_bytes():
                    break
    time.sleep(1)
    if pid:
        import subprocess
        out = subprocess.run(["lsof", "-p", pid], capture_output=True, text=True).stdout
        n = out.count("big.bin")
        report("download_disconnect_closes_fds", n == 0, f"open big.bin fds={n}")
    else:
        report("download_disconnect_closes_fds", True, "skipped (no EXECD_PID)")


def t_upload_multi_partial():
    # Two pairs where the second is invalid: is the first written?
    p1 = f"{WORK}/multi-a.txt"
    with c() as cl:
        cl.delete("/files", params={"path": p1})
        files = [("metadata", ("metadata", json.dumps({"path": p1}), "application/json")),
                 ("file", ("f", b"A", "application/octet-stream")),
                 ("metadata", ("metadata", "not-json", "application/json")),
                 ("file", ("f", b"B", "application/octet-stream"))]
        r = cl.post("/files/upload", files=files)
        exists = cl.get("/files/info", params={"path": p1}).status_code
        report("upload_multi_partial_failure", True, f"(informational) status={r.status_code} first_written={exists == 200}")


def t_concurrent_upload_same_path():
    p = f"{WORK}/race.bin"
    blobs = [bytes([i]) * (2 << 20) for i in range(16)]
    with c(120) as cl:
        def up(b):
            with c(120) as c2:
                return upload(c2, p, b).status_code
        with cf.ThreadPoolExecutor(16) as ex:
            codes = list(ex.map(up, blobs))
        r = cl.get("/files/download", params={"path": p})
        whole = r.content in blobs
        report("concurrent_upload_same_path_atomic", whole and all(x == 200 for x in codes), f"codes={set(codes)} len={len(r.content)} mixed={not whole}")


# ---------------------------------------------------------------- sessions

def t_sessions():
    with c() as cl:
        sid = cl.post("/session", json={}).json()["session_id"]
        a = sse(cl, f"/session/{sid}/run", {"command": "export FOO=bar; cd /tmp"})
        b = sse(cl, f"/session/{sid}/run", {"command": "echo $FOO; pwd"})
        out = joined(b, "stdout")
        report("session_state_persists", "bar" in out and "/tmp" in out, repr(out))
        # concurrent runs in the same session
        def r1(i):
            with c() as c2:
                return joined(sse(c2, f"/session/{sid}/run", {"command": f"sleep 0.3; echo s{i}"}), "stdout")
        with cf.ThreadPoolExecutor(4) as ex:
            outs = list(ex.map(r1, range(4)))
        report("session_concurrent_runs", all(o.strip() == f"s{i}" for i, o in enumerate(outs)), f"outs={outs}")
        # exit inside session
        e = sse(cl, f"/session/{sid}/run", {"command": "exit 3"})
        after = sse(cl, f"/session/{sid}/run", {"command": "echo alive"})
        report("session_survives_exit", True, f"(informational) exit_events={[x['type'] for x in e]} after={[x.get('text', x.get('status')) for x in after][:4]}")
        d = cl.delete(f"/session/{sid}")
        d2 = cl.delete(f"/session/{sid}")
        r = sse(cl, f"/session/{sid}/run", {"command": "echo x"})
        report("session_delete_semantics", d.status_code == 200 and d2.status_code == 404 and r[0].get("status") in (404, 400),
               f"del={d.status_code} del2={d2.status_code} run_after={r[0]}")


def t_session_timeout():
    with c() as cl:
        sid = cl.post("/session", json={}).json()["session_id"]
        t = time.time()
        ev = sse(cl, f"/session/{sid}/run", {"command": "sleep 30", "timeout": 1000})
        dt = time.time() - t
        after = sse(cl, f"/session/{sid}/run", {"command": "echo alive"})
        report("session_timeout", dt < 5, f"dt={dt:.1f} last={ev[-1]} after={joined(after, 'stdout')!r}")
        cl.delete(f"/session/{sid}")


def t_session_delete_while_running():
    with c() as cl, cf.ThreadPoolExecutor(1) as ex:
        sid = cl.post("/session", json={}).json()["session_id"]
        fut = ex.submit(lambda: sse(c(), f"/session/{sid}/run", {"command": "sleep 20; echo done"}))
        time.sleep(0.5)
        t = time.time()
        d = cl.delete(f"/session/{sid}")
        try:
            ev = fut.result(timeout=30)
        except Exception as e:  # noqa: BLE001
            ev = [{"type": "_exc", "text": repr(e)}]
        report("session_delete_while_running", time.time() - t < 5, f"del={d.status_code} dt={time.time()-t:.1f} last={ev[-1]}")


def t_many_sessions():
    def one(i):
        with c() as cl:
            sid = cl.post("/session", json={}).json()["session_id"]
            o = joined(sse(cl, f"/session/{sid}/run", {"command": f"X={i}; echo $X"}), "stdout")
            cl.delete(f"/session/{sid}")
            return i, o
    with cf.ThreadPoolExecutor(32) as ex:
        bad = [(i, o) for i, o in ex.map(one, range(64)) if o.strip() != str(i)]
    report("many_concurrent_sessions", not bad, f"bad={bad[:5]}")


TESTS = {k[2:]: v for k, v in dict(globals()).items() if k.startswith("t_")}


def main():
    global WORK
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", nargs="*")
    ap.add_argument("--workdir", default=WORK)
    a = ap.parse_args()
    WORK = a.workdir
    for name, fn in TESTS.items():
        if a.only and name not in a.only:
            continue
        try:
            fn()
        except Exception as e:  # noqa: BLE001
            report(name, False, f"EXC {e!r}")
    fails = [r for r in RESULTS if not r[1]]
    print(f"\n{len(RESULTS) - len(fails)} pass, {len(fails)} fail")


if __name__ == "__main__":
    main()
