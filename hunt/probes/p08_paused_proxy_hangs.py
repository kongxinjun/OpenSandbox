"""Docker: proxied calls to a Paused sandbox hang until the shared client's 180 s
read timeout (then 504), holding one of the shared pool's 100 connections each.

    hunt/.venv/bin/python -m hunt.probes.p08_paused_proxy_hangs [--flood 100]
"""
import argparse
import asyncio
import time

import httpx

from hunt.common import API_KEY, BASE, client, create_body, log, purge, server, wait_state


async def main(flood: int, wait: float):
    with server("docker-egress.toml"):
        c = client(600)
        pol = {"defaultAction": "deny", "egress": [{"action": "allow", "target": "example.com"}]}
        paused = c.post("/sandboxes", json=create_body(networkPolicy=pol)).json()["id"]
        running = c.post("/sandboxes", json=create_body(networkPolicy=pol)).json()["id"]
        wait_state(c, paused, {"Running"}, 90); wait_state(c, running, {"Running"}, 90)
        t = time.time(); r = c.get(f"/sandboxes/{running}/networkpolicy")
        log(f"baseline running GET networkpolicy: {r.status_code} in {time.time()-t:.2f}s")
        c.post(f"/sandboxes/{paused}/pause"); wait_state(c, paused, {"Paused"})
        async with httpx.AsyncClient(base_url=BASE, headers={"OPEN-SANDBOX-API-KEY": API_KEY},
                                     timeout=400, limits=httpx.Limits(max_connections=flood + 10)) as ac:
            hung = [asyncio.create_task(ac.get(f"/sandboxes/{paused}/networkpolicy")) for _ in range(flood)]
            await asyncio.sleep(wait)
            t = time.time()
            r = await ac.get(f"/sandboxes/{running}/networkpolicy")
            log(f"running sandbox GET networkpolicy while {flood} calls hang on the paused one: "
                f"{r.status_code} in {time.time()-t:.1f}s {r.text[:160]}")
            done = await asyncio.gather(*hung, return_exceptions=True)
            codes = {}
            for x in done:
                k = getattr(x, "status_code", repr(x)[:40]); codes[k] = codes.get(k, 0) + 1
            log(f"paused sandbox calls: {codes} (total {time.time()-t:.0f}s)")
        for s in (paused, running):
            c.delete(f"/sandboxes/{s}")
    purge()


if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("--flood", type=int, default=100); ap.add_argument("--wait", type=float, default=3)
    a = ap.parse_args()
    purge()
    asyncio.run(main(a.flood, a.wait))
