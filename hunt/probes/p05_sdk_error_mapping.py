"""P05: how the Python SDK surfaces server errors that are not ErrorResponse-shaped.

The server answers request-validation failures with FastAPI's 422 {"detail": [...]}
(spec: 400 ErrorResponse) and malformed bodies with 400 {"detail": "..."}.
Run with the SDK's own venv:
  hunt/.venv/bin/python -m hunt.probes.p05_sdk_error_mapping  (SDK installed editable into hunt/.venv)
"""
import asyncio
import os
import sys
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from hunt.common import API_KEY, PORT, create_body, log, server  # noqa: E402

from opensandbox import Sandbox  # noqa: E402
from opensandbox.config import ConnectionConfig  # noqa: E402


async def main():
    cfg = ConnectionConfig(api_key=API_KEY, domain=f"127.0.0.1:{PORT}", request_timeout=timedelta(seconds=60))
    cases = {
        "timeout below 60s (server 422)": dict(timeout=timedelta(seconds=10)),
        "bad resource value (server 400 ErrorResponse)": dict(resource={"cpu": "lots"}),
    }
    for name, kw in cases.items():
        try:
            sb = await Sandbox.create(image="busybox:latest", entrypoint=["sh", "-c", "sleep 600"],
                                      connection_config=cfg, skip_health_check=True, **kw)
            log(name, "-> created?!", sb.id)
            await sb.kill()
        except Exception as e:  # noqa: BLE001
            err = getattr(e, "error", None)
            log(f"{name} -> {type(e).__name__}: {str(e)[:160]!r} | code={getattr(err, 'code', None)!r} "
                f"message={str(getattr(err, 'message', None))[:80]!r}")


with server(log="/tmp/osb-hunt/server-p05.log"):
    asyncio.run(main())
