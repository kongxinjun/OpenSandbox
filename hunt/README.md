# hunt/ — bug-hunting harness for OpenSandbox

Not for upstream. Lives on the fork's `hunt/harness` branch only.

Everything runs against the **real** lifecycle server (Docker runtime) and a
locally built execd, on one Docker daemon. One hunt run at a time: the server
port is fixed and `purge()` removes every container labelled `opensandbox.io/id`.

## Setup

```bash
cd server && uv sync --all-groups && cd ..
uv venv --python 3.12 hunt/.venv
uv pip install --python hunt/.venv/bin/python schemathesis hypothesis httpx docker pyyaml pytest
uv pip install --python hunt/.venv/bin/python -e sdks/sandbox/python     # only for p05
hunt/execd-image/build.sh           # -> osb-hunt/execd:dev from this checkout
docker pull busybox:latest          # sandbox image used everywhere
```

`hunt/common.py` defaults `DOCKER_HOST` to Colima's socket; override it for
Docker Desktop. `HUNT_SERVER_DIR=<worktree>/server` runs a different server
checkout (used to verify fix branches with the same probes).

## Tools

| Command | What it does |
|---|---|
| `server/.venv/bin/python ../hunt/contract_diff.py` (from `server/`) | Static diff of `specs/sandbox-lifecycle.yml` against the server's own `app.openapi()`: operations, parameters, request/response schemas (required, defaults, enums, bounds), status codes. Mostly noise from schema style; useful as a checklist. |
| `hunt/.venv/bin/python -m hunt.run_st [st args]` | Starts the server, creates a live sandbox, runs schemathesis (`--checks all`, examples + coverage + fuzzing + stateful phases) over the lifecycle spec. Hooks (`hunt/st/hooks.py`) point 70% of `sandboxId` path params at the live sandbox and force `busybox` / no volumes on creates. |
| `hunt/.venv/bin/python -m hunt.run_st_execd [st args]` | Same, over `specs/execd-api.yaml`, against execd inside a real sandbox (direct host port). Jupyter and isolated-session routes are excluded. |
| `hunt/.venv/bin/python -m pytest hunt/test_lifecycle_sm.py` | Hypothesis state machine: create / delete / pause / resume / renew (incl. shortening to force expiry) / metadata merge-patch / snapshot / concurrent pairs on one sandbox. Invariants after every step: GET == model == container state on the daemon, list totals and `state` / `metadata` filters, deleted ⇒ 404 and no container, documented status codes, error bodies are `ErrorResponse`. `HUNT_EXAMPLES`, `HUNT_STEPS`. |
| `server/.venv/bin/python -m hunt.fault_sweep --op OP` | In-process `DockerSandboxService` on the real daemon; the k-th Docker Engine API request of OP is answered with a synthetic 500 (docker-py raises the real `APIError`), for every k. Then: no leaked containers / sidecars / auto-created volumes / reserved host ports, GET agrees with the daemon, the operation can be retried, final delete is clean. OPs: `create`, `create_pvc`, `delete`, `pause`, `resume`, `renew`. `--status 404` injects NotFound instead. |
| `hunt/.venv/bin/python -m hunt.probes.<name>` | Minimal reproductions, one per finding. |
| `hunt/.venv/bin/python -m hunt.smoke` | Create → endpoint → execd ping → pause → resume → delete. |

Kubernetes: `hunt/config/k8s.toml` runs the server against a kind cluster with
the controller started on the host (`go run ./kubernetes/cmd/controller`).

## Probes

| Probe | Finding |
|---|---|
| `p03_snapshot_reports_paused` | Docker snapshot (`docker commit`, pause=True) runs outside the lifecycle lock: GET says Paused, pause → 409, resume accepted mid-commit. Fixed on `fix/docker-snapshot-lifecycle-lock`. |
| `p04_restart_persistence` | Renewed expiry, metadata patch, pause and an expiry that passes while the server is down all survive a restart (no bug; kept as a regression check). |
| `p05_sdk_error_mapping` | Python SDK on 422 `{"detail": [...]}`: `SandboxApiException` with `code=UNEXPECTED_RESPONSE`, `message=None`. |

Security-relevant probes are kept out of this branch until disclosed privately.

## Results so far (2026-11-25, main `178cfe32f`)

* fault_sweep: pause / resume / renew / create (22 calls) clean; `create_pvc` leaks the auto-created volume when the inspect right after `create_volume` fails (k=3).
* schemathesis lifecycle: 404/405/400 framework errors return `{"detail": ...}` (fixed on `fix/error-response-framework-errors`); request validation answers 422 `{"detail": [...]}` where the spec says 400 `ErrorResponse`; `X-Request-ID` is a 32-hex string, spec says `format: uuid`.
* schemathesis execd: no crash in 1386 cases; client errors (empty path, unknown user, missing session) answered as 500 `RUNTIME_ERROR`.
* state machine: only the snapshot/pause interaction above.
