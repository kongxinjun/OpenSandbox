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
| `EXECD_BASE=... hunt/.venv/bin/python -m hunt.execd_probe` | execd directly (pair with `go build -race` on the host, see below): foreground SSE integrity (300k lines, stdout/stderr interleave, `\r` / `\r\n` / unterminated fragments, a 17 MiB line), exit codes, timeouts, 96 concurrent commands, client disconnect, background logs with cursor (complete, incremental, past-end, negative), interrupts, 64 MiB upload/download sha256, byte ranges and 416, line reads, raw-socket upload cut mid-body (target file must survive), download disconnects (fd leaks via `lsof`), concurrent uploads to one path, bash sessions (state, concurrent runs, timeout, delete while running, 64 concurrent sessions). |
| `hunt/.venv/bin/python -m hunt.execd_file_stress --seconds 60` | Random concurrent upload / download / mv / delete / info / list / search / replace / chmod / mkdir / rmdir on a few paths; flags non-ENOENT 5xx and downloads that match no uploaded blob (torn writes). |
| `hunt/egress-image/build.sh` | `osb-hunt/egress:dev` from this checkout (host cross-compile + debian slim with iptables/nftables; no mitmproxy, so credential-vault MITM is not covered). |
| `hunt/.venv/bin/python -m hunt.egress_probe [--only basic pause restart snapshot]` | Server with `config/docker-egress.toml` (`dns+nft`): deny-default enforcement, PATCH semantics (first rule per target wins, replace in place), PUT replace, a validation matrix of odd targets/ports (no 5xx), pause/resume keeps runtime policy, sidecar restart, restore from a snapshot with a new policy. `HUNT_EGRESS_CONFIG` picks another config. |
| `hunt/.venv/bin/python -m hunt.expiry_race [--egress] [--ops renew snapshot delete pause concurrent]` | Fires renew / snapshot / delete / pause at expiry + offset (offsets sweep the boundary); checks renew-200 ⇒ alive, snapshot ends Ready-with-image or Failed-without, no containers of a 404 sandbox, no orphan snapshot images; plus 4 concurrent snapshots and restore racing a snapshot delete. |
| `hunt/.venv/bin/python -m hunt.sdk_contract` | Wire names declared by the hand-written Go / C# / Kotlin SDKs (`json:` tags, `JsonPropertyName`, `@SerialName`) that no spec defines, and required spec properties an SDK never names. Python/TS are generated: regenerate (`scripts/generate_api.py`, `pnpm gen:api`) and diff instead. |

Kubernetes: `hunt/config/k8s.toml` runs the server against a kind cluster with
the controller started on the host (`go run ./kubernetes/cmd/controller`).

## Probes

| Probe | Finding |
|---|---|
| `p03_snapshot_reports_paused` | Docker snapshot (`docker commit`, pause=True) runs outside the lifecycle lock: GET says Paused, pause → 409, resume accepted mid-commit. Fixed on `fix/docker-snapshot-lifecycle-lock`. |
| `p04_restart_persistence` | Renewed expiry, metadata patch, pause and an expiry that passes while the server is down all survive a restart (no bug; kept as a regression check). |
| `p06_k8s_delete_during_create` | Kubernetes: deleting a sandbox while its create waits keeps the create open until POD_READY_TIMEOUT, then 504. Fixed on `fix/k8s-create-wait-stops-on-delete`. |
| `p05_sdk_error_mapping` | Python SDK on 422 `{"detail": [...]}`: `SandboxApiException` with `code=UNEXPECTED_RESPONSE`, `message=None`. |
| `p08_paused_proxy_hangs` | Docker: proxied calls to a Paused sandbox wait for the shared client's 180 s timeout (504) and hold its pool; 100 of them delay another sandbox's `/networkpolicy` from 0.01 s to 177 s. Fixed on `fix/docker-proxy-rejects-paused`. |
| `p09_expiry_leaks_sidecar` | Docker: pause/snapshot racing expiry; sidecar cleanup lags the 404 by a few seconds but nothing leaks (no bug; regression check). |
| `p10_snapshot_delete_conflict_strands` | Docker: deleting a snapshot whose image a restored sandbox uses answers 409 but leaves it `Deleting` (no longer restorable), and the next server start deletes it. Fixed on `fix/snapshot-delete-conflict-keeps-ready`. |

Security-relevant probes are kept out of this branch until disclosed privately.

## Results so far (2026-11-25, main `178cfe32f`)

* fault_sweep: pause / resume / renew / create (22 calls) clean; `create_pvc` leaks the auto-created volume when the inspect right after `create_volume` fails (k=3).
* schemathesis lifecycle: 404/405/400 framework errors return `{"detail": ...}` (fixed on `fix/error-response-framework-errors`); request validation answers 422 `{"detail": [...]}` where the spec says 400 `ErrorResponse`; `X-Request-ID` is a 32-hex string, spec says `format: uuid`.
* schemathesis execd: no crash in 1386 cases; client errors (empty path, unknown user, missing session) answered as 500 `RUNTIME_ERROR`.
* state machine (40 examples x 20 steps): only the snapshot/pause interaction above.
* kind round (`hunt/k8s_round.py`): create/get/list/patch/renew-shorten-expiry/concurrent delete clean; delete during create waits for the full ready timeout (p06).

## Round 2 (2026-11-26, upstream main `06ff79763`, fixes from `faa30a96f`)

Host-run execd with the race detector (macOS; isolated sessions and uid/gid
paths need Linux):

```bash
(cd components/execd && go build -race -o /tmp/osb-hunt/bin/execd-race .)
mkdir -p /tmp/osb-hunt/execd-host/work && cd /tmp/osb-hunt/execd-host/work
/tmp/osb-hunt/bin/execd-race --port 45772 > ../execd.log 2>&1 &
EXECD_PID=$! hunt/.venv/bin/python -m hunt.execd_probe; grep -c "DATA RACE" /tmp/osb-hunt/execd-host/execd.log
```

* execd: 26/31 probe checks pass and no data race under `-race` (probes plus 60 s of file stress). The rest are known: foreground commands survive a client disconnect by design (maintainers declined #2083 / #2762 for SSE resume), 416 is plain text (#3005), client errors answered 500 (round 1 H), `/files/replace` writes in place so concurrent readers see a truncated file (#2889 / #2890).
* egress (`dns+nft`): enforcement, PATCH/PUT semantics and the validation matrix are clean; errors relayed from the sidecar are plain text, not `ErrorResponse`.
* snapshots / expiry: renew and delete are exact at the expiry boundary; findings p08 and p10 above.
* SDKs: Go wire names all in the specs; C# serializes `NetworkRuleAction` as `"Allow"` / `"Deny"` (the `[JsonPropertyName]` on enum members is ignored by `JsonStringEnumConverter`), accepted only because server and sidecar lowercase it; TS regenerates clean; Python egress client still lags `dropEstablished` (round 1 I).
* kind: create/patch/renew/expiry/concurrent delete clean, delete during create now 409 at once (upstream fix of round 1 D), `IMAGE_PULL_FAILING` reported while a pull fails.
