"""Static contract diff: specs/sandbox-lifecycle.yml vs the server's own OpenAPI.

Run from server/:  uv run python ../hunt/contract_diff.py [--json out.json]

Compares, per operation (method + path under /v1):
  * presence of the operation on both sides
  * query/path/header parameters: name, required, default, min/max, enum
  * request body schema: properties, required, defaults, enums, bounds
  * declared response status codes
Schema comparison resolves $ref on both sides and walks nested objects.
Uses a mocked docker client, like server/tests/conftest.py, so no daemon is touched.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock

import yaml

ROOT = Path(__file__).resolve().parents[1]
os.environ.setdefault("SANDBOX_CONFIG_PATH", str(ROOT / "server/tests/testdata/config.toml"))

import docker  # noqa: E402

_mock = MagicMock()
_mock.containers.list.return_value = []
docker.from_env = lambda: _mock  # type: ignore

from opensandbox_server.main import app  # noqa: E402

METHODS = {"get", "post", "put", "patch", "delete"}
KEYWORDS = ("type", "default", "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum",
            "minLength", "maxLength", "pattern", "enum", "format", "minItems", "maxItems",
            "minProperties", "maxProperties")


def resolve(doc, node, seen=()):
    while isinstance(node, dict) and "$ref" in node:
        ref = node["$ref"]
        if ref in seen:
            return {"$cycle": ref}
        seen = seen + (ref,)
        cur = doc
        for part in ref.lstrip("#/").split("/"):
            cur = cur[part]
        extra = {k: v for k, v in node.items() if k != "$ref"}
        node = {**cur, **extra}
    return node


def flatten(doc, node, depth=0, seen=()):
    """Normalise a schema: merge allOf, collapse anyOf[X, null] into nullable X."""
    node = resolve(doc, node, seen)
    if not isinstance(node, dict):
        return node
    out = dict(node)
    if "allOf" in out:
        merged: dict = {}
        for sub in out.pop("allOf"):
            sub = flatten(doc, sub, depth + 1, seen)
            for k, v in sub.items():
                if k == "properties":
                    merged.setdefault("properties", {}).update(v)
                elif k == "required":
                    merged.setdefault("required", []).extend(v)
                else:
                    merged.setdefault(k, v)
        merged.update(out)
        out = merged
    for key in ("anyOf", "oneOf"):
        if key in out:
            variants = [flatten(doc, v, depth + 1, seen) for v in out[key]]
            non_null = [v for v in variants if v.get("type") != "null"]
            if len(non_null) == 1:
                out.pop(key)
                base = dict(non_null[0])
                base.update({k: v for k, v in out.items()})
                if len(non_null) != len(variants):
                    base["nullable"] = True
                out = base
    if out.get("type") == ["string", "null"]:
        out["type"] = "string"
        out["nullable"] = True
    return out


def schema_diff(spec_doc, impl_doc, s, i, path, out, depth=0):
    if depth > 6:
        return
    s = flatten(spec_doc, s)
    i = flatten(impl_doc, i)
    if not isinstance(s, dict) or not isinstance(i, dict):
        return
    for k in KEYWORDS:
        sv, iv = s.get(k), i.get(k)
        if k == "format" and None in (sv, iv):
            continue
        if k == "type" and (sv is None or iv is None):
            continue
        if sv != iv:
            out.append({"where": path, "keyword": k, "spec": sv, "impl": iv})
    sp, ip = s.get("properties") or {}, i.get("properties") or {}
    for name in sorted(set(sp) | set(ip)):
        if name not in ip:
            out.append({"where": f"{path}.{name}", "keyword": "property", "spec": "present", "impl": "missing"})
        elif name not in sp:
            out.append({"where": f"{path}.{name}", "keyword": "property", "spec": "missing", "impl": "present"})
        else:
            schema_diff(spec_doc, impl_doc, sp[name], ip[name], f"{path}.{name}", out, depth + 1)
    sr, ir = set(s.get("required") or []), set(i.get("required") or [])
    if sr != ir and (sp or ip):
        out.append({"where": path, "keyword": "required", "spec": sorted(sr - ir), "impl": sorted(ir - sr)})
    if "items" in s and "items" in i:
        schema_diff(spec_doc, impl_doc, s["items"], i["items"], f"{path}[]", out, depth + 1)
    sa, ia = s.get("additionalProperties"), i.get("additionalProperties")
    if isinstance(sa, dict) and isinstance(ia, dict):
        schema_diff(spec_doc, impl_doc, sa, ia, f"{path}{{*}}", out, depth + 1)


def ops(doc, prefix=""):
    res = {}
    for p, item in (doc.get("paths") or {}).items():
        for m, op in item.items():
            if m in METHODS:
                norm = (prefix + p)
                # FastAPI uses snake_case path params, spec uses camelCase.
                import re
                norm = re.sub(r"\{[^}]+\}", "{}", norm)
                res[(m, norm)] = (p, op, item.get("parameters", []))
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--spec", default=str(ROOT / "specs/sandbox-lifecycle.yml"))
    ap.add_argument("--json")
    args = ap.parse_args()
    spec = yaml.safe_load(Path(args.spec).read_text())
    impl = app.openapi()
    base = ""
    for server in spec.get("servers") or []:
        url = server.get("url", "")
        if url.endswith("/v1"):
            base = "/v1"
    spec_ops = ops(spec, base)
    impl_ops = {k: v for k, v in ops(impl).items() if k[1].startswith("/v1/")}
    findings = []
    for key in sorted(set(spec_ops) | set(impl_ops)):
        if key not in impl_ops:
            findings.append({"op": key, "kind": "missing-in-impl"})
            continue
        if key not in spec_ops:
            findings.append({"op": key, "kind": "missing-in-spec"})
            continue
        sp, sop, sparams = spec_ops[key]
        ip, iop, iparams = impl_ops[key]
        sparam = {}
        for prm in list(sparams) + list(sop.get("parameters") or []):
            prm = resolve(spec, prm)
            sparam[(prm["in"], prm["name"])] = prm
        iparam = {}
        for prm in list(iparams) + list(iop.get("parameters") or []):
            prm = resolve(impl, prm)
            iparam[(prm["in"], prm["name"])] = prm
        for pk in sorted(set(sparam) | set(iparam)):
            if pk[0] == "path":
                continue
            if pk not in iparam:
                findings.append({"op": key, "kind": "param-missing-in-impl", "param": pk})
                continue
            if pk not in sparam:
                if pk[0] != "header":
                    findings.append({"op": key, "kind": "param-missing-in-spec", "param": pk})
                continue
            if bool(sparam[pk].get("required")) != bool(iparam[pk].get("required")):
                findings.append({"op": key, "kind": "param-required", "param": pk,
                                 "spec": sparam[pk].get("required"), "impl": iparam[pk].get("required")})
            d: list = []
            schema_diff(spec, impl, sparam[pk].get("schema", {}), iparam[pk].get("schema", {}), "param", d)
            for x in d:
                findings.append({"op": key, "kind": "param-schema", "param": pk, **x})
        sb = ((sop.get("requestBody") or {}).get("content") or {}).get("application/json", {}).get("schema")
        ib = ((iop.get("requestBody") or {}).get("content") or {}).get("application/json", {}).get("schema")
        if bool(sb) != bool(ib):
            findings.append({"op": key, "kind": "body-presence", "spec": bool(sb), "impl": bool(ib)})
        elif sb:
            sreq = bool((resolve(spec, sop.get("requestBody")) or {}).get("required"))
            ireq = bool((iop.get("requestBody") or {}).get("required"))
            if sreq != ireq:
                findings.append({"op": key, "kind": "body-required", "spec": sreq, "impl": ireq})
            d = []
            schema_diff(spec, impl, sb, ib, "body", d)
            for x in d:
                findings.append({"op": key, "kind": "body-schema", **x})
        scodes = set(map(str, (sop.get("responses") or {}).keys()))
        icodes = set(map(str, (iop.get("responses") or {}).keys())) - {"422"}
        if scodes != icodes:
            findings.append({"op": key, "kind": "status-codes", "spec_only": sorted(scodes - icodes),
                             "impl_only": sorted(icodes - scodes)})
        for code in sorted(scodes & icodes):
            if not code.startswith("2"):
                continue
            ss = ((resolve(spec, sop["responses"][code]).get("content") or {}).get("application/json") or {}).get("schema")
            ist = ((iop["responses"][code].get("content") or {}).get("application/json") or {}).get("schema")
            if ss and ist:
                d = []
                schema_diff(spec, impl, ss, ist, f"resp{code}", d)
                for x in d:
                    findings.append({"op": key, "kind": "response-schema", **x})
    for f in findings:
        print(json.dumps(f, default=str))
    print(f"# {len(findings)} findings", file=sys.stderr)
    if args.json:
        Path(args.json).write_text(json.dumps(findings, indent=2, default=str))


if __name__ == "__main__":
    main()
