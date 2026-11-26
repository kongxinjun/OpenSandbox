"""Static SDK <-> OpenAPI contract diff.

Hand-written SDKs (Go, C#): every JSON wire name they declare (`json:"x"` tags,
`[JsonPropertyName("x")]`, `@SerialName("x")`) is checked against the names the
specs define (schema properties, parameters, headers). A wire name no spec
defines is either an extension the server reads loosely or a typo that the
server silently drops; each one needs a look.

Also reports, per spec schema, required properties a hand-written SDK never
names (requests it cannot build) and enum values of selected fields.

    hunt/.venv/bin/python -m hunt.sdk_contract [--sdk go csharp kotlin]
"""
from __future__ import annotations

import argparse
import re
from collections import defaultdict
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SPECS = ["sandbox-lifecycle.yml", "execd-api.yaml", "egress-api.yaml", "diagnostic-api.yml"]
SDK_GLOBS = {
    "go": (["sdks/sandbox/go"], "*.go", [r'json:"([^",]+)']),
    "csharp": (["sdks/sandbox/csharp/src", "sdks/code-interpreter/csharp/src"], "*.cs",
               [r'JsonPropertyName\("([^"]+)"\)']),
    "kotlin": (["sdks/sandbox/kotlin/sandbox/src/main", "sdks/sandbox/kotlin/code-interpreter"], "*.kt",
               [r'@SerialName\("([^"]+)"\)']),
}


def spec_names():
    names: dict[str, set[str]] = defaultdict(set)   # wire name -> specs
    required: dict[tuple[str, str], list[str]] = {}

    def walk(node, spec):
        if isinstance(node, dict):
            props = node.get("properties")
            if isinstance(props, dict):
                for k in props:
                    names[k].add(spec)
            if node.get("in") in ("query", "header", "path") and "name" in node:
                names[node["name"]].add(spec)
            for v in node.values():
                walk(v, spec)
        elif isinstance(node, list):
            for v in node:
                walk(v, spec)

    for s in SPECS:
        doc = yaml.safe_load((ROOT / "specs" / s).read_text())
        walk(doc, s)
        for name, sch in (doc.get("components", {}).get("schemas") or {}).items():
            if isinstance(sch, dict) and sch.get("required"):
                required[(s, name)] = sch["required"]
        for h in (doc.get("components", {}).get("headers") or {}):
            names[h].add(s)
    return names, required


def sdk_names(sdk):
    dirs, glob, pats = SDK_GLOBS[sdk]
    out: dict[str, list[str]] = defaultdict(list)
    for d in dirs:
        for f in (ROOT / d).rglob(glob):
            if any(p in f.parts for p in ("test", "tests", "Tests", "bin", "obj", "build")) or f.name.endswith("_test.go"):
                continue
            text = f.read_text(errors="replace")
            for pat in pats:
                for m in re.finditer(pat, text):
                    line = text.count("\n", 0, m.start()) + 1
                    out[m.group(1)].append(f"{f.relative_to(ROOT)}:{line}")
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sdk", nargs="*", default=list(SDK_GLOBS))
    a = ap.parse_args()
    names, required = spec_names()
    lower = {k.lower(): k for k in names}
    for sdk in a.sdk:
        got = sdk_names(sdk)
        unknown = {k: v for k, v in got.items() if k not in names and k != "-"}
        print(f"\n== {sdk}: {len(got)} wire names, {len(unknown)} not in any spec")
        for k, where in sorted(unknown.items()):
            hint = ""
            if k.lower() in lower:
                hint = f"  <-- case differs from spec {lower[k.lower()]!r}"
            else:
                near = [n for n in names if n.lower().replace("_", "") == k.lower().replace("_", "")]
                if near:
                    hint = f"  <-- spec spells it {near}"
            print(f"  {k:32s} {where[0]}{' (+%d)' % (len(where) - 1) if len(where) > 1 else ''}{hint}")
        missing = []
        for (spec, schema), req in sorted(required.items()):
            for r in req:
                if r not in got:
                    missing.append(f"{spec}:{schema}.{r}")
        print(f"  required spec properties never named by {sdk}: {len(missing)}")
        for m in missing[:400]:
            print("    ", m)


if __name__ == "__main__":
    main()
