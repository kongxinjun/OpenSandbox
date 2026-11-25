"""Schemathesis hooks: aim generated requests at a live sandbox and keep creates cheap."""
import os
import random

import schemathesis

LIVE = os.environ.get("HUNT_LIVE_SANDBOX", "")
IMAGE = os.environ.get("HUNT_IMAGE", "busybox:latest")


@schemathesis.hook
def map_path_parameters(ctx, path_parameters):
    if path_parameters and LIVE and "sandboxId" in path_parameters and random.random() < 0.7:
        path_parameters["sandboxId"] = LIVE
    return path_parameters


@schemathesis.hook
def map_body(ctx, body):
    # Never pull arbitrary images, mount host paths or ask for real volumes.
    if isinstance(body, dict) and isinstance(body.get("image"), dict):
        body["image"]["uri"] = IMAGE
        body["image"].pop("auth", None)
    if isinstance(body, dict):
        for k in ("volumes", "credentialProxy", "secureAccess"):
            body.pop(k, None)
        if isinstance(body.get("timeout"), int) and body["timeout"] > 0:
            body["timeout"] = min(body["timeout"], 120)
    return body
