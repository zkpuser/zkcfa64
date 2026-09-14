"""Validation of the measured QEMU scope and external-call policy."""

from __future__ import annotations

import hashlib
import json
import re


TRACE_SCHEMA = "zkcfa.scope.trace"
EXTERNAL_NONE = "none"
EXTERNAL_GATEWAY = "plt-exact-return"

_POLICY_FIELDS = {
    "schema",
    "mode",
    "binding",
    "loader_scope",
    "thread_model",
    "dispatch_integrity",
    "runtime_dependencies",
    "calls",
}


def external_call_model(static_manifest: dict[str, object]) -> str:
    """Validate the private policy and return its stable public model name."""

    policy = static_manifest.get("external_call_policy")
    if not isinstance(policy, dict) or set(policy) != _POLICY_FIELDS:
        raise ValueError("static manifest has a missing or unknown external-call policy")
    calls = policy.get("calls")
    if not isinstance(calls, list):
        raise ValueError("static external-call policy has no canonical call list")
    call_fields = {
        "call_site",
        "plt_target",
        "symbol",
        "synthetic_node",
        "return_site",
        "gateway_end",
    }
    call_sites: list[str] = []
    for call in calls:
        if not isinstance(call, dict) or set(call) != call_fields:
            raise ValueError("static external-call policy has a malformed call")
        for field in call_fields - {"symbol"}:
            value = call.get(field)
            if not isinstance(value, str) or re.fullmatch(r"0x[0-9a-f]+", value) is None:
                raise ValueError("static external-call policy has a non-canonical address")
        if not isinstance(call.get("symbol"), str) or not call["symbol"]:
            raise ValueError("static external-call policy has a malformed symbol")
        call_sites.append(call["call_site"])
    if (
        len(call_sites) != len(set(call_sites))
        or call_sites != sorted(call_sites, key=lambda item: int(item, 16))
    ):
        raise ValueError("static external-call policy call sites are repeated or unordered")

    if static_manifest.get("trace_schema") != TRACE_SCHEMA:
        raise ValueError("static trace schema and external-call policy disagree")
    external = bool(calls)
    runtime_profile = static_manifest.get("runtime_profile")
    if runtime_profile == "freestanding-static":
        dynamic_runtime = False
    elif runtime_profile in {"ubuntu20", "ubuntu22"}:
        dynamic_runtime = True
    else:
        raise ValueError("static runtime profile is unsupported")
    expected = {
        "schema": "zkcfa.external-call-policy",
        "mode": EXTERNAL_GATEWAY if external else EXTERNAL_NONE,
        "binding": "eager" if dynamic_runtime else "none",
        "loader_scope": "trusted-out-of-scope" if dynamic_runtime else "none",
        "thread_model": "single",
    }
    if any(policy.get(field) != value for field, value in expected.items()):
        raise ValueError("static external-call policy is unsupported or downgraded")

    runtime = policy.get("runtime_dependencies")
    runtime_fields = {
        "schema", "runtime_profile", "binding", "environment", "files", "loader_scope"
    }
    if not isinstance(runtime, dict) or set(runtime) != runtime_fields:
        raise ValueError("external-call runtime dependencies are not bound")
    if (
        runtime.get("schema") != "zkcfa.runtime-dependencies"
        or runtime.get("runtime_profile") != runtime_profile
        or runtime.get("binding") != expected["binding"]
        or runtime.get("loader_scope") != expected["loader_scope"]
    ):
        raise ValueError("external-call runtime dependencies are not bound")
    dependency_digest = static_manifest.get("runtime_dependencies_sha256")
    if not isinstance(dependency_digest, str) or re.fullmatch(
        r"[0-9a-f]{64}", dependency_digest
    ) is None:
        raise ValueError("dependency-manifest digest is malformed")
    canonical = (json.dumps(runtime, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if hashlib.sha256(canonical).hexdigest() != dependency_digest:
        raise ValueError("dependency-manifest digest disagrees with policy")

    if not dynamic_runtime:
        if (
            external
            or policy.get("mode") != EXTERNAL_NONE
            or policy.get("dispatch_integrity") is not None
            or runtime.get("environment") != {}
            or runtime.get("files") != []
        ):
            raise ValueError("static no-external-call policy is malformed")
        return EXTERNAL_NONE
    if static_manifest.get("architecture") != "x86_64":
        raise ValueError("external-call tracing is supported only for x86-64")
    dispatch = policy.get("dispatch_integrity")
    dispatch_fields = {
        "schema",
        "bind_now",
        "no_rpath_or_runpath",
        "needed",
        "allowed_needed",
        "relro_ranges",
        "jump_slots",
    }
    if (
        not isinstance(dispatch, dict)
        or set(dispatch) != dispatch_fields
        or dispatch.get("schema") != "zkcfa.external-dispatch-policy"
        or dispatch.get("bind_now") is not True
        or dispatch.get("no_rpath_or_runpath") is not True
        or dispatch.get("allowed_needed") != ["libc.so.6", "libm.so.6"]
        or not isinstance(dispatch.get("needed"), list)
        or not dispatch["needed"]
        or any(item not in dispatch["allowed_needed"] for item in dispatch["needed"])
        or len(dispatch["needed"]) != len(set(dispatch["needed"]))
    ):
        raise ValueError("external-call dispatch integrity is not bound")
    ranges = dispatch.get("relro_ranges")
    jump_slots = dispatch.get("jump_slots")
    if (
        not isinstance(ranges, list)
        or not ranges
        or any(
            not isinstance(item, dict)
            or set(item) != {"start", "end"}
            or any(
                not isinstance(item.get(field), str)
                or re.fullmatch(r"0x[0-9a-f]+", item[field]) is None
                for field in ("start", "end")
            )
            for item in ranges
        )
        or not isinstance(jump_slots, list)
        or not jump_slots
        or any(
            not isinstance(item, str) or re.fullmatch(r"0x[0-9a-f]+", item) is None
            for item in jump_slots
        )
        or len(jump_slots) != len(set(jump_slots))
    ):
        raise ValueError("external-call RELRO dispatch record is malformed")
    parsed_ranges = [
        (int(item["start"], 16), int(item["end"], 16)) for item in ranges
    ]
    parsed_slots = [int(item, 16) for item in jump_slots]
    if (
        any(start >= end for start, end in parsed_ranges)
        or parsed_ranges != sorted(parsed_ranges)
        or parsed_slots != sorted(parsed_slots)
        or any(
            not any(start <= slot < end for start, end in parsed_ranges)
            for slot in parsed_slots
        )
    ):
        raise ValueError("external-call jump slots are not covered by GNU RELRO")

    if (
        runtime.get("environment") != {"LD_BIND_NOW": "1"}
        or not isinstance(runtime.get("files"), list)
        or not runtime["files"]
    ):
        raise ValueError("external-call runtime dependencies are not bound")
    expected_paths = [
        "lib64/ld-linux-x86-64.so.2",
        "lib/x86_64-linux-gnu/libc.so.6",
        "lib/x86_64-linux-gnu/libm.so.6",
    ]
    if [
        item.get("path") if isinstance(item, dict) else None
        for item in runtime["files"]
    ] != expected_paths or any(
        not isinstance(item, dict)
        or set(item) != {"path", "sha256"}
        or not isinstance(item.get("sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) is None
        for item in runtime["files"]
    ):
        raise ValueError("external-call dependency measurements are malformed")
    return EXTERNAL_GATEWAY if external else EXTERNAL_NONE
