#!/usr/bin/env python3
"""Sign fitted complete and shadow bundles for the 21 paper applications."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from bundle import build_signed_raw_bundle
from static.shadow_safe_bundle import materialize_shadow_safe_bundle


APPLICATIONS = (
    "aha-mont64",
    "crc32",
    "cubic",
    "edn",
    "huffbench",
    "matmult-int",
    "md5sum",
    "minver",
    "nbody",
    "nettle-aes",
    "nettle-sha256",
    "nsichneu",
    "picojpeg",
    "primecount",
    "sglib-combined",
    "slre",
    "st",
    "statemate",
    "tarfind",
    "ud",
    "wikisort",
)


def _summary(result: dict[str, object]) -> dict[str, object]:
    challenge = result.get("challenge")
    circuit = result.get("circuit")
    if not isinstance(challenge, dict) or not isinstance(circuit, dict):
        raise ValueError("protocol result omitted its challenge or circuit")
    bundle = Path(str(result["bundle"]))
    return {
        "bundle": str(bundle),
        "authority_public": str(bundle.parent / "keys/public/authority.pem"),
        "authority_sha256": result["authority_sha256"],
        "challenge_id": challenge["challenge_id"],
        "nonce": challenge["nonce"],
        "raw_registry_id": result["raw_registry_id"],
        "raw_config_id": result["raw_config_id"],
        "h_cfg_raw24": result["h_cfg_raw24"],
        "h_ep_raw24": result["h_ep_raw24"],
        "edge_cap": circuit["edge_cap"],
        "ep_cap": circuit["ep_cap"],
        "log_inv_rate": circuit["log_inv_rate"],
        "registry_bytes": result["registry_bytes"],
        "report_bytes": result["report_bytes"],
        "public_bytes": result["public_bytes"],
        "private_bytes": result["private_bytes"],
        "authority_provision_ms": result["authority_provision_ms"],
        "device_sign_ms": result["device_sign_ms"],
        "online_verdict": result["online_verdict"],
        "replay_rejection": result["replay_rejection"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    inputs = args.inputs.resolve()
    output = args.output.resolve()
    if output.exists() or output.is_symlink():
        raise FileExistsError("suite output must be absent")
    output.mkdir(parents=True, mode=0o700)

    outcomes: list[dict[str, object]] = []
    for application in APPLICATIONS:
        source = inputs / application
        artifacts = source / "artifacts"
        binary = source / application
        trace = source / "trace.log"
        app_output = output / application

        complete = build_signed_raw_bundle(
            run_dir=app_output / "complete",
            artifacts=artifacts,
            policy_artifacts=artifacts,
            binary=binary,
            trace_path=trace,
            path_mode="complete",
        )

        projected = output / "device-local" / application
        projection = materialize_shadow_safe_bundle(artifacts, projected)
        shadow = build_signed_raw_bundle(
            run_dir=app_output / "shadow",
            artifacts=projected,
            policy_artifacts=artifacts,
            binary=binary,
            trace_path=trace,
            path_mode="shadow",
            complete_source_artifacts=artifacts,
            source_trace_path=trace,
        )
        outcomes.append(
            {
                "application": application,
                "complete": _summary(complete),
                "shadow": _summary(shadow),
                "projection": projection,
            }
        )
        print(
            json.dumps(
                {
                    "application": application,
                    "complete_ep_cap": complete["circuit"]["ep_cap"],
                    "shadow_ep_cap": shadow["circuit"]["ep_cap"],
                    "shadow_rows": projection["compressed_rows"],
                },
                sort_keys=True,
            ),
            flush=True,
        )

    manifest = {
        "schema": "zkcfa.research.signed-suite",
        "capacity_policy": "fitted-evaluation",
        "applications": outcomes,
    }
    manifest_path = output / "bundles.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="ascii"
    )
    manifest_path.chmod(0o600)
    print(json.dumps({"applications": len(outcomes), "manifest": str(manifest_path)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
