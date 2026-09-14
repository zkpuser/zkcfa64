"""Key generation for the authority and enrolled device."""

from __future__ import annotations

import re
from pathlib import Path

from zkcfa_provider.crypto import generate_keypair


def create_keys(root: Path, device_id: str) -> dict[str, str]:
    if re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", device_id) is None:
        raise ValueError("device identifier is not canonical")
    if root.is_symlink():
        raise ValueError("key root must not be a symlink")
    authority_private = root / "private" / "authority.pem"
    authority_public = root / "public" / "authority.pem"
    device_private = root / "private" / f"{device_id}.pem"
    device_public = root / "public" / f"{device_id}.pem"
    paths = (authority_private, authority_public, device_private, device_public)
    if any(path.exists() or path.is_symlink() for path in paths):
        raise FileExistsError("refusing to overwrite an existing provider key")
    authority_id = generate_keypair(authority_private, authority_public)
    device_key_id = generate_keypair(device_private, device_public)
    return {"authority_key_id": authority_id, "device_key_id": device_key_id}
