"""Creates Konklav's signing keys in a directory, unless they exist.

- `signing-key.pem`: the Ed25519 key that signs access tokens
- `id-token-key.pem`: the P-256 key that signs ID tokens (ES256)
"""

import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519


def write(path: Path, key) -> None:
    if path.exists():
        print(f"{path} exists")
        return
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as file:
        file.write(pem)
    print(f"wrote {path}")


directory = Path(sys.argv[1])
write(directory / "signing-key.pem", ed25519.Ed25519PrivateKey.generate())
write(directory / "id-token-key.pem", ec.generate_private_key(ec.SECP256R1()))
