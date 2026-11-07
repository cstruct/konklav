"""Seeds Konklav for the example with the control-plane client.

Run once, with the bootstrap token, before the apps start:

- the action catalog and the global roles the app and the admin page use
- two people: Ada (an admin and editor) and Bob (a member)
- two OIDC clients, both requiring DPoP:
  - `app`, public: the browser app holds its tokens in memory
  - `admin`, confidential: the admin page's backend holds its tokens
- two service principals:
  - `app-api`, which the app's backend follows the change feed as
  - `admin-api`, which the admin page also manages people with

It writes the secrets the apps need to SECRETS_FILE and does nothing if
that file exists, since secrets are shown only once. Among them is the
rate-limit secret, which every replica must share: rate-limit keys are
hashed under it before they reach Valkey.
"""

import json
import os
import sys
import time
import uuid
from pathlib import Path
from secrets import token_urlsafe

import httpx
from konklav_control_plane.sync import BearerToken, ControlPlaneClient

SUBJECT_URL = os.environ["KONKLAV_SUBJECT_URL"]
CONTROL_URL = os.environ["KONKLAV_CONTROL_URL"]
SECRETS_FILE = Path(os.environ["SECRETS_FILE"])

APP = "http://localhost:3000"
ADMIN = "http://localhost:4000"

# Stable ids, so a second run after a lost secrets file doesn't duplicate.
NAMESPACE = uuid.UUID("6f1d3c3e-3b8e-4c2a-9d1c-5b0a8e7f2a10")


def stable_id(name: str) -> str:
    return str(uuid.uuid5(NAMESPACE, name))


PEOPLE = [
    ("ada@example.com", "correct horse battery", ["member", "editor", "admin"]),
    ("bob@example.com", "bob's long password", ["member"]),
]

ROLES = {
    "member": ["notes:read"],
    "editor": ["notes:read", "notes:write"],
    "admin": ["admin:access"],
    # The admin page's service principal: managing people, their roles and
    # their sessions, and nothing else of the control plane.
    "admin-api": ["konklav:subjects:manage", "konklav:authz:manage", "konklav:sessions:manage"],
}


def wait_until_ready() -> None:
    for _ in range(120):
        try:
            if httpx.get(f"{SUBJECT_URL}/readyz").is_success:
                return
        except httpx.HTTPError:
            pass
        time.sleep(1)
    sys.exit("Konklav never became ready")


def service_principal(client: ControlPlaneClient, name: str, roles: list[str]) -> str:
    """A service principal with a fresh secret key; returns `<key id>.<secret>`."""
    subject = stable_id(f"service:{name}")
    client.subjects.create(subject, {"kind": "service"})
    created = client.credentials.create(subject, {"kind": "secret_key"})
    for role in roles:
        client.assignments.assign_global(subject, {"role": role})
    return created.value["secret_keys"]["a"]


def main() -> None:
    if SECRETS_FILE.exists():
        print(f"{SECRETS_FILE} exists; Konklav is already set up")
        return
    wait_until_ready()
    token = os.environ["KONKLAV_BOOTSTRAP_TOKEN"]
    with ControlPlaneClient(CONTROL_URL, auth=BearerToken(token)) as client:
        client.catalog.put(
            {
                "actions": [
                    {"name": "notes:read", "description": "Read the app's notes"},
                    {"name": "notes:write", "description": "Write notes in the app"},
                    {"name": "admin:access", "description": "Use the admin page"},
                ]
            }
        )
        for key, actions in ROLES.items():
            policies = [{"action": action, "effect": "allow"} for action in actions]
            client.roles.put("root", key, {"policies": policies})

        for email, password, roles in PEOPLE:
            subject = stable_id(f"person:{email}")
            client.subjects.create(subject, {"kind": "human"})
            client.credentials.create(
                subject,
                {
                    "id": stable_id(f"password:{email}"),
                    "kind": "password",
                    "identifier": email,
                    "password": password,
                },
            )
            for role in roles:
                client.assignments.assign_global(
                    subject, {"id": stable_id(f"{email}:{role}"), "role": role}
                )
            print(f"{email}: {', '.join(roles)}")

        client.oidc_clients.put(
            "app",
            {
                "kind": "public",
                "redirect_uris": [f"{APP}/callback"],
                "post_logout_redirect_uris": [f"{APP}/"],
                "audience": "app-api",
                "scopes": ["openid", "email"],
                "refresh": True,
                "require_dpop": True,
            },
        )
        client.oidc_clients.put(
            "admin",
            {
                "kind": "confidential",
                "redirect_uris": [f"{ADMIN}/callback"],
                "post_logout_redirect_uris": [f"{ADMIN}/"],
                "audience": "admin",
                "scopes": ["openid", "email"],
                "refresh": True,
                "require_dpop": True,
                "require_pkce": True,
            },
        )
        admin_secret = client.oidc_clients.new_secret("admin")["client_secret"]

        secrets = {
            "app_api_key": service_principal(client, "app-api", []),
            "admin_api_key": service_principal(client, "admin-api", ["admin-api"]),
            "admin_client_secret": admin_secret,
            # 32 random bytes, base64url: at least the 32 bytes RateLimit needs.
            "rate_limit_secret": token_urlsafe(32),
        }

    temporary = SECRETS_FILE.with_suffix(".tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w") as file:
        json.dump(secrets, file)
    temporary.rename(SECRETS_FILE)
    print(f"wrote {SECRETS_FILE}")


if __name__ == "__main__":
    main()
