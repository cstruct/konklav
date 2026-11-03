"""Checked by mypy, never run: calls on the client's namespaces keep their
types, and the same calls on a batch's return `Pending` ones."""

from typing import assert_type

from konklav_control_plane import BearerToken, ControlPlaneClient, Pending, Written, sync, types


async def direct_and_batched(client: ControlPlaneClient) -> None:
    assert_type(await client.tenants.create("t", {}), Written[types.Tenant])
    assert_type(await client.tenants.get("t"), types.Tenant)
    async with client.batch(idempotency_key="k") as batch:
        assert_type(batch.tenants.create("t", {}), Pending[Written[types.Tenant]])
        assert_type(batch.oidc_clients.new_secret("app"), Pending[types.OidcClientSecret])
        # Reads exist only on the client.
        batch.tenants.get("t")  # type: ignore[misc, unused-coroutine]
    assert_type(batch.cursor, int | None)


def synchronous(client: sync.ControlPlaneClient) -> None:
    assert_type(client.tenants.create("t", {}), Written[types.Tenant])
    with client.batch() as batch:
        assert_type(batch.tenants.create("t", {}), Pending[Written[types.Tenant]])


async def made() -> None:
    async with ControlPlaneClient("https://konklav.example", auth=BearerToken("t")) as client:
        await direct_and_batched(client)
