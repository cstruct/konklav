import inspect
import typing

import konklav_control_plane
import konklav_control_plane.sync
from konklav_control_plane import types

# The async names for what the sync client calls differently.
SYNC_NAMES = {"aclose": "close", "__aenter__": "__enter__", "__aexit__": "__exit__"}


def methods(cls):
    return {name for name, member in inspect.getmembers(cls, inspect.isfunction) if not name.startswith("_")} | {
        name for name in ("__aenter__", "__aexit__", "__enter__", "__exit__") if hasattr(cls, name)
    }


# r[verify item.py-control-plane.sync-parity]
def test_both_clients_have_the_same_methods_and_arguments():
    for name in ("ControlPlaneClient", "BearerToken", "SecretKey"):
        asynchronous = getattr(konklav_control_plane, name)
        synchronous = getattr(konklav_control_plane.sync, name)
        assert {SYNC_NAMES.get(m, m) for m in methods(asynchronous)} == methods(synchronous), name
        for method in methods(asynchronous):
            a = inspect.signature(getattr(asynchronous, method))
            s = inspect.signature(getattr(synchronous, SYNC_NAMES.get(method, method)))
            assert list(a.parameters) == list(s.parameters), f"{name}.{method}"
        assert inspect.iscoroutinefunction(asynchronous.__init__) is False
    assert inspect.iscoroutinefunction(konklav_control_plane.ControlPlaneClient.request)
    assert not inspect.iscoroutinefunction(konklav_control_plane.sync.ControlPlaneClient.request)
    assert konklav_control_plane.Written is konklav_control_plane.sync.Written


# r[verify item.py-control-plane.async-default]
def test_the_default_client_is_async():
    assert konklav_control_plane.ControlPlaneClient.__aenter__
    assert inspect.iscoroutinefunction(konklav_control_plane.ControlPlaneClient.request)


# r[verify item.py-control-plane.types]
def test_types_are_typed_dicts_of_the_decoded_json():
    hints = typing.get_type_hints(types.Tenant)
    assert typing.is_typeddict(types.Tenant)
    assert hints["created_at"] is str, "timestamps stay strings"
    assert set(typing.get_args(types.TenantState.__value__)) == {"active", "suspended", "deleted"}
    assert typing.is_typeddict(types.ErrorResponse)
