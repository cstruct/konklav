import importlib.metadata
import importlib.resources
import subprocess
import sys

import konklav_control_plane


def test_version_is_the_distributions():
    assert konklav_control_plane.__version__ == importlib.metadata.version("konklav-control-plane")


# r[verify item.py-control-plane.independent]
def test_does_not_need_the_relying_sdk():
    requires = importlib.metadata.requires("konklav-control-plane") or []
    assert not [r for r in requires if r.startswith("konklav-relying")]
    # In a fresh interpreter, since this one may have imported it already.
    loaded = subprocess.run(
        [sys.executable, "-c", "import sys, konklav_control_plane; print('konklav_relying' in sys.modules)"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert loaded == "False"


def test_is_typed():
    assert importlib.resources.files(konklav_control_plane).joinpath("py.typed").is_file()


# r[verify item.py-control-plane.pure-python]
def test_is_pure_python():
    package = importlib.resources.files(konklav_control_plane)
    native = [f.name for f in package.iterdir() if f.name.endswith((".so", ".pyd", ".dylib"))]
    assert not native
    wheel = importlib.metadata.distribution("konklav-control-plane").read_text("WHEEL") or ""
    assert "Root-Is-Purelib: true" in wheel
    assert "Tag: py3-none-any" in wheel
