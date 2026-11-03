import importlib.metadata
import importlib.resources
import subprocess
import sys

import konklav_control_plane


def test_version_is_the_distributions():
    assert konklav_control_plane.__version__ == importlib.metadata.version("konklav-control-plane")


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
