import importlib.metadata
import importlib.resources

import konklav_fastapi
import konklav_relying


def test_version_is_the_distributions() -> None:
    assert konklav_fastapi.__version__ == importlib.metadata.version("konklav-fastapi")


def test_is_typed() -> None:
    assert importlib.resources.files(konklav_fastapi).joinpath("py.typed").is_file()


# r[verify item.py-fastapi.pure-python]
# r[verify item.py-fastapi.same-version]
def test_is_pure_python_and_requires_its_own_relying_version() -> None:
    package = importlib.resources.files(konklav_fastapi)
    assert not [f.name for f in package.iterdir() if f.name.endswith((".so", ".pyd", ".dylib"))]
    requires = importlib.metadata.requires("konklav-fastapi") or []
    assert f"konklav-relying=={konklav_fastapi.__version__}" in requires
    assert importlib.metadata.version("konklav-relying") == konklav_fastapi.__version__
    assert konklav_relying.RelyingClient


# r[verify item.py-fastapi.fastapi-range]
def test_requires_a_bounded_fastapi_range() -> None:
    requires = importlib.metadata.requires("konklav-fastapi") or []
    (fastapi,) = [r for r in requires if r.startswith("fastapi")]
    assert ">=" in fastapi and "<" in fastapi.replace("<=", "")
