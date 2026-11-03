"""Writes the generated parts of the package:

- `src/konklav_control_plane/types.py`, the request and response types,
  from the control-plane API document;
- `src/konklav_control_plane/_sync`, the sync client, from the async source
  in `_async`, and its tests in `tests/_sync` from `tests/_async`.

`--check` writes them to a temporary directory instead and fails when they
differ from the committed files. `mise run py-control-plane:generate` and
`mise run lint` run this.
"""

# r[impl item.py-control-plane.types]
# r[impl item.py-control-plane.sync-parity]

import argparse
import filecmp
import pathlib
import subprocess
import sys
import tempfile

import unasync

ROOT = pathlib.Path(__file__).resolve().parent.parent
PACKAGE = ROOT / "src" / "konklav_control_plane"
TESTS = ROOT / "tests"
DOCUMENT = ROOT.parent / "server" / "openapi" / "control-plane.json"
HEADER = "# Generated from ../_async by tools/generate.py; don't edit.\n"
REPLACEMENTS = {
    "AsyncClient": "Client",
    "aclose": "close",
    "AsyncLock": "SyncLock",
    "AsyncToken": "SyncToken",
    "async_sleep": "sync_sleep",
}


def types(output: pathlib.Path) -> None:
    subprocess.run(
        [
            "datamodel-codegen",
            f"--input={DOCUMENT}",
            "--input-file-type=openapi",
            f"--output={output}",
            "--output-model-type=typing.TypedDict",
            "--disable-timestamp",
            "--use-title-as-name",
            "--target-python-version=3.12",
            "--use-standard-collections",
            "--use-union-operator",
            "--enum-field-as-literal=all",
            "--use-schema-description",
            "--use-field-description",
            "--formatters=builtin",
        ],
        check=True,
        capture_output=True,
    )
    # The generator names the input by its path; keep only the file name.
    text = output.read_text().replace(f"filename:  {DOCUMENT}", f"filename:  {DOCUMENT.name}")
    output.write_text(text)


def unasynced(fromdir: pathlib.Path, todir: pathlib.Path, replacements: dict[str, str]) -> None:
    todir.mkdir(parents=True, exist_ok=True)
    sources = sorted(str(path) for path in fromdir.glob("*.py"))
    rule = unasync.Rule(fromdir=f"{fromdir}/", todir=f"{todir}/", additional_replacements=replacements)
    unasync.unasync_files(sources, [rule])
    for path in sorted(todir.glob("*.py")):
        path.write_text(HEADER + path.read_text())


def generate(package: pathlib.Path, tests: pathlib.Path) -> None:
    types(package / "types.py")
    unasynced(PACKAGE / "_async", package / "_sync", REPLACEMENTS)
    # The tests import the async client by its module path.
    unasynced(TESTS / "_async", tests / "_sync", REPLACEMENTS | {"_async": "_sync"})


def differences(fresh: pathlib.Path, committed: pathlib.Path) -> list[str]:
    found = []
    for path in sorted(fresh.rglob("*.py")):
        relative = path.relative_to(fresh)
        if not (committed / relative).is_file() or not filecmp.cmp(path, committed / relative, shallow=False):
            found.append(str(relative))
    for path in sorted(committed.rglob("*.py")):
        if not (fresh / path.relative_to(committed)).exists():
            found.append(f"{path.relative_to(committed)} (not generated)")
    return found


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="fail if the committed files are stale")
    check = parser.parse_args().check
    if not check:
        for old in [*(PACKAGE / "_sync").glob("*.py"), *(TESTS / "_sync").glob("*.py")]:
            old.unlink()
        generate(PACKAGE, TESTS)
        return 0
    with tempfile.TemporaryDirectory() as scratch:
        package, tests = pathlib.Path(scratch) / "package", pathlib.Path(scratch) / "tests"
        generate(package, tests)
        committed = pathlib.Path(scratch) / "committed"
        stale = [
            *(
                f"src/konklav_control_plane/{name}"
                for name in differences(package, _generated(PACKAGE, committed / "package"))
            ),
            *(f"tests/{name}" for name in differences(tests, _generated(TESTS, committed / "tests"))),
        ]
    if stale:
        print("Stale generated files; run `mise run py-control-plane:generate`:", file=sys.stderr)
        for name in stale:
            print(f"  {name}", file=sys.stderr)
        return 1
    return 0


def _generated(root: pathlib.Path, view: pathlib.Path) -> pathlib.Path:
    """A copy of `root`'s generated files in `view`, for comparing."""
    for path in [root / "types.py", *(root / "_sync").glob("*.py")]:
        if path.is_file():
            target = view / path.relative_to(root)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(path.read_bytes())
    return view


if __name__ == "__main__":
    sys.exit(main())
