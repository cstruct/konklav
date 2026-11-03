"""Runs the example against a server on a fresh database, started by the
`test-server` binary that `KONKLAV_TEST_SERVER` names, as `mise run
example:python` (part of `mise run test`) sets it."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import read_your_writes  # noqa: E402

pytestmark = pytest.mark.anyio


@pytest.fixture
def konklav():
    binary = os.environ.get("KONKLAV_TEST_SERVER")
    if not binary:
        pytest.skip("set KONKLAV_TEST_SERVER, as `mise run example:python` does")
    process = subprocess.Popen([binary], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    try:
        line = process.stdout.readline()
        if not line:
            pytest.fail(f"{binary} didn't start a server (exit {process.wait(30)})")
        server = json.loads(line)
        yield read_your_writes.Konklav(
            control=server["control"],
            subject=server["subject"],
            relying=server["relying"],
            issuer=server["issuer"],
            audience=server["audience"],
            token=server["bootstrap_token"],
        )
    finally:
        process.stdin.close()
        process.wait(30)


async def test_a_grant_is_decided_once_its_cursor_is_reached(konklav, capsys):
    assert await read_your_writes.run(konklav) == "allow"
    output = capsys.readouterr().out
    assert "before the grant, document:read is deny" in output
    assert "the relying client reached that cursor" in output
