"""A real Konklav for the integration tests, started by the `test-server`
binary from `examples/` on a fresh database.

The tests are skipped unless `KONKLAV_TEST_SERVER` names that binary, as
`mise run py-control-plane:integration` (part of `mise run test`) does.
"""

import json
import os
import subprocess
from collections.abc import Iterator
from typing import Any

import pytest


def start() -> Iterator[dict[str, Any]]:
    binary = os.environ.get("KONKLAV_TEST_SERVER")
    if not binary:
        pytest.skip("set KONKLAV_TEST_SERVER, as `mise run py-control-plane:integration` does")
    process = subprocess.Popen([binary], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    try:
        assert process.stdout is not None
        line = process.stdout.readline()
        if not line:
            pytest.fail(f"{binary} didn't start a server (exit {process.wait(30)})")
        yield json.loads(line)
    finally:
        # Closing stdin stops the server and drops its database.
        assert process.stdin is not None
        process.stdin.close()
        process.wait(30)


@pytest.fixture(scope="module")
def konklav() -> Iterator[dict[str, Any]]:
    """One server for a test module."""
    yield from start()


@pytest.fixture
def fresh_konklav() -> Iterator[dict[str, Any]]:
    """A server for one test, for changes the others mustn't see."""
    yield from start()
