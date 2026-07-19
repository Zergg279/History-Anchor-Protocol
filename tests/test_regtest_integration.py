from __future__ import annotations

import os
import shutil
import subprocess

import pytest


@pytest.mark.skipif(
    os.environ.get("HAP_RUN_BITCOIN_INTEGRATION") != "1"
    or shutil.which("bitcoind") is None,
    reason="set HAP_RUN_BITCOIN_INTEGRATION=1 with Bitcoin Core installed",
)
def test_regtest_end_to_end() -> None:
    subprocess.run(["bash", "scripts/regtest_e2e.sh"], check=True, timeout=180)
