import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).resolve().parent.parent
OPA_URL = os.environ.get("OPA_URL", "http://localhost:8181")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def opa_up() -> bool:
    try:
        return httpx.get(f"{OPA_URL}/health", timeout=1).status_code == 200
    except httpx.HTTPError:
        return False


requires_opa = pytest.mark.skipif(not opa_up(), reason=f"OPA not reachable at {OPA_URL}")


@pytest.fixture
def var_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("ZT_VAR_DIR", str(tmp_path))
    return tmp_path


def _start_gateway(var_dir: Path, opa_url: str):
    port = _free_port()
    env = {**os.environ, "ZT_VAR_DIR": str(var_dir), "OPA_URL": opa_url}
    proc = subprocess.Popen([sys.executable, "-m", "uvicorn", "gateway.main:app", "--port", str(port)],
                            cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    url = f"http://127.0.0.1:{port}"
    for _ in range(60):
        try:
            if httpx.get(f"{url}/healthz", timeout=1).status_code == 200:
                return proc, url
        except httpx.HTTPError:
            time.sleep(0.5)
    proc.kill()
    raise RuntimeError("gateway did not start")


@pytest.fixture
def gateway(var_dir):
    proc, url = _start_gateway(var_dir, OPA_URL)
    yield url
    proc.kill()
    proc.wait()


@pytest.fixture
def gateway_without_pdp(var_dir):
    proc, url = _start_gateway(var_dir, "http://127.0.0.1:9")  # nothing listens here
    yield url
    proc.kill()
    proc.wait()
