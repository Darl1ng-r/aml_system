import pytest
import urllib.request
import json
import socket


def is_server_running(host="localhost", port=8000) -> bool:
    try:
        s = socket.create_connection((host, port), timeout=1)
        s.close()
        return True
    except Exception:
        return False


@pytest.mark.skipif(not is_server_running(), reason="FastAPI server is not running on localhost:8000")
def test_e2e_flow_server_health():
    """Verify live server health endpoint when running locally."""
    req = urllib.request.Request("http://localhost:8000/", headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as response:
        data = json.loads(response.read().decode("utf-8"))
        assert "service" in data
