import subprocess
import time

from config import WORKSPACE_TEST_FILENAME


def preflight_failure(issues):
    message = "\n".join(issues)
    return {
        "success": False,
        "stage": "preflight",
        "command": "preflight",
        "returncode": 1,
        "stdout": "",
        "stderr": message,
        "combined_output": message,
        "duration_seconds": 0.0,
    }


def verify_test_suite(workspace_root, test_rel_path=None):
    rel_path = test_rel_path or f"test/{WORKSPACE_TEST_FILENAME}"
    cmd = ["forge", "test", "--match-path", rel_path, "-vv"]

    started_at = time.time()
    result = subprocess.run(cmd, cwd=workspace_root, capture_output=True, text=True)
    duration = time.time() - started_at

    stdout = result.stdout or ""
    stderr = result.stderr or ""
    return {
        "success": result.returncode == 0,
        "stage": "forge_test",
        "command": " ".join(cmd),
        "returncode": result.returncode,
        "stdout": stdout,
        "stderr": stderr,
        "combined_output": f"{stdout}\n{stderr}".strip(),
        "duration_seconds": round(duration, 3),
    }
