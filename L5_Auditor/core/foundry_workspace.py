import shutil
from pathlib import Path

from config import (
    FOUNDRY_LIBRARY_CANDIDATES,
    WORKSPACE_DIR,
    WORKSPACE_TARGET_DIRNAME,
    WORKSPACE_TEST_FILENAME,
)

FOUNDRY_TOML = """[profile.default]
src = "src"
test = "test"
out = "out"
libs = ["lib", "target/lib", "target/node_modules"]

[fuzz]
runs = 128
fail_on_revert = false

[invariant]
runs = 32
depth = 64
fail_on_revert = false
"""

EXCLUDED_DIRS = {
    ".git",
    "artifacts",
    "broadcast",
    "cache",
    "out",
    "results",
    "__pycache__",
}


def _ignore_generated(_, names):
    return [name for name in names if name in EXCLUDED_DIRS]


def _ensure_forge_std(destination):
    if destination.is_symlink() or destination.exists():
        return

    destination.parent.mkdir(parents=True, exist_ok=True)
    for candidate in FOUNDRY_LIBRARY_CANDIDATES:
        if not candidate.exists():
            continue

        try:
            destination.symlink_to(candidate, target_is_directory=True)
        except OSError:
            shutil.copytree(candidate, destination)
        return

    raise FileNotFoundError(
        "forge-std not found. Add it under L5_Auditor/lib/forge-std."
    )


def _translate_remapping_path(path_value):
    if path_value.startswith("/"):
        return path_value

    normalized = path_value.lstrip("./")
    return f"{WORKSPACE_TARGET_DIRNAME}/{normalized}"


def _write_remappings(source_dir, workspace_root):
    remapping_lines = ["forge-std/=lib/forge-std/src/"]
    source_remappings = Path(source_dir) / "remappings.txt"

    if source_remappings.exists():
        for raw_line in source_remappings.read_text(encoding="utf-8").splitlines():
            stripped = raw_line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue

            name, path_value = stripped.split("=", 1)
            translated = _translate_remapping_path(path_value.strip())
            remapping_lines.append(f"{name.strip()}={translated}")

    unique_lines = []
    seen = set()
    for line in remapping_lines:
        if line in seen:
            continue
        seen.add(line)
        unique_lines.append(line)

    (workspace_root / "remappings.txt").write_text("\n".join(unique_lines) + "\n", encoding="utf-8")


def prepare_workspace(target_dir, workspace_root=None):
    source_dir = Path(target_dir).resolve()
    if not source_dir.exists():
        raise FileNotFoundError(f"Target directory does not exist: {source_dir}")

    workspace_root = Path(workspace_root or WORKSPACE_DIR)
    workspace_root.mkdir(parents=True, exist_ok=True)

    (workspace_root / "src").mkdir(exist_ok=True)
    (workspace_root / "test").mkdir(exist_ok=True)
    (workspace_root / "foundry.toml").write_text(FOUNDRY_TOML, encoding="utf-8")

    target_root = workspace_root / WORKSPACE_TARGET_DIRNAME
    if target_root.exists():
        shutil.rmtree(target_root)
    shutil.copytree(source_dir, target_root, ignore=_ignore_generated)

    _ensure_forge_std(workspace_root / "lib" / "forge-std")
    _write_remappings(source_dir, workspace_root)

    test_file = workspace_root / "test" / WORKSPACE_TEST_FILENAME
    return {
        "root": str(workspace_root),
        "target_root": str(target_root),
        "test_file": str(test_file),
        "test_rel_path": f"test/{WORKSPACE_TEST_FILENAME}",
        "import_prefix": f"../{WORKSPACE_TARGET_DIRNAME}",
    }
