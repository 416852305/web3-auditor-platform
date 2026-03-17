# config.py
import os
from pathlib import Path

# [Analyst] - 负责逻辑分析和提取不变量
ANALYST_API_KEY = os.getenv("L5_ANALYST_API_KEY", "")
ANALYST_API_URL = os.getenv("L5_ANALYST_API_URL", "https://api.deepseek.com/v1/chat/completions")
ANALYST_MODEL = os.getenv("L5_ANALYST_MODEL", "deepseek-chat")

# [Hacker] - 负责写高级 Fuzzing 代码
HACKER_API_KEY = os.getenv("L5_HACKER_API_KEY", "")
# 务必确认 URL 结尾
HACKER_API_URL = os.getenv("L5_HACKER_API_URL", "https://code-next.akclau.de/v1/chat/completions")
HACKER_MODEL = os.getenv("L5_HACKER_MODEL", "claude-sonnet-4-5")

# [Paths]
BASE_DIR = Path(__file__).resolve().parent
RESULTS_DIR = BASE_DIR / "results"
WORKSPACE_DIR = RESULTS_DIR / "foundry_workspace"
WORKSPACE_TARGET_DIRNAME = "target"
WORKSPACE_TEST_FILENAME = "L5_Invariant_Suite.t.sol"
FOUNDRY_LIBRARY_CANDIDATES = [
    BASE_DIR / "lib" / "forge-std",
]

# [Settings]
TIMEOUT_SECONDS = int(os.getenv("L5_TIMEOUT_SECONDS", "300"))
MAX_REPAIR_ATTEMPTS = int(os.getenv("L5_MAX_REPAIR_ATTEMPTS", "2"))
SLITHER_ENABLED = os.getenv("L5_SLITHER_ENABLED", "true").lower() == "true"
