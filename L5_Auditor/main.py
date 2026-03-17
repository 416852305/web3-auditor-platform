# main.py
import argparse

from config import MAX_REPAIR_ATTEMPTS, SLITHER_ENABLED
from pipeline import run_pipeline


def main():
    parser = argparse.ArgumentParser(description="L5 Web3 Auditor with Foundry verification loop")
    parser.add_argument("--target-dir", default="targets", help="Directory containing the target Solidity project")
    parser.add_argument(
        "--skip-slither",
        action="store_true",
        help="Skip Slither and run LLM analysis directly",
    )
    parser.add_argument(
        "--max-repair-attempts",
        type=int,
        default=MAX_REPAIR_ATTEMPTS,
        help="How many times to ask the model to repair a failing test suite",
    )
    args = parser.parse_args()

    result = run_pipeline(
        target_dir=args.target_dir,
        slither_enabled=SLITHER_ENABLED and not args.skip_slither,
        max_repair_attempts=max(args.max_repair_attempts, 0),
    )
    raise SystemExit(result["exit_code"])


if __name__ == "__main__":
    main()
