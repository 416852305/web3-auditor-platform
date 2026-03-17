import json
from pathlib import Path

from config import MAX_REPAIR_ATTEMPTS, RESULTS_DIR, SLITHER_ENABLED, WORKSPACE_DIR, WORKSPACE_TEST_FILENAME
from core import analyst_l5, foundry_workspace, hacker_fuzzer, project_loader, slither_runner, verifier


def save_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def verification_report_path(results_root=RESULTS_DIR):
    return Path(results_root) / "reports" / "L5_Verification_Report.json"


def audit_report_path(results_root=RESULTS_DIR):
    return Path(results_root) / "reports" / "L5_Audit_Report.json"


def build_verification_summary(verification_report):
    verification_report = verification_report or {}
    attempts = verification_report.get("attempts", []) or []
    last_attempt = attempts[-1] if attempts else {}
    return {
        "passed": verification_report.get("passed"),
        "attempt_count": len(attempts),
        "last_stage": last_attempt.get("stage"),
        "last_returncode": last_attempt.get("returncode"),
        "last_duration_seconds": last_attempt.get("duration_seconds"),
    }


def build_audit_report_document(analysis_result, generation_strategy=None, verification_report=None):
    analysis_result = analysis_result or {"vulnerabilities": [], "invariants": []}
    return {
        "vulnerabilities": analysis_result.get("vulnerabilities", []),
        "invariants": analysis_result.get("invariants", []),
        "generation_strategy": generation_strategy,
        "verification_summary": build_verification_summary(verification_report) if verification_report else None,
    }


def _build_workspace_info(root=None, test_rel_path=None):
    workspace_root = Path(root or WORKSPACE_DIR)
    rel_path = test_rel_path or f"test/{WORKSPACE_TEST_FILENAME}"
    return {
        "root": str(workspace_root),
        "target_root": str(workspace_root / "target"),
        "test_file": str(workspace_root / rel_path),
        "test_rel_path": rel_path,
        "import_prefix": "../target",
    }


def _persist_manual_verification(result, workspace_info, results_root=RESULTS_DIR):
    report = {
        "passed": result["success"],
        "workspace": workspace_info,
        "test_file": workspace_info["test_file"],
        "generation_requirement_issues": [],
        "attempts": [{**result, "attempt": 1}],
    }
    save_json(verification_report_path(results_root), report)
    audit_path = audit_report_path(results_root)
    if audit_path.exists():
        try:
            with audit_path.open("r", encoding="utf-8") as f:
                audit_doc = json.load(f)
        except json.JSONDecodeError:
            audit_doc = {"vulnerabilities": [], "invariants": []}
        audit_doc["verification_summary"] = build_verification_summary(report)
        save_json(audit_path, audit_doc)
    return report


def reverify_existing_suite(workspace_root=None, test_rel_path=None, results_root=RESULTS_DIR):
    workspace_info = _build_workspace_info(workspace_root, test_rel_path)
    result = verifier.verify_test_suite(workspace_info["root"], workspace_info["test_rel_path"])
    return _persist_manual_verification(result, workspace_info, results_root=results_root)


def run_pipeline(
    target_dir,
    slither_enabled=SLITHER_ENABLED,
    max_repair_attempts=MAX_REPAIR_ATTEMPTS,
    results_root=RESULTS_DIR,
    workspace_root=WORKSPACE_DIR,
    progress_callback=None,
):
    results_root = Path(results_root)
    workspace_root = Path(workspace_root)

    bundle = project_loader.load_project_bundle(target_dir)
    if not bundle:
        return {
            "exit_code": 1,
            "analysis_result": {"vulnerabilities": [], "invariants": []},
            "verification_report": None,
            "generation_strategy": None,
            "workspace_info": None,
            "report_path": str(audit_report_path(results_root)),
            "verification_report_path": str(verification_report_path(results_root)),
        }

    project_context = bundle["project_context"]
    file_map = bundle["file_map"]
    source_manifest = bundle["source_manifest"]

    if progress_callback:
        progress_callback(stage="project_load", message="已加载 Solidity 项目文件。")

    slither_report = "Skipped"
    if slither_enabled:
        if progress_callback:
            progress_callback(stage="slither", message="正在运行 Slither 静态分析。")
        slither_report = slither_runner.run_slither_on_dir(target_dir)

    if progress_callback:
        progress_callback(stage="analysis", message="正在执行 LLM 审计分析。")
    analysis_result = analyst_l5.analyze_project(project_context, slither_report, source_manifest, file_map)
    report_path = audit_report_path(results_root)
    save_json(report_path, build_audit_report_document(analysis_result))

    print("\n=== L5 Analysis Result ===")
    print(f"Invariants Found: {len(analysis_result.get('invariants', []))}")
    print(f"Vulnerabilities: {len(analysis_result.get('vulnerabilities', []))}")

    if progress_callback:
        progress_callback(stage="workspace", message="正在准备 Foundry 工作区。")
    workspace_info = foundry_workspace.prepare_workspace(target_dir, workspace_root=workspace_root)
    print(f"[*] Foundry workspace prepared at: {workspace_info['root']}")

    if progress_callback:
        progress_callback(stage="generate", message="正在生成 Foundry 测试套件。")
    generation = hacker_fuzzer.generate_fuzz_test(
        project_context,
        analysis_result,
        source_manifest,
        file_map,
        workspace_info,
    )
    if not generation["success"]:
        verification_report = {
            "passed": False,
            "workspace": workspace_info,
            "generation_error": generation["error"],
            "generation_requirement_issues": generation.get("requirement_issues", []),
            "generation_strategy": generation.get("generation_strategy"),
            "attempts": [],
        }
        save_json(verification_report_path(results_root), verification_report)
        save_json(
            report_path,
            build_audit_report_document(
                analysis_result,
                generation_strategy=generation.get("generation_strategy"),
                verification_report=verification_report,
            ),
        )
        return {
            "exit_code": 1,
            "analysis_result": analysis_result,
            "verification_report": verification_report,
            "generation_strategy": generation.get("generation_strategy"),
            "workspace_info": workspace_info,
            "report_path": str(report_path),
            "verification_report_path": str(verification_report_path(results_root)),
        }

    attempts = []
    current_code = generation["code"]
    current_issues = generation["requirement_issues"]

    for attempt_index in range(max_repair_attempts + 1):
        if progress_callback:
            progress_callback(
                stage="verify",
                message=f"正在执行验证，第 {attempt_index + 1}/{max_repair_attempts + 1} 次尝试。",
            )
        if current_issues:
            verification_result = verifier.preflight_failure(current_issues)
        else:
            verification_result = verifier.verify_test_suite(
                workspace_info["root"], workspace_info["test_rel_path"]
            )

        verification_result["attempt"] = attempt_index + 1
        attempts.append(verification_result)

        if verification_result["success"]:
            break

        if attempt_index >= max_repair_attempts:
            break

        if progress_callback:
            progress_callback(
                stage="repair",
                message=f"验证失败，正在修复生成套件（第 {attempt_index + 1} 次失败后）。",
            )
        repaired = hacker_fuzzer.repair_fuzz_test(
            project_context,
            analysis_result,
            source_manifest,
            file_map,
            workspace_info,
            current_code,
            verification_result,
        )
        if not repaired["success"]:
            attempts.append(
                {
                    "attempt": attempt_index + 2,
                    "success": False,
                    "stage": "repair_request",
                    "error": repaired["error"],
                }
            )
            break

        current_code = repaired["code"]
        current_issues = repaired["requirement_issues"]

    verification_report = {
        "passed": bool(attempts and attempts[-1]["success"]),
        "workspace": workspace_info,
        "test_file": workspace_info["test_file"],
        "generation_requirement_issues": generation.get("requirement_issues", []),
        "generation_strategy": generation.get("generation_strategy"),
        "attempts": attempts,
    }
    verification_report_file = verification_report_path(results_root)
    save_json(verification_report_file, verification_report)
    save_json(
        report_path,
        build_audit_report_document(
            analysis_result,
            generation_strategy=generation.get("generation_strategy"),
            verification_report=verification_report,
        ),
    )

    if verification_report["passed"]:
        print("[+] Verification passed.")
        print(f"    -> Report: {report_path}")
        print(f"    -> Test suite: {workspace_info['test_file']}")
        exit_code = 0
    else:
        print("[!] Verification failed.")
        print(f"    -> Report: {report_path}")
        print(f"    -> Verification details: {verification_report_file}")
        print(f"    -> Last test suite: {workspace_info['test_file']}")
        exit_code = 1

    return {
        "exit_code": exit_code,
        "analysis_result": analysis_result,
        "verification_report": verification_report,
        "generation_strategy": generation.get("generation_strategy"),
        "workspace_info": workspace_info,
        "report_path": str(report_path),
        "verification_report_path": str(verification_report_file),
    }
