import json
import os
import re
import shutil
import sys
import threading
import uuid
import zipfile
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path, PurePosixPath

from fastapi import FastAPI, File, Form, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse, HTMLResponse

BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent
L5_DIR = Path(os.getenv("L5_DIR", str(PROJECT_ROOT / "L5_Auditor"))).resolve()
if str(L5_DIR) not in sys.path:
    sys.path.append(str(L5_DIR))

from config import WORKSPACE_DIR, WORKSPACE_TEST_FILENAME
from pipeline import audit_report_path, run_pipeline, verification_report_path

WEB_TARGET_DIR = BASE_DIR / "runtime_targets"
JOBS_DIR = BASE_DIR / "runtime_jobs"
SUITE_PATH = Path(WORKSPACE_DIR) / "test" / WORKSPACE_TEST_FILENAME
JOB_TTL_HOURS = int(os.getenv("WEB3_AI_JOB_TTL_HOURS", "24"))
DEFAULT_JOB_LIST_LIMIT = int(os.getenv("WEB3_AI_JOB_LIST_LIMIT", "25"))

JOB_STAGE_LABELS = {
    "queued": "排队中",
    "starting": "开始执行",
    "project_load": "加载项目",
    "slither": "静态分析",
    "analysis": "模型分析",
    "workspace": "准备工作区",
    "generate": "生成测试",
    "verify": "验证测试",
    "repair": "修复测试",
    "done": "已完成",
    "failed": "已失败",
}

@asynccontextmanager
async def lifespan(_app: FastAPI):
    JOBS_DIR.mkdir(parents=True, exist_ok=True)
    cleanup_old_jobs()
    yield


app = FastAPI(lifespan=lifespan)


def infer_target_filename(code):
    match = re.search(r"\b(?:abstract\s+)?(?:contract|interface|library)\s+([A-Za-z_][A-Za-z0-9_]*)", code)
    if match:
        return f"{match.group(1)}.sol"
    return "PastedTarget.sol"


def sanitize_upload_name(filename):
    parts = []
    for part in PurePosixPath(filename).parts:
        normalized = part.strip()
        if not normalized or normalized in {".", ".."}:
            continue
        parts.append(normalized)

    if not parts:
        return Path("UploadedTarget.sol")

    return Path(*parts)


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def parse_utc(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def reset_target_dir(target_root=WEB_TARGET_DIR):
    target_root = Path(target_root)
    if target_root.exists():
        shutil.rmtree(target_root)
    target_root.mkdir(parents=True, exist_ok=True)


def job_root(job_id):
    return JOBS_DIR / job_id


def job_target_dir(job_id):
    return job_root(job_id) / "targets"


def job_results_dir(job_id):
    return job_root(job_id) / "results"


def job_workspace_dir(job_id):
    return job_results_dir(job_id) / "foundry_workspace"


def job_manifest_path(job_id):
    return job_root(job_id) / "job.json"


def job_response_path(job_id):
    return job_root(job_id) / "response.json"


def save_job_manifest(job_id, payload):
    path = job_manifest_path(job_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)


def load_job_manifest(job_id):
    path = job_manifest_path(job_id)
    if not path.exists():
        raise FileNotFoundError(job_id)
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def save_job_response(job_id, payload):
    path = job_response_path(job_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)


def load_job_response(job_id):
    path = job_response_path(job_id)
    if not path.exists():
        return None
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def stage_label(stage):
    return JOB_STAGE_LABELS.get(stage, stage or "未知阶段")


def _write_sol_file(target_root, relative_path, content, written_files, valid_uploads):
    output_path = Path(target_root) / relative_path
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(content)
    written_files.append(output_path)
    valid_uploads.append(str(output_path))


def extract_zip_upload(target_root, content, written_files, valid_uploads):
    extracted = 0
    with zipfile.ZipFile(BytesIO(content)) as archive:
        for member in archive.infolist():
            if member.is_dir():
                continue

            safe_name = sanitize_upload_name(member.filename)
            if safe_name.suffix.lower() != ".sol":
                continue

            file_bytes = archive.read(member)
            if not file_bytes.strip():
                continue

            _write_sol_file(target_root, safe_name, file_bytes, written_files, valid_uploads)
            extracted += 1

    return extracted


async def prepare_target_dir(code="", files=None, target_root=WEB_TARGET_DIR):
    files = files or []
    target_root = Path(target_root)
    reset_target_dir(target_root)

    written_files = []
    valid_uploads = []
    zip_seen = False

    for upload in files:
        if not upload or not upload.filename:
            continue

        safe_name = sanitize_upload_name(upload.filename)
        content = await upload.read()
        if not content.strip():
            continue

        suffix = safe_name.suffix.lower()
        if suffix == ".zip":
            zip_seen = True
            extract_zip_upload(target_root, content, written_files, valid_uploads)
            continue

        if suffix and suffix != ".sol":
            continue

        _write_sol_file(target_root, safe_name, content, written_files, valid_uploads)

    source_mode = "zip-upload" if zip_seen else ("upload" if written_files else "paste")

    if not written_files:
        stripped_code = (code or "").strip()
        if not stripped_code:
            raise ValueError("Provide Solidity code or upload one or more .sol files.")

        target_file = target_root / infer_target_filename(stripped_code)
        target_file.write_text(stripped_code, encoding="utf-8")
        written_files.append(target_file)
        valid_uploads.append(str(target_file))

    return target_root, written_files, source_mode, valid_uploads


def read_text_if_exists(path_str):
    if not path_str:
        return None
    path = Path(path_str)
    if not path.exists():
        return None
    return path.read_text(encoding="utf-8")


def latest_attempt(verification):
    attempts = (verification or {}).get("attempts") or []
    return attempts[-1] if attempts else {}


def build_generated_outputs(result):
    verification = result.get("verification_report") or {}
    workspace = result.get("workspace_info") or {}
    test_file = workspace.get("test_file")
    if not test_file:
        return []

    return [
        {
            "type": "foundry_suite",
            "file_path": test_file,
            "status": "Verified" if verification.get("passed") else "Generated",
        }
    ]


def artifact_paths(job_id=None):
    if job_id:
        results_root = job_results_dir(job_id)
        workspace_root = job_workspace_dir(job_id)
        return {
            "audit-report": Path(audit_report_path(results_root)),
            "verification-report": Path(verification_report_path(results_root)),
            "suite": Path(workspace_root) / "test" / WORKSPACE_TEST_FILENAME,
        }

    return {
        "audit-report": Path(audit_report_path()),
        "verification-report": Path(verification_report_path()),
        "suite": SUITE_PATH,
    }


def build_pipeline_response(result, target_files, source_mode, job_id=None):
    analysis = result.get("analysis_result") or {"vulnerabilities": [], "invariants": []}
    verification = result.get("verification_report") or {}
    generation_strategy = result.get("generation_strategy") or verification.get("generation_strategy") or {}
    workspace = result.get("workspace_info") or {}
    suite_code = read_text_if_exists(workspace.get("test_file"))
    last_attempt = latest_attempt(verification)
    if job_id:
        downloads = {
            "audit_report": f"/artifact/{job_id}/audit-report",
            "verification_report": f"/artifact/{job_id}/verification-report",
            "suite": f"/artifact/{job_id}/suite",
        }
    else:
        downloads = {
            "audit_report": "/artifact/audit-report",
            "verification_report": "/artifact/verification-report",
            "suite": "/artifact/suite",
        }

    response = {
        "job_id": job_id,
        "critical_vulnerabilities": analysis.get("vulnerabilities", []),
        "informational_warnings": [],
        "invariants": analysis.get("invariants", []),
        "verification": verification,
        "generation_strategy": generation_strategy,
        "verification_summary": {
            "passed": verification.get("passed"),
            "attempt_count": len(verification.get("attempts", [])),
            "last_stage": last_attempt.get("stage"),
            "last_returncode": last_attempt.get("returncode"),
            "last_duration_seconds": last_attempt.get("duration_seconds"),
        },
        "last_attempt_log": last_attempt.get("combined_output"),
        "generated_exploits": build_generated_outputs(result),
        "test_suite_path": workspace.get("test_file"),
        "test_suite_code": suite_code,
        "target_files": [str(path) for path in target_files],
        "primary_target_file": str(target_files[0]) if target_files else None,
        "source_mode": source_mode,
        "report_path": result.get("report_path"),
        "verification_report_path": result.get("verification_report_path"),
        "downloads": downloads,
    }

    if result.get("exit_code", 1) != 0:
        response["error"] = "L5 pipeline did not complete successfully."

    return response


def build_job_summary(response):
    verification_summary = response.get("verification_summary") or {}
    return {
        "vulnerabilities": len(response.get("critical_vulnerabilities", [])),
        "invariants": len(response.get("invariants", [])),
        "verification_passed": verification_summary.get("passed"),
        "attempt_count": verification_summary.get("attempt_count"),
    }


def create_job_record(job_id, target_files, source_mode):
    manifest = {
        "job_id": job_id,
        "status": "queued",
        "stage": "queued",
        "stage_display": stage_label("queued"),
        "stage_message": "等待开始。",
        "created_at": utc_now(),
        "updated_at": utc_now(),
        "source_mode": source_mode,
        "target_files": [str(path) for path in target_files],
        "summary": None,
        "error": None,
    }
    save_job_manifest(job_id, manifest)
    return manifest


def update_job_record(job_id, **updates):
    manifest = load_job_manifest(job_id)
    if "stage" in updates:
        updates["stage_display"] = stage_label(updates["stage"])
    manifest.update(updates)
    manifest["updated_at"] = updates.get("updated_at", utc_now())
    save_job_manifest(job_id, manifest)
    return manifest


def serialize_job(job_id):
    manifest = load_job_manifest(job_id)
    response = load_job_response(job_id)
    if response:
        manifest["result"] = response
    return manifest


def list_jobs(limit=None):
    jobs = []
    if not JOBS_DIR.exists():
        return jobs

    for child in JOBS_DIR.iterdir():
        if not child.is_dir():
            continue
        try:
            jobs.append(load_job_manifest(child.name))
        except FileNotFoundError:
            continue

    jobs.sort(key=lambda item: item.get("updated_at", ""), reverse=True)
    if limit is not None:
        jobs = jobs[:limit]
    return jobs


def delete_job(job_id):
    manifest = load_job_manifest(job_id)
    if manifest.get("status") in {"queued", "running"}:
        raise RuntimeError("Cannot delete a job that is still running.")

    root = job_root(job_id)
    shutil.rmtree(root)


def should_cleanup_job(manifest):
    if manifest.get("status") not in {"completed", "failed"}:
        return False

    updated_at = parse_utc(manifest.get("updated_at"))
    if not updated_at:
        return False

    age_seconds = (datetime.now(timezone.utc) - updated_at).total_seconds()
    return age_seconds > JOB_TTL_HOURS * 3600


def cleanup_old_jobs():
    removed = []
    for job in list_jobs():
        if should_cleanup_job(job):
            try:
                delete_job(job["job_id"])
                removed.append(job["job_id"])
            except FileNotFoundError:
                continue
    return removed


def run_job_pipeline(job_id, target_dir, target_files, source_mode):
    def on_progress(stage, message):
        update_job_record(job_id, status="running", stage=stage, stage_message=message)

    try:
        update_job_record(job_id, status="running", stage="starting", stage_message="开始执行后台审计任务。")
        result = run_pipeline(
            str(target_dir),
            slither_enabled=True,
            max_repair_attempts=3,
            results_root=job_results_dir(job_id),
            workspace_root=job_workspace_dir(job_id),
            progress_callback=on_progress,
        )
        response = build_pipeline_response(result, target_files, source_mode, job_id=job_id)
        save_job_response(job_id, response)
        update_job_record(
            job_id,
            status="completed" if result.get("exit_code", 1) == 0 else "failed",
            stage="done" if result.get("exit_code", 1) == 0 else "failed",
            stage_message="任务已成功完成。" if result.get("exit_code", 1) == 0 else "任务已结束，但存在失败。",
            summary=build_job_summary(response),
            error=response.get("error"),
        )
        return response
    except Exception as e:
        update_job_record(job_id, status="failed", stage="failed", stage_message=f"任务异常：{e}", error=str(e))
        return None


def enqueue_job(target_dir, target_files, source_mode):
    job_id = uuid.uuid4().hex[:12]
    create_job_record(job_id, target_files, source_mode)
    worker = threading.Thread(
        target=run_job_pipeline,
        args=(job_id, target_dir, target_files, source_mode),
        daemon=True,
    )
    worker.start()
    return job_id


def run_web_audit(code, pipeline_runner=run_pipeline):
    target_dir = None
    target_files = None
    source_mode = "paste"

    try:
        target_dir, target_files, source_mode, _ = _sync_prepare_target_dir(code)
        result = pipeline_runner(str(target_dir), slither_enabled=True, max_repair_attempts=3)
        return build_pipeline_response(result, target_files, source_mode)
    except ValueError as e:
        return {"error": str(e)}


def _sync_prepare_target_dir(code):
    reset_target_dir(WEB_TARGET_DIR)
    stripped_code = (code or "").strip()
    if not stripped_code:
        raise ValueError("Provide Solidity code or upload one or more .sol files.")
    target_file = WEB_TARGET_DIR / infer_target_filename(stripped_code)
    target_file.write_text(stripped_code, encoding="utf-8")
    return WEB_TARGET_DIR, [target_file], "paste", [str(target_file)]


@app.get("/artifact/{kind}")
async def download_artifact(kind: str):
    paths = artifact_paths()
    if kind not in paths:
        raise HTTPException(status_code=404, detail="Unknown artifact type")

    artifact = paths[kind]
    if not artifact.exists():
        raise HTTPException(status_code=404, detail="Artifact not found")

    media_type = "application/json" if artifact.suffix == ".json" else "text/plain"
    return FileResponse(path=artifact, filename=artifact.name, media_type=media_type)


@app.get("/artifact/{job_id}/{kind}")
async def download_job_artifact(job_id: str, kind: str):
    paths = artifact_paths(job_id)
    if kind not in paths:
        raise HTTPException(status_code=404, detail="Unknown artifact type")

    artifact = paths[kind]
    if not artifact.exists():
        raise HTTPException(status_code=404, detail="Artifact not found")

    media_type = "application/json" if artifact.suffix == ".json" else "text/plain"
    return FileResponse(path=artifact, filename=artifact.name, media_type=media_type)


@app.post("/audit/submit")
async def submit_audit(
    code: str = Form(default=""),
    files: list[UploadFile] = File(default=[]),
):
    print("[*] Received background L5 web audit request...")
    cleanup_old_jobs()
    try:
        pending_id = uuid.uuid4().hex[:12]
        target_dir, target_files, source_mode, _ = await prepare_target_dir(
            code,
            files,
            target_root=job_target_dir(pending_id),
        )
        create_job_record(pending_id, target_files, source_mode)
        worker = threading.Thread(
            target=run_job_pipeline,
            args=(pending_id, target_dir, target_files, source_mode),
            daemon=True,
        )
        worker.start()
        return {"job_id": pending_id, "status": "queued"}
    except ValueError as e:
        return {"error": str(e)}


@app.get("/jobs/{job_id}")
async def get_job(job_id: str):
    try:
        return serialize_job(job_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Unknown job id")


@app.get("/jobs")
async def get_jobs(limit: int = Query(default=DEFAULT_JOB_LIST_LIMIT, ge=1, le=200)):
    cleanup_old_jobs()
    jobs = list_jobs(limit=limit)
    return {"jobs": jobs, "limit": limit}


@app.delete("/jobs/{job_id}")
async def delete_job_route(job_id: str):
    try:
        delete_job(job_id)
        return {"deleted": True, "job_id": job_id}
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Unknown job id")
    except RuntimeError as e:
        raise HTTPException(status_code=409, detail=str(e))


@app.get("/", response_class=HTMLResponse)
async def read_root():
    return """
    <!DOCTYPE html>
    <html>
        <head>
            <title>L5 Smart Contract Auditor</title>
            <style>
                :root {
                    --bg: #111827;
                    --panel: #172033;
                    --panel-2: #0f172a;
                    --border: #334155;
                    --text: #e5e7eb;
                    --muted: #94a3b8;
                    --ok: #22c55e;
                    --alert: #f97316;
                    --link: #38bdf8;
                }
                body { background: radial-gradient(circle at top, #1f2937 0%, var(--bg) 45%); color: var(--text); font-family: 'Segoe UI', monospace; padding: 20px; margin: 0; }
                .shell { max-width: 1320px; margin: 0 auto; }
                textarea { width: 100%; height: 220px; background: var(--panel-2); color: #fff; border: 1px solid var(--border); padding: 12px; border-radius: 8px; box-sizing: border-box; }
                button { background: #0f766e; color: white; padding: 10px 20px; border: none; font-weight: bold; cursor: pointer; margin-top: 12px; border-radius: 999px; }
                button:hover { background: #0d9488; }
                .toolbar { display: flex; flex-wrap: wrap; gap: 10px; margin: 12px 0 6px 0; }
                .toolbar button { margin-top: 0; }
                .ghost { background: transparent; border: 1px solid var(--border); color: var(--text); }
                .ghost:hover { background: #1e293b; border-color: var(--link); }
                .grid { display: grid; grid-template-columns: 1.2fr 1fr; gap: 16px; }
                .stack { display: grid; gap: 16px; }
                .box { border: 1px solid var(--border); padding: 16px; margin-top: 15px; background: var(--panel); white-space: pre-wrap; border-radius: 10px; }
                .primary { border-left: 5px solid var(--alert); }
                .secondary { border-left: 5px solid var(--ok); }
                .muted { border-left: 5px solid #64748b; color: #cbd5e1; }
                .metrics { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; margin-top: 16px; }
                .metric { background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 14px; }
                .metric .label { display: block; color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.08em; }
                .metric .value { display: block; margin-top: 8px; font-size: 22px; font-weight: bold; }
                .section-title { margin: 0 0 10px 0; font-size: 16px; color: #f8fafc; }
                .card-list { display: grid; gap: 12px; }
                .card { background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 14px; }
                .card h4 { margin: 0 0 8px 0; }
                .badge { display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 12px; background: rgba(249, 115, 22, 0.14); color: #fdba74; margin-right: 8px; }
                .ok-badge { background: rgba(34, 197, 94, 0.14); color: #86efac; }
                .fail-badge { background: rgba(239, 68, 68, 0.14); color: #fda4af; }
                .kv { color: var(--muted); font-size: 13px; }
                .artifact-row { display: flex; flex-wrap: wrap; gap: 10px; margin-top: 12px; }
                .artifact-row a, .history-button { color: var(--link); text-decoration: none; border: 1px solid var(--border); border-radius: 999px; padding: 8px 12px; background: rgba(15, 23, 42, 0.7); display: inline-block; }
                .artifact-row a:hover, .history-button:hover { border-color: var(--link); }
                .upload-row { display: flex; flex-wrap: wrap; align-items: center; gap: 12px; margin-top: 14px; }
                .upload-row input[type=file] { color: var(--muted); }
                .upload-note, .cache-note { color: var(--muted); margin-top: 8px; font-size: 13px; }
                .history-list { display: grid; gap: 10px; }
                .history-item { background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 12px; }
                .history-item h4 { margin: 0 0 6px 0; }
                .history-actions { display: flex; gap: 8px; margin-top: 8px; flex-wrap: wrap; }
                .server-jobs { display: grid; gap: 10px; }
                .server-job { background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 12px; }
                .server-job h4 { margin: 0 0 6px 0; }
                .help-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px; margin-top: 16px; }
                .help-card { background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 14px; }
                .help-card h4 { margin: 0 0 8px 0; }
                pre { margin: 0; overflow-x: auto; }
                details { margin-top: 12px; }
                summary { cursor: pointer; color: var(--link); }
                .hidden { display: none; }
                @media (max-width: 960px) {
                    .grid { grid-template-columns: 1fr; }
                    .metrics { grid-template-columns: repeat(2, minmax(0, 1fr)); }
                    .help-grid { grid-template-columns: 1fr; }
                }
            </style>
        </head>
        <body>
            <div class="shell">
                <h1>L5 Smart Contract Auditor <span style="font-size:0.6em; color:#94a3b8">(Slither + LLM + Foundry)</span></h1>
                <p style="color:#cbd5e1; max-width:920px;">Paste Solidity code or upload a small multi-file Solidity project, then inspect grounded findings, verification logs, and the generated Foundry suite.</p>
                <div class="help-grid">
                    <div class="help-card">
                        <h4>Input Modes</h4>
                        <div class="kv">Paste one Solidity file, upload multiple `.sol` files, or upload a `.zip` project.</div>
                    </div>
                    <div class="help-card">
                        <h4>Template Families</h4>
                        <div class="kv">Currently supports deterministic verification for delegatecall/module vaults, inflation vaults, reentrancy banks, owner takeovers, and fee-accounting vaults.</div>
                    </div>
                    <div class="help-card">
                        <h4>Fallback Logic</h4>
                        <div class="kv">The system always analyzes openly first. If no deterministic template matches, it falls back to general LLM-generated Foundry tests.</div>
                    </div>
                </div>
                <textarea id="code" placeholder="// Paste a Solidity contract here..."></textarea>
                <div class="upload-row">
                    <input id="file-input" type="file" multiple accept=".sol,.zip,application/zip,text/plain" webkitdirectory directory />
                    <span class="upload-note" id="upload-note">No uploaded files selected. You can choose .sol files, a folder, or a .zip archive.</span>
                </div>
                <div class="toolbar">
                    <button onclick="audit()">Run L5 Audit</button>
                    <button class="ghost" onclick="loadExample('inflation')">Example: Inflation Vault</button>
                    <button class="ghost" onclick="loadExample('simple_bank')">Example: Reentrancy Bank</button>
                    <button class="ghost" onclick="clearCurrentAudit()">Clear Current Input</button>
                    <button class="ghost" onclick="clearAuditHistory()">Clear History</button>
                </div>
                <div id="status" style="margin-top:10px;"></div>
                <div id="cache-note" class="cache-note"></div>

                <div class="box muted">
                    <h3 class="section-title">Recent Audits</h3>
                    <div id="history-list" class="history-list"></div>
                </div>

                <div class="box muted">
                    <h3 class="section-title">Server Jobs</h3>
                    <div id="server-jobs" class="server-jobs"></div>
                </div>

                <div id="metrics" class="metrics hidden">
                    <div class="metric"><span class="label">Vulnerabilities</span><span class="value" id="metric-vulns">0</span></div>
                    <div class="metric"><span class="label">Invariants</span><span class="value" id="metric-invariants">0</span></div>
                    <div class="metric"><span class="label">Verification</span><span class="value" id="metric-verification">Pending</span></div>
                    <div class="metric"><span class="label">Attempts</span><span class="value" id="metric-attempts">0</span></div>
                </div>

                <div id="report-area" class="grid hidden">
                    <div class="stack">
                        <div class="box primary">
                            <h3 class="section-title">Vulnerabilities</h3>
                            <div id="critical-vulns" class="card-list"></div>
                        </div>
                        <div class="box secondary">
                            <h3 class="section-title">Invariants</h3>
                            <div id="invariants" class="card-list"></div>
                        </div>
                        <div class="box muted">
                            <h3 class="section-title">Generation Strategy</h3>
                            <div id="generation-strategy"></div>
                        </div>
                    </div>
                    <div class="stack">
                        <div class="box muted">
                            <h3 class="section-title">Verification</h3>
                            <div id="verification-summary"></div>
                            <div class="artifact-row" id="artifact-links"></div>
                            <details>
                                <summary>Show Last Verification Log</summary>
                                <pre id="verification-log"></pre>
                            </details>
                            <details>
                                <summary>Show Raw Verification JSON</summary>
                                <pre id="verification-raw"></pre>
                            </details>
                        </div>
                        <div class="box">
                            <h3 class="section-title">Generated Foundry Suite</h3>
                            <div id="suite-meta" class="kv"></div>
                            <details open>
                                <summary>Show Solidity</summary>
                                <pre id="suite-code"></pre>
                            </details>
                        </div>
                    </div>
                </div>
            </div>

            <script>
                const CACHE_KEY = 'l5_audit_cache_v2';
                const HISTORY_KEY = 'l5_audit_history_v1';
                let currentJobId = null;
                let restoredFiles = [];

                const EXAMPLES = {
                    inflation: `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ExampleToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    constructor() {
        balanceOf[msg.sender] = 1_000_000 ether;
    }

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "bal");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(balanceOf[from] >= amount, "bal");
        require(allowance[from][msg.sender] >= amount, "allow");
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

contract InflationVault {
    ExampleToken public asset;
    uint256 public totalShares;
    mapping(address => uint256) public balanceOf;

    constructor(address _asset) {
        asset = ExampleToken(_asset);
    }

    function deposit(uint256 assets) external {
        require(assets > 0, "zero");
        uint256 totalAssets = asset.balanceOf(address(this));
        uint256 shares = totalShares == 0 ? assets : (assets * totalShares) / totalAssets;
        require(shares > 0, "Zero shares minted");
        balanceOf[msg.sender] += shares;
        totalShares += shares;
        asset.transferFrom(msg.sender, address(this), assets);
    }

    function withdraw(uint256 shares) external {
        require(balanceOf[msg.sender] >= shares, "shares");
        uint256 totalAssets = asset.balanceOf(address(this));
        uint256 amount = (shares * totalAssets) / totalShares;
        balanceOf[msg.sender] -= shares;
        totalShares -= shares;
        asset.transfer(msg.sender, amount);
    }
}`,
                    simple_bank: `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract EtherBank {
    mapping(address => uint256) public balanceOf;

    function deposit() external payable {
        balanceOf[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = balanceOf[msg.sender];
        require(amount > 0, "empty");
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
        balanceOf[msg.sender] = 0;
    }
}
`
                };

                function escapeHtml(value) {
                    return String(value ?? '')
                        .replaceAll('&', '&amp;')
                        .replaceAll('<', '&lt;')
                        .replaceAll('>', '&gt;')
                        .replaceAll('"', '&quot;')
                        .replaceAll("'", '&#39;');
                }

                function renderVulnerabilities(items) {
                    if (!items.length) return '<div class="kv">No grounded high-severity vulnerabilities.</div>';
                    return items.map((item) => `
                        <div class="card">
                            <h4>${escapeHtml(item.name || item.vulnerability || 'Unnamed')}</h4>
                            <div class="kv"><span class="badge">${escapeHtml(item.severity || 'N/A')}</span>Score ${escapeHtml(item.score ?? 'N/A')}</div>
                            <p>${escapeHtml(item.description || '')}</p>
                            <div class="kv">Target: ${escapeHtml(item.target_contract || '?')} (${escapeHtml(item.target_file || '?')})</div>
                            <details>
                                <summary>Attack Path</summary>
                                <pre>${escapeHtml(JSON.stringify(item.logic_flow || [], null, 2))}</pre>
                            </details>
                        </div>
                    `).join('');
                }

                function renderInvariants(items) {
                    if (!items.length) return '<div class="kv">No invariants extracted.</div>';
                    return items.map((item) => `
                        <div class="card">
                            <h4>${escapeHtml(item.name || 'Unnamed')}</h4>
                            <div class="kv">Target: ${escapeHtml(item.target_contract || '?')} (${escapeHtml(item.target_file || '?')})</div>
                            <p>${escapeHtml(item.description || '')}</p>
                            <details>
                                <summary>Expression Hint</summary>
                                <pre>${escapeHtml(item.expression_hint || '')}</pre>
                            </details>
                        </div>
                    `).join('');
                }

                function renderVerificationSummary(data) {
                    const summary = data.verification_summary || {};
                    const passed = summary.passed ? 'Passed' : 'Failed';
                    const badgeClass = summary.passed ? 'badge ok-badge' : 'badge';
                    return `
                        <div class="card">
                            <div><span class="${badgeClass}">${passed}</span></div>
                            <div class="kv">Attempts: ${escapeHtml(summary.attempt_count ?? 0)}</div>
                            <div class="kv">Last Stage: ${escapeHtml(summary.last_stage || 'N/A')}</div>
                            <div class="kv">Last Return Code: ${escapeHtml(summary.last_returncode ?? 'N/A')}</div>
                            <div class="kv">Last Duration: ${escapeHtml(summary.last_duration_seconds ?? 'N/A')}s</div>
                        </div>
                    `;
                }

                function renderGenerationStrategy(data) {
                    const strategy = data.generation_strategy || {};
                    const mode = strategy.mode || 'unknown';
                    const template = strategy.template_name || 'none';
                    const reason = strategy.reason || 'No strategy reason recorded.';
                    const modeBadge = mode === 'template' ? 'ok-badge' : 'badge';
                    return `
                        <div class="card">
                            <div><span class="badge ${modeBadge}">${escapeHtml(mode)}</span></div>
                            <div class="kv">Template: ${escapeHtml(template)}</div>
                            <div class="kv">Phase: ${escapeHtml(strategy.phase || 'N/A')}</div>
                            <p>${escapeHtml(reason)}</p>
                        </div>
                    `;
                }

                function renderArtifactLinks(downloads) {
                    if (!downloads) return '';
                    const items = [
                        ['Audit Report', downloads.audit_report],
                        ['Verification Report', downloads.verification_report],
                        ['Foundry Suite', downloads.suite],
                    ].filter((item) => item[1]);
                    return items.map(([label, href]) => `<a href="${escapeHtml(href)}" target="_blank" rel="noopener noreferrer">${escapeHtml(label)}</a>`).join('');
                }

                function updateCacheNote(message) {
                    document.getElementById('cache-note').textContent = message || '';
                }

                function updateUploadNote() {
                    const input = document.getElementById('file-input');
                    const note = document.getElementById('upload-note');
                    const selected = Array.from(input.files || []);
                    const active = selected.length
                        ? selected.map((file) => file.name)
                        : restoredFiles.map((file) => file.name + (file.kind === 'zip' ? ' [zip]' : ''));
                    note.textContent = active.length
                        ? `Selected inputs: ${active.join(', ')}`
                        : 'No uploaded files selected. You can choose .sol files, a folder, or a .zip archive.';
                }

                function renderAuditResult(data) {
                    document.getElementById('metrics').classList.remove('hidden');
                    document.getElementById('report-area').classList.remove('hidden');

                    document.getElementById('metric-vulns').textContent = String((data.critical_vulnerabilities || []).length);
                    document.getElementById('metric-invariants').textContent = String((data.invariants || []).length);
                    document.getElementById('metric-verification').textContent = (data.verification_summary || {}).passed ? 'Passed' : 'Failed';
                    document.getElementById('metric-attempts').textContent = String((data.verification_summary || {}).attempt_count ?? 0);

                    document.getElementById('critical-vulns').innerHTML = renderVulnerabilities(data.critical_vulnerabilities || []);
                    document.getElementById('invariants').innerHTML = renderInvariants(data.invariants || []);
                    document.getElementById('generation-strategy').innerHTML = renderGenerationStrategy(data);
                    document.getElementById('verification-summary').innerHTML = renderVerificationSummary(data);
                    document.getElementById('artifact-links').innerHTML = renderArtifactLinks(data.downloads);
                    document.getElementById('verification-log').textContent = data.last_attempt_log || 'No verification log available.';
                    document.getElementById('verification-raw').textContent = JSON.stringify(data.verification || {}, null, 2);
                    document.getElementById('suite-meta').textContent = JSON.stringify({
                        source_mode: data.source_mode,
                        target_files: data.target_files,
                        report_path: data.report_path,
                        verification_report_path: data.verification_report_path,
                        test_suite_path: data.test_suite_path,
                        generated_exploits: data.generated_exploits
                    }, null, 2);
                    document.getElementById('suite-code').textContent = data.test_suite_code || 'No suite generated.';
                }

                function getHistory() {
                    try {
                        return JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]');
                    } catch (e) {
                        return [];
                    }
                }

                function setHistory(history) {
                    localStorage.setItem(HISTORY_KEY, JSON.stringify(history.slice(0, 5)));
                }

                function renderHistory() {
                    const history = getHistory();
                    const container = document.getElementById('history-list');
                    if (!history.length) {
                        container.innerHTML = '<div class="kv">No recent audits saved in this browser.</div>';
                        return;
                    }

                    container.innerHTML = history.map((entry, index) => `
                        <div class="history-item">
                            <h4>${escapeHtml(entry.label || 'Audit')}</h4>
                            <div class="kv">Mode: ${escapeHtml(entry.mode || 'paste')} | Saved: ${escapeHtml(new Date(entry.timestamp).toLocaleString())}</div>
                            <div class="kv">Job ID: ${escapeHtml(entry.job_id || 'sync')}</div>
                            <div class="kv">
                                Vulns: ${escapeHtml(entry.summary?.vulns ?? 0)} |
                                Invariants: ${escapeHtml(entry.summary?.invariants ?? 0)} |
                                Files: ${escapeHtml(entry.summary?.file_count ?? 0)}
                            </div>
                            <div class="kv">
                                <span class="badge ${entry.summary?.verification === 'Passed' ? 'ok-badge' : 'fail-badge'}">${escapeHtml(entry.summary?.verification ?? 'N/A')}</span>
                            </div>
                            <div class="history-actions">
                                <button class="history-button" onclick="restoreHistoryEntry(${index})">Restore</button>
                                ${entry.job_id ? `<button class="history-button" onclick="rePollHistoryEntry(${index})">Re-poll Job</button>` : ''}
                            </div>
                        </div>
                    `).join('');
                }

                async function renderServerJobs() {
                    const container = document.getElementById('server-jobs');
                    try {
                        const res = await fetch('/jobs');
                        const payload = await res.json();
                        const jobs = payload.jobs || [];
                        if (!jobs.length) {
                            container.innerHTML = '<div class="kv">No server-side jobs recorded yet.</div>';
                            return;
                        }

                        container.innerHTML = jobs.map((job) => `
                            <div class="server-job">
                                <h4>${escapeHtml(job.job_id)}</h4>
                                <div class="kv">Status: <span class="badge ${job.status === 'completed' ? 'ok-badge' : (job.status === 'failed' ? 'fail-badge' : '')}">${escapeHtml(job.status || 'unknown')}</span></div>
                                <div class="kv">Stage: ${escapeHtml(job.stage || 'N/A')}</div>
                                <div class="kv">${escapeHtml(job.stage_message || '')}</div>
                                <div class="kv">Updated: ${escapeHtml(job.updated_at || '')}</div>
                                <div class="history-actions">
                                    <button class="history-button" onclick="openServerJob('${job.job_id}')">Open</button>
                                    <button class="history-button" onclick="rePollServerJob('${job.job_id}')">Re-poll</button>
                                    <button class="history-button" onclick="deleteServerJob('${job.job_id}')">Delete</button>
                                </div>
                            </div>
                        `).join('');
                    } catch (e) {
                        container.innerHTML = '<div class="kv">Unable to load server jobs.</div>';
                    }
                }

                function saveHistoryEntry(entry) {
                    const history = getHistory();
                    history.unshift(entry);
                    setHistory(history);
                    renderHistory();
                    renderServerJobs();
                }

                function restoreHistoryEntry(index) {
                    const history = getHistory();
                    const entry = history[index];
                    if (!entry) return;

                    document.getElementById('code').value = entry.code || '';
                    restoredFiles = entry.files || [];
                    document.getElementById('file-input').value = '';
                    updateUploadNote();

                    if (entry.data) {
                        renderAuditResult(entry.data);
                        document.getElementById('status').innerHTML = `<p style="color:#cbd5e1">Restored audit result from ${new Date(entry.timestamp).toLocaleString()}.</p>`;
                    }

                    currentJobId = entry.job_id || null;
                    localStorage.setItem(CACHE_KEY, JSON.stringify(entry));
                    updateCacheNote(`Restored cached audit from ${new Date(entry.timestamp).toLocaleString()}.`);
                }

                function saveCachedAudit(entry) {
                    localStorage.setItem(CACHE_KEY, JSON.stringify(entry));
                    updateCacheNote(`Cached last audit at ${new Date(entry.timestamp).toLocaleString()}.`);
                    saveHistoryEntry(entry);
                }

                function currentStatusLine(job) {
                    const stage = job.stage || job.status || 'unknown';
                    const msg = job.stage_message || '';
                    return `Job ${job.job_id}: ${stage}${msg ? ' — ' + msg : ''}`;
                }

                function clearCurrentAudit() {
                    localStorage.removeItem(CACHE_KEY);
                    restoredFiles = [];
                    document.getElementById('file-input').value = '';
                    document.getElementById('code').value = '';
                    document.getElementById('metrics').classList.add('hidden');
                    document.getElementById('report-area').classList.add('hidden');
                    document.getElementById('status').innerHTML = '<p style="color:#cbd5e1">Cleared current input and current result.</p>';
                    updateCacheNote('');
                    updateUploadNote();
                }

                function clearAuditHistory() {
                    localStorage.removeItem(HISTORY_KEY);
                    renderHistory();
                    document.getElementById('status').innerHTML = '<p style="color:#cbd5e1">Cleared recent audit history.</p>';
                }

                async function openServerJob(jobId) {
                    const res = await fetch(`/jobs/${jobId}`);
                    const job = await res.json();
                    if (job.result) {
                        renderAuditResult(job.result);
                        currentJobId = jobId;
                        document.getElementById('status').innerHTML = `<p style="color:#cbd5e1">Opened server job ${escapeHtml(jobId)}.</p>`;
                    } else {
                        document.getElementById('status').innerHTML = `<p style="color:#facc15">${escapeHtml(currentStatusLine(job))}</p>`;
                    }
                }

                function rePollServerJob(jobId) {
                    currentJobId = jobId;
                    document.getElementById('status').innerHTML = `<p style="color:#facc15">Re-polling server job ${escapeHtml(jobId)}...</p>`;
                    pollJob(jobId, { label: jobId, mode: 'server', code: '', files: [] });
                }

                async function deleteServerJob(jobId) {
                    const res = await fetch(`/jobs/${jobId}`, { method: 'DELETE' });
                    if (res.ok) {
                        if (currentJobId === jobId) {
                            currentJobId = null;
                        }
                        document.getElementById('status').innerHTML = `<p style="color:#cbd5e1">Deleted server job ${escapeHtml(jobId)}.</p>`;
                        renderServerJobs();
                    } else {
                        const payload = await res.json().catch(() => ({}));
                        document.getElementById('status').innerHTML = `<p style="color:#ef4444">Failed to delete server job ${escapeHtml(jobId)}: ${escapeHtml(payload.detail || 'unknown error')}.</p>`;
                    }
                }

                function loadExample(name) {
                    const code = EXAMPLES[name];
                    if (!code) return;
                    currentJobId = null;
                    restoredFiles = [];
                    document.getElementById('file-input').value = '';
                    document.getElementById('code').value = code;
                    updateUploadNote();
                    document.getElementById('status').innerHTML = `<p style="color:#cbd5e1">Loaded example: ${escapeHtml(name)}.</p>`;
                }

                function fileToDataUrl(file) {
                    return new Promise((resolve, reject) => {
                        const reader = new FileReader();
                        reader.onload = () => resolve(reader.result);
                        reader.onerror = () => reject(reader.error);
                        reader.readAsDataURL(file);
                    });
                }

                async function readFileObjects(fileList) {
                    const collected = [];
                    for (const file of fileList) {
                        const name = file.webkitRelativePath || file.name;
                        if (file.name.endsWith('.sol')) {
                            collected.push({
                                name,
                                kind: 'sol',
                                content: await file.text(),
                            });
                            continue;
                        }

                        if (file.name.endsWith('.zip')) {
                            collected.push({
                                name,
                                kind: 'zip',
                                data_url: await fileToDataUrl(file),
                            });
                        }
                    }
                    return collected;
                }

                function dataUrlToBlob(dataUrl) {
                    const [meta, payload] = dataUrl.split(',');
                    const mimeMatch = /data:([^;]+)/.exec(meta || '');
                    const mime = mimeMatch ? mimeMatch[1] : 'application/octet-stream';
                    const bytes = atob(payload);
                    const buffer = new Uint8Array(bytes.length);
                    for (let i = 0; i < bytes.length; i++) {
                        buffer[i] = bytes.charCodeAt(i);
                    }
                    return new Blob([buffer], { type: mime });
                }

                function restoreCachedAudit() {
                    const raw = localStorage.getItem(CACHE_KEY);
                    if (!raw) return;
                    try {
                        const cached = JSON.parse(raw);
                        currentJobId = cached.job_id || null;
                        document.getElementById('code').value = cached.code || '';
                        restoredFiles = cached.files || [];
                        updateUploadNote();
                        if (cached.data) {
                            renderAuditResult(cached.data);
                            document.getElementById('status').innerHTML = `<p style="color:#cbd5e1">Loaded cached audit result from ${new Date(cached.timestamp).toLocaleString()}.</p>`;
                            updateCacheNote(`Cached last audit at ${new Date(cached.timestamp).toLocaleString()}.`);
                        }
                    } catch (e) {
                        localStorage.removeItem(CACHE_KEY);
                    }
                }

                function sleep(ms) {
                    return new Promise((resolve) => setTimeout(resolve, ms));
                }

                async function pollJob(jobId, entryBase) {
                    currentJobId = jobId;

                    while (currentJobId === jobId) {
                        const res = await fetch(`/jobs/${jobId}`);
                        const job = await res.json();

                        if (job.status === 'queued' || job.status === 'running') {
                            document.getElementById('status').innerHTML = `<p style="color:#facc15">${escapeHtml(currentStatusLine(job))}</p>`;
                            await sleep(1500);
                            continue;
                        }

                        if (job.result) {
                            const data = job.result;
                            renderAuditResult(data);
                            currentJobId = jobId;
                            document.getElementById('status').innerHTML = data.error
                                ? `<p style="color:#fb923c">Job ${escapeHtml(jobId)} completed with issues.</p>`
                                : `<p style="color:#4ade80">Job ${escapeHtml(jobId)} completed successfully.</p>`;

                            const entry = {
                                ...entryBase,
                                timestamp: Date.now(),
                                job_id: jobId,
                                data,
                                summary: {
                                    vulns: (data.critical_vulnerabilities || []).length,
                                    invariants: (data.invariants || []).length,
                                    verification: (data.verification_summary || {}).passed ? 'Passed' : 'Failed',
                                    file_count: entryBase.files.length || 1,
                                },
                            };
                            saveCachedAudit(entry);
                            renderServerJobs();
                        } else {
                            document.getElementById('status').innerHTML = `<p style="color:#ef4444">Job ${escapeHtml(jobId)} failed before returning a result.</p>`;
                            renderServerJobs();
                        }
                        return;
                    }
                }

                function rePollHistoryEntry(index) {
                    const history = getHistory();
                    const entry = history[index];
                    if (!entry || !entry.job_id) return;
                    currentJobId = entry.job_id;
                    document.getElementById('status').innerHTML = `<p style="color:#facc15">Re-polling job ${escapeHtml(entry.job_id)}...</p>`;
                    pollJob(entry.job_id, entry);
                }

                async function audit() {
                    const code = document.getElementById('code').value;
                    const status = document.getElementById('status');
                    const inputFiles = Array.from(document.getElementById('file-input').files || []);
                    const selectedFiles = inputFiles.length ? await readFileObjects(inputFiles) : restoredFiles;

                    if (!code.trim() && !selectedFiles.length) return;

                    status.innerHTML = "<p style='color:#facc15'>Submitting job...</p>";
                    document.getElementById('metrics').classList.add('hidden');
                    document.getElementById('report-area').classList.add('hidden');

                    try {
                        const formData = new FormData();
                        if (selectedFiles.length) {
                            for (const file of selectedFiles) {
                                if (file.kind === 'zip' && file.data_url) {
                                    formData.append('files', dataUrlToBlob(file.data_url), file.name);
                                } else {
                                    formData.append('files', new Blob([file.content], { type: 'text/plain' }), file.name);
                                }
                            }
                        } else {
                            formData.append('code', code);
                        }

                        const res = await fetch('/audit/submit', { method: 'POST', body: formData });
                        const job = await res.json();

                        if (job.error) {
                            status.innerHTML = "<p style='color:#fb923c'>Unable to submit: " + job.error + "</p>";
                            return;
                        }

                        status.innerHTML = `<p style='color:#facc15'>Submitted job ${escapeHtml(job.job_id)}. Waiting for result...</p>`;
                        renderServerJobs();
                        const entryBase = {
                            label: selectedFiles.length ? selectedFiles.map((file) => file.name).join(', ') : inferTargetLabel(code),
                            mode: selectedFiles.length ? 'upload' : 'paste',
                            code: selectedFiles.length ? '' : code,
                            files: selectedFiles,
                        };
                        pollJob(job.job_id, entryBase);
                    } catch (e) {
                        status.innerHTML = "<p style='color:#ef4444'>Error: " + e.message + "</p>";
                    }
                }

                function inferTargetLabel(code) {
                    const match = code.match(/(?:abstract\\s+)?(?:contract|interface|library)\\s+([A-Za-z_][A-Za-z0-9_]*)/);
                    return match ? `${match[1]}.sol` : 'PastedTarget.sol';
                }

                document.getElementById('file-input').addEventListener('change', () => {
                    restoredFiles = [];
                    updateUploadNote();
                });

                renderHistory();
                renderServerJobs();
                restoreCachedAudit();
                updateUploadNote();
            </script>
        </body>
    </html>
    """


@app.post("/audit")
async def audit_code(
    code: str = Form(default=""),
    files: list[UploadFile] = File(default=[]),
):
    print("[*] Received synchronous L5 web audit request...")
    cleanup_old_jobs()
    try:
        sync_job_id = uuid.uuid4().hex[:12]
        target_dir, target_files, source_mode, _ = await prepare_target_dir(
            code,
            files,
            target_root=job_target_dir(sync_job_id),
        )
    except ValueError as e:
        return {"error": str(e)}

    create_job_record(sync_job_id, target_files, source_mode)
    response = run_job_pipeline(sync_job_id, target_dir, target_files, source_mode)
    if response is None:
        try:
            return serialize_job(sync_job_id).get("result") or {"error": "Synchronous audit failed."}
        except FileNotFoundError:
            return {"error": "Synchronous audit failed."}
    return response


if __name__ == "__main__":
    import uvicorn

    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run(app, host=host, port=port)
