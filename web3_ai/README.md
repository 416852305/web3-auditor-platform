# Web3 AI Auditor

`web3_ai` is the web entrypoint for the `L5_Auditor` pipeline.

## What It Does

- Accepts pasted Solidity code
- Accepts multi-file Solidity uploads
- Accepts `.zip` Solidity project uploads
- Runs the `L5_Auditor` pipeline:
  - project load
  - Slither
  - LLM analysis
  - Foundry suite generation
  - Foundry verification
- Stores server-side jobs on disk
- Exposes downloadable artifacts:
  - audit report
  - verification report
  - generated Foundry suite

## Start

Run the web server:

```bash
cd web3_ai
PORT=8001 python3 server.py
```

Open:

`http://127.0.0.1:8001`

## Inputs

The UI supports three modes:

- Paste a single Solidity file into the textarea
- Upload one or more `.sol` files
- Upload a `.zip` archive containing Solidity files

## Outputs

Each completed audit can return:

- Grounded vulnerabilities
- Extracted invariants
- Generation strategy:
  - `template`
  - `llm_fallback`
  - `llm_repair`
- Verification summary
- Generated Foundry suite

Downloaded report files now also include:

- `generation_strategy`
- `verification_summary`

## HTTP Endpoints

UI:

- `GET /`

Synchronous audit:

- `POST /audit`

Background job flow:

- `POST /audit/submit`
- `GET /jobs`
- `GET /jobs/{job_id}`
- `DELETE /jobs/{job_id}`

Artifacts:

- `GET /artifact/audit-report`
- `GET /artifact/verification-report`
- `GET /artifact/suite`
- `GET /artifact/{job_id}/audit-report`
- `GET /artifact/{job_id}/verification-report`
- `GET /artifact/{job_id}/suite`

## Job Storage

Server jobs are stored under:

`web3_ai/runtime_jobs`

Each job has:

- `job.json`
- `response.json`
- isolated `targets/`
- isolated `results/`

Completed and failed jobs are auto-cleaned after the configured TTL.

## Environment

Important env vars:

- `PORT`
- `HOST`
- `WEB3_AI_JOB_TTL_HOURS`
- `WEB3_AI_JOB_LIST_LIMIT`
- `L5_ANALYST_API_KEY`
- `L5_ANALYST_API_URL`
- `L5_ANALYST_MODEL`
- `L5_HACKER_API_KEY`
- `L5_HACKER_API_URL`
- `L5_HACKER_MODEL`
- `L5_TIMEOUT_SECONDS`
- `L5_MAX_REPAIR_ATTEMPTS`

## Notes

- This project now prefers deterministic template-backed verification when a known vulnerability family is matched.
- If no template matches, it falls back to general LLM generation.
- Running jobs cannot be deleted; only completed or failed jobs can be removed.
