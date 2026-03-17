# Web3 Auditor Platform

This project combines:

- `L5_Auditor`: the audit and verification engine
- `web3_ai`: the web UI and job runner

## Structure

- `L5_Auditor/`
- `web3_ai/`

## Main Capabilities

- Open-ended Solidity project analysis
- Slither-assisted vulnerability discovery
- Foundry verification generation
- Deterministic verification templates for common vulnerability families
- Background job execution with persisted results
- Web upload support for:
  - pasted Solidity
  - multi-file `.sol`
  - `.zip` Solidity projects

## Current Template Families

- delegatecall / module vault
- inflation vault
- reentrancy bank
- owner / access-control takeover
- fee-accounting vault

## Before You Run

Set environment variables for model access:

- `L5_ANALYST_API_KEY`
- `L5_HACKER_API_KEY`

Optional:

- `L5_ANALYST_API_URL`
- `L5_HACKER_API_URL`
- `L5_ANALYST_MODEL`
- `L5_HACKER_MODEL`
- `L5_TIMEOUT_SECONDS`
- `L5_MAX_REPAIR_ATTEMPTS`
- `WEB3_AI_JOB_TTL_HOURS`
- `WEB3_AI_JOB_LIST_LIMIT`

## Start Web UI

```bash
cd web3_ai
PORT=8001 python3 server.py
```

Then open:

`http://127.0.0.1:8001`

## Operator Docs

See:

- `SETUP_AND_TROUBLESHOOTING.md`
- `L5_Auditor/TEMPLATE_COVERAGE.md`
