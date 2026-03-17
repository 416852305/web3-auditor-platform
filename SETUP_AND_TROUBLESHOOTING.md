# Setup And Troubleshooting

## Quick Start

1. Install Python dependencies:

```bash
pip install -r requirements.txt
```

2. Set required environment variables:

```bash
export L5_ANALYST_API_KEY=...
export L5_HACKER_API_KEY=...
```

3. Start the web UI:

```bash
cd web3_ai
PORT=8001 python3 server.py
```

4. Open:

`http://127.0.0.1:8001`

## Required Local Tools

- `python3`
- `git`
- `forge`
- `slither`

`forge-std` is already vendored under:

`L5_Auditor/lib/forge-std`

## Common Problems

### 1. Analyst or Hacker stage returns empty results

Check:

- `L5_ANALYST_API_KEY`
- `L5_HACKER_API_KEY`
- network access from the machine

The code now refuses to call the model endpoints if the corresponding key is missing.

### 2. Port 8001 is already in use

Use a different port:

```bash
PORT=8010 python3 server.py
```

### 3. `/jobs` keeps growing

Server-side jobs are stored under:

`web3_ai/runtime_jobs`

Auto-clean behavior:

- only completed / failed jobs are eligible
- default TTL is `24` hours

Tune with:

```bash
export WEB3_AI_JOB_TTL_HOURS=12
```

### 4. Running jobs cannot be deleted

This is intentional.

- `queued` and `running` jobs return `409` on delete
- only completed / failed jobs can be removed

### 5. Template not used

The system always does open-ended analysis first.

Then:

- if a known pattern is matched, it uses deterministic template-backed verification
- otherwise it falls back to general LLM generation

Current template families are documented in:

`L5_Auditor/TEMPLATE_COVERAGE.md`

### 6. Foundry verification fails on a new project

This usually means one of these:

- the project falls outside current template families
- the fallback LLM-generated harness was not stable enough
- the target uses a pattern not yet templated

In that case:

- inspect `L5_Verification_Report.json`
- inspect the generated `L5_Invariant_Suite.t.sol`
- decide whether to add a new template family

### 7. GitHub push over HTTPS fails

Use SSH.

Typical workflow:

1. generate SSH key
2. add public key in GitHub SSH settings
3. switch remote to `git@github.com:USER/REPO.git`
4. push again

## Useful Files

- main project README: `README.md`
- web UI README: `web3_ai/README.md`
- template coverage: `L5_Auditor/TEMPLATE_COVERAGE.md`
- env example: `.env.example`

## Recommended Production Cleanup

Before broader deployment, still consider:

- process manager for `server.py`
- reverse proxy and HTTPS
- rate limiting for upload endpoints
- artifact retention policy
- rotating API keys
