# Unified Connectors — Dev Deployment Tool

Automates deploying connector manifests to a dev tenant via GitLab CI/CD.

## Requirements

- **Python 3.10** (the project uses syntax like `list[dict]` and `dict | None` that requires Python 3.10+)
- `gcloud` CLI and `kubectl` (for `create_ucp_instance.py` only)

## Setup

1. Create a virtual environment with Python 3.10 and install dependencies:
   ```bash
   python3.10 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

2. Copy and configure `.env`:
   ```bash
   cp .env.example .env
   # Edit .env — set GITLAB_TOKEN and REPO_DIR at minimum
   ```

3. Create a GitLab personal access token:
   - Go to https://gitlab.xdr.pan.local/-/user_settings/personal_access_tokens
   - Create a token with `api` scope
   - Add it to `.env` as `GITLAB_TOKEN`

## Usage

```bash
python deploy.py                              # Use .env defaults
python deploy.py --tenant 123456              # Override tenant ID
python deploy.py --branch my-branch           # Override branch name
python deploy.py --reason "testing auth"      # Override reason
python deploy.py --skip-git                   # Skip git ops
python deploy.py --repo-dir /path/to/repo     # Override repo path
```

## What it does

1. Creates/resets a git branch from the base branch (default: `dev`)
2. Force-pushes the branch to GitLab
3. Triggers a CI/CD pipeline with `TENANT_ID` and `CONTENT_ONLY=true`
4. Polls the pipeline until completion (~2-5 minutes)
5. Reports success/failure with a summary

## Configuration Priority

CLI args > Environment variables > `.env` file > Built-in defaults

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Pipeline succeeded — content deployed to tenant |
| `1` | Pipeline failed (shows failed jobs) |
| `2` | Timeout exceeded |
https://gitlab.xdr.pan.local/xdr/development/platform/unified-connectors-content/-/pipelines/new?ref=xsoar-test-ui&var%5BTENANT_ID%5D=9995282716924&var%5BOVERRIDE_REASON%5D=test&var%5BCONTENT_ONLY%5D=true