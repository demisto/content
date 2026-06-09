#!/usr/bin/env python3
"""
Unified Connectors Content — Dev Deployment Tool

Automates: branch creation → push → pipeline trigger → poll → report

Configuration priority: CLI args > env vars > .env file > defaults
"""

import os
import sys
import json
import time
import argparse
import subprocess
from pathlib import Path
import requests as req_lib
from urllib.parse import quote

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from dotenv import load_dotenv

# Load .env from the script's own directory (works regardless of CWD)
_SCRIPT_DIR = Path(__file__).resolve().parent
load_dotenv()


# ── Colors ──────────────────────────────────────────────────────────────────

class Colors:
    BOLD = "\033[1m" if sys.stdout.isatty() else ""
    GREEN = "\033[92m" if sys.stdout.isatty() else ""
    RED = "\033[91m" if sys.stdout.isatty() else ""
    YELLOW = "\033[93m" if sys.stdout.isatty() else ""
    CYAN = "\033[96m" if sys.stdout.isatty() else ""
    DIM = "\033[2m" if sys.stdout.isatty() else ""
    RESET = "\033[0m" if sys.stdout.isatty() else ""


def info(msg):
    print(f"{Colors.CYAN}▸{Colors.RESET} {msg}")


def success(msg):
    print(f"{Colors.GREEN}✔{Colors.RESET} {msg}")


def warn(msg):
    print(f"{Colors.YELLOW}⚠{Colors.RESET} {msg}")


def error(msg):
    print(f"{Colors.RED}✖{Colors.RESET} {msg}", file=sys.stderr)


def header(msg):
    print(f"\n{Colors.BOLD}{msg}{Colors.RESET}")
    print("─" * 50)


# ── Configuration ───────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="Deploy unified-connectors-content to a dev tenant",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                              # Use .env defaults
  %(prog)s --tenant 123456              # Override tenant IDs (comma-separated)
  %(prog)s --branch my-branch           # Override branch name
  %(prog)s --reason "testing auth"      # Override reason
  %(prog)s --skip-git                   # Skip git ops, just trigger pipeline
  %(prog)s --repo-dir /path/to/repo     # Override repo directory

Environment variables (set in .env or shell):
  GITLAB_URL, GITLAB_TOKEN, CONNECTUS_REPO_DIR, CONNECTUS_BRANCH,
  BASE_BRANCH, TENANT_IDS, OVERRIDE_REASON
  (PROJECT_PATH is hardcoded; POLL_INTERVAL/MAX_WAIT are CLI-only.)
        """,
    )
    parser.add_argument("--gitlab-url", default=None, help="GitLab instance URL")
    parser.add_argument("--token", default=None, help="GitLab personal access token")
    parser.add_argument("--project", default=None, help="GitLab project path (defaults to the hardcoded PROJECT_PATH)")
    parser.add_argument("--repo-dir", default=None, help="Path to the local unified-connectors-content repo (overrides CONNECTUS_REPO_DIR)")
    parser.add_argument("--branch", default=None, help="Branch IN THE CONNECTUS REPO to create/force-push (overrides CONNECTUS_BRANCH)")
    parser.add_argument("--base", default=None, help="Base branch; CONNECTUS_BRANCH is HARD-RESET (git reset --hard) to origin/<base> on every deploy")
    parser.add_argument("--tenant", default=None, help="Comma-separated tenant IDs for dev override")
    parser.add_argument("--reason", default=None, help="Override reason")
    parser.add_argument("--skip-git", action="store_true", help="Skip git operations")
    parser.add_argument("--poll-interval", type=int, default=None, help="Seconds between status polls")
    parser.add_argument("--max-wait", type=int, default=None, help="Max seconds to wait for pipeline")
    parser.add_argument("--diagnose", action="store_true", help="Run connectivity diagnostics and exit")
    return parser.parse_args()


# The GitLab project that hosts unified-connectors-content. Hardcoded — there is
# only ever one project; it does not vary per developer.
PROJECT_PATH = "xdr/development/platform/unified-connectors-content"

# Polling defaults (seconds). Not exposed as env vars — override via --poll-interval
# / --max-wait if ever needed.
DEFAULT_POLL_INTERVAL = 2
DEFAULT_MAX_WAIT = 600


def get_config(args):
    """Build config from env vars (loaded by dotenv) with CLI overrides.

    Env vars consumed:
      * CONNECTUS_REPO_DIR — local clone of the unified-connectors-content repo
        (git ops run here). REQUIRED for git operations.
      * CONNECTUS_BRANCH — branch IN THE CONNECTUS REPO that is force-pushed +
        deployed. REQUIRED for git operations.
      * BASE_BRANCH — what CONNECTUS_BRANCH is HARD-RESET to on every deploy.
      * TENANT_ID (single tenant; sent to the GitLab pipeline as TENANT_IDS),
        OVERRIDE_REASON, GITLAB_URL, GITLAB_TOKEN.
    PROJECT_PATH is hardcoded; POLL_INTERVAL/MAX_WAIT are CLI-only.
    """
    return {
        "gitlab_url": args.gitlab_url or os.getenv("GITLAB_URL", "https://gitlab.xdr.pan.local"),
        "gitlab_token": args.token or os.getenv("GITLAB_TOKEN", ""),
        "project_path": args.project or PROJECT_PATH,
        "repo_dir": args.repo_dir or os.getenv("CONNECTUS_REPO_DIR", ""),
        "branch_name": args.branch or os.getenv("CONNECTUS_BRANCH", "xsoar"),
        "base_branch": args.base or os.getenv("BASE_BRANCH", "stable"),
        # Single tenant per shell. Input var is TENANT_ID; it is sent to the
        # GitLab pipeline as the CI-expected `TENANT_IDS` variable (see
        # trigger_pipeline). --tenant overrides.
        "tenant_ids": args.tenant or os.getenv("TENANT_ID", ""),
        "override_reason": args.reason or os.getenv("OVERRIDE_REASON", "dev-testing"),
        "poll_interval": args.poll_interval if args.poll_interval is not None else DEFAULT_POLL_INTERVAL,
        "max_wait": args.max_wait if args.max_wait is not None else DEFAULT_MAX_WAIT,
        "skip_git": args.skip_git,
        "diagnose": args.diagnose,
    }


def validate_config(config):
    """Validate required configuration values."""
    if not config["gitlab_token"] or config["gitlab_token"] == "your-gitlab-personal-access-token":
        error("GITLAB_TOKEN is required")
        print(f"  Set it in {_SCRIPT_DIR / '.env'} or via --token flag")
        print(f"  Create a token at: {config['gitlab_url']}/-/user_settings/personal_access_tokens")
        print(f"  Required scope: {Colors.BOLD}api{Colors.RESET}")
        sys.exit(1)

    if not config["skip_git"] and not config["repo_dir"]:
        error("CONNECTUS_REPO_DIR is required for git operations")
        print(f"  Set it in {_SCRIPT_DIR / '.env'} or via --repo-dir flag")
        print(f"  Or use --skip-git to skip git operations")
        sys.exit(1)

    if not config["skip_git"] and not Path(config["repo_dir"]).is_dir():
        error(f"CONNECTUS_REPO_DIR does not exist: {config['repo_dir']}")
        sys.exit(1)


# ── Diagnostics ─────────────────────────────────────────────────────────────

def run_diagnostics(config):
    """Run connectivity diagnostics against GitLab."""
    import socket
    import ssl
    from urllib.parse import urlparse

    header("Connectivity Diagnostics")
    gitlab_url = config["gitlab_url"]
    parsed = urlparse(gitlab_url)
    hostname = parsed.hostname
    port = parsed.port or 443

    # Test 1: DNS Resolution
    info(f"Test 1: DNS resolution for '{hostname}'...")
    try:
        ip = socket.gethostbyname(hostname)
        success(f"DNS resolved: {hostname} → {ip}")
    except socket.gaierror as e:
        error(f"DNS resolution failed: {e}")
        print("  → You may not be connected to the corporate network/VPN")
        return

    # Test 2: TCP Connection
    info(f"Test 2: TCP connection to {hostname}:{port}...")
    try:
        sock = socket.create_connection((hostname, port), timeout=10)
        sock.close()
        success(f"TCP connection successful to {hostname}:{port}")
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        error(f"TCP connection failed: {e}")
        print("  → The server may be down or a firewall is blocking the connection")
        return

    # Test 3: SSL/TLS Handshake
    info(f"Test 3: SSL/TLS handshake with {hostname}:{port}...")
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                success(f"SSL handshake successful (protocol: {ssock.version()})")
    except ssl.SSLError as e:
        error(f"SSL handshake failed: {e}")
        print("  → There may be an SSL/TLS incompatibility")
        return
    except Exception as e:
        error(f"SSL test failed: {e}")
        return

    # Test 4: Simple HTTPS GET to GitLab API
    info(f"Test 4: HTTPS GET to {gitlab_url}/api/v4/version ...")
    try:
        resp = req_lib.get(f"{gitlab_url}/api/v4/version",
                          headers={"PRIVATE-TOKEN": config["gitlab_token"]},
                          verify=False, timeout=15)
        success(f"HTTP {resp.status_code}: {resp.text[:200]}")
    except Exception as e:
        error(f"HTTPS GET failed: {e}")
        print("  → The requests library cannot reach the GitLab API")
        return

    # Test 5: Test the actual pipeline endpoint with a dry-run (GET to list pipelines)
    info(f"Test 5: GET pipelines list from project...")
    api_base = get_api_base(config)
    try:
        resp = req_lib.get(f"{api_base}/pipelines?per_page=1",
                          headers={"PRIVATE-TOKEN": config["gitlab_token"]},
                          verify=False, timeout=15)
        success(f"HTTP {resp.status_code}: {resp.text[:200]}")
    except Exception as e:
        error(f"Pipeline list request failed: {e}")
        return

    # Test 6: Try the actual POST to trigger pipeline
    info(f"Test 6: POST to pipeline trigger endpoint...")
    try:
        data = {
            "ref": config["branch_name"],
            "variables": [
                {"key": "SKINNY_PIPELINE", "value": "true"},
                {"key": "TENANT_IDS", "value": config["tenant_ids"]},
                {"key": "OVERRIDE_REASON", "value": config["override_reason"]},
            ],
        }
        resp = req_lib.post(f"{api_base}/pipeline",
                           headers={"PRIVATE-TOKEN": config["gitlab_token"],
                                    "Content-Type": "application/json"},
                           json=data,
                           verify=False, timeout=30)
        if resp.status_code < 400:
            success(f"HTTP {resp.status_code}: Pipeline triggered successfully!")
            print(f"  Response: {resp.text[:500]}")
        else:
            warn(f"HTTP {resp.status_code}: {resp.text[:500]}")
    except Exception as e:
        error(f"Pipeline trigger failed: {e}")
        print(f"  Error type: {type(e).__name__}")
        print(f"  → This confirms the issue is with the POST request to the pipeline endpoint")

    print()
    info("Diagnostics complete.")


# ── GitLab API ──────────────────────────────────────────────────────────────

def get_api_base(config):
    encoded = quote(config["project_path"], safe="")
    return f"{config['gitlab_url']}/api/v4/projects/{encoded}"


def api_request(config, method, path, data=None):
    """Make a GitLab API request."""
    url = f"{get_api_base(config)}{path}"
    headers = {"PRIVATE-TOKEN": config["gitlab_token"]}
    
    try:
        response = req_lib.request(
            method, url, headers=headers, json=data if data else None,
            timeout=30, verify=False
        )
        if response.status_code == 401:
            error("Authentication failed (401)")
            print(f"  Check your GITLAB_TOKEN has 'api' scope")
            print(f"  Token URL: {config['gitlab_url']}/-/user_settings/personal_access_tokens")
            sys.exit(1)
        elif response.status_code == 404:
            error(f"Project not found (404): {config['project_path']}")
            print(f"  Check PROJECT_PATH in your .env")
            sys.exit(1)
        
        response.raise_for_status()
        return response.json()
    except req_lib.exceptions.ConnectionError as e:
        error(f"Network error: {e}")
        print(f"  Check GITLAB_URL: {config['gitlab_url']}")
        print(f"  Ensure you're connected to the corporate network / VPN")
        sys.exit(1)
    except req_lib.exceptions.HTTPError as e:
        error(f"GitLab API error ({response.status_code}): {response.text}")
        sys.exit(1)


# ── Git Operations ──────────────────────────────────────────────────────────

def run_git(config, *args):
    """Run a git command in the repo directory."""
    cmd = ["git"] + list(args)
    result = subprocess.run(
        cmd,
        cwd=config["repo_dir"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        error(f"Git command failed: {' '.join(cmd)}")
        if result.stderr:
            print(f"  {result.stderr.strip()}")
        return False, result.stderr
    return True, result.stdout.strip()


def git_operations(config):
    """Create/reset branch and push to GitLab."""
    header("Step 1: Git Operations")
    branch = config["branch_name"]
    base = config["base_branch"]

    # Fetch latest
    info(f"Fetching from origin...")
    ok, _ = run_git(config, "fetch", "origin")
    if not ok:
        error("Failed to fetch from origin")
        print("  Check your SSH keys or git credentials")
        sys.exit(1)
    success("Fetched latest from origin")

    # Check if branch exists locally
    ok, _ = run_git(config, "show-ref", "--verify", "--quiet", f"refs/heads/{branch}")
    if ok:
        info(f"Branch '{branch}' exists locally, resetting to origin/{base}...")
        run_git(config, "checkout", branch)
        run_git(config, "reset", "--hard", f"origin/{base}")
    else:
        info(f"Creating branch '{branch}' from origin/{base}...")
        ok, err = run_git(config, "checkout", "-b", branch, f"origin/{base}")
        if not ok:
            error(f"Failed to create branch '{branch}'")
            sys.exit(1)
    success(f"Branch '{branch}' ready (based on origin/{base})")

    # Force push
    info(f"Pushing '{branch}' to origin...")
    ok, err = run_git(config, "push", "origin", branch, "--force")
    if not ok:
        error(f"Failed to push branch '{branch}'")
        print("  Check your SSH keys or git credentials")
        sys.exit(1)
    success(f"Pushed '{branch}' to origin")


# ── Pipeline Operations ────────────────────────────────────────────────────

def trigger_pipeline(config):
    """Trigger a GitLab CI/CD skinny pipeline."""
    header("Step 2: Trigger Connector Deploy Pipeline")
    info(f"Triggering skinny pipeline on branch '{config['branch_name']}'...")
    info(f"  Tenant IDs: {config['tenant_ids']}")
    info(f"  Reason: {config['override_reason']}")

    data = {
        "ref": config["branch_name"],
        "variables": [
            {"key": "SKINNY_PIPELINE", "value": "true"},
            {"key": "TENANT_IDS", "value": config["tenant_ids"]},
            {"key": "OVERRIDE_REASON", "value": config["override_reason"]},
        ],
    }

    result = api_request(config, "POST", "/pipeline", data)
    pipeline_id = result["id"]
    pipeline_url = result["web_url"]

    success(f"Pipeline #{pipeline_id} created (skinny pipeline)")
    info(f"URL: {pipeline_url}")
    return pipeline_id, pipeline_url


def poll_pipeline(config, pipeline_id):
    """Poll pipeline status until completion or timeout."""
    header("Step 3: Waiting for Connector Deploy Pipeline To Complete")
    terminal_states = {"success", "failed", "canceled"}
    start = time.time()
    last_status = ""

    while True:
        elapsed = time.time() - start
        if elapsed > config["max_wait"]:
            print()
            warn(f"Timeout after {int(elapsed)}s (max: {config['max_wait']}s)")
            return "timeout", elapsed

        result = api_request(config, "GET", f"/pipelines/{pipeline_id}")
        status = result["status"]

        if status != last_status:
            if last_status:
                print()  # newline after previous \r line
            timestamp = time.strftime("%H:%M:%S")
            info(f"[{timestamp}] Status: {Colors.YELLOW}{status}{Colors.RESET}")
            last_status = status
        else:
            timestamp = time.strftime("%H:%M:%S")
            dots = "." * (int(elapsed) % 4)
            print(f"  {Colors.DIM}[{timestamp}] {status}{dots}{' ' * 4}{Colors.RESET}", end="\r", flush=True)

        if status in terminal_states:
            print()
            return status, elapsed

        time.sleep(config["poll_interval"])


def get_failed_jobs(config, pipeline_id):
    """Get list of failed jobs for a pipeline."""
    try:
        jobs = api_request(config, "GET", f"/pipelines/{pipeline_id}/jobs")
        return [
            {"name": j["name"], "stage": j["stage"], "url": j.get("web_url", "")}
            for j in jobs
            if j["status"] == "failed"
        ]
    except SystemExit:
        return []


# ── Summary ─────────────────────────────────────────────────────────────────

def print_summary(config, pipeline_url, status_text, duration, failed_jobs=None):
    """Print a formatted deployment summary."""
    header("Step 4: Deployment Summary")

    duration_str = f"{int(duration)}s"
    if duration > 60:
        mins = int(duration) // 60
        secs = int(duration) % 60
        duration_str = f"{mins}m {secs}s"

    print(f"╔{'═' * 56}╗")
    print(f"║  {'Branch:':<14} {config['branch_name']:<38} ║")
    print(f"║  {'Base:':<14} {config['base_branch']:<38} ║")
    print(f"║  {'Tenant IDs:':<14} {config['tenant_ids']:<38} ║")
    print(f"║  {'Reason:':<14} {config['override_reason']:<38} ║")
    print(f"║  {'Duration:':<14} {duration_str:<38} ║")
    print(f"║  {'Status:':<14} {status_text:<38} ║")
    print(f"╠{'═' * 56}╣")
    print(f"║  Pipeline: {pipeline_url:<43} ║" if len(pipeline_url) <= 43 else f"║  Pipeline:{' ' * 45}║\n║  {pipeline_url:<54} ║")
    print(f"╚{'═' * 56}╝")

    if failed_jobs:
        print(f"\n{Colors.RED}Failed jobs:{Colors.RESET}")
        for job in failed_jobs:
            print(f"  {Colors.RED}✖{Colors.RESET} {job['name']} ({job['stage']})")
            if job.get("url"):
                print(f"    {Colors.DIM}{job['url']}{Colors.RESET}")


# ── Main ────────────────────────────────────────────────────────────────────

def main():
    args = parse_args()
    config = get_config(args)
    validate_config(config)

    if config["diagnose"]:
        run_diagnostics(config)
        sys.exit(0)

    print(f"\n{Colors.BOLD}🚀 Unified Connectors — Dev Deployment{Colors.RESET}")
    print(f"{Colors.DIM}Config: {_SCRIPT_DIR / '.env'}{Colors.RESET}\n")

    # Step 1: Git operations — reset the branch from origin/<base> and force-push
    # the connector-manifest branch so the pipeline deploys FROM that branch. This
    # push step had been dropped from main(); without it the pipeline runs against a
    # stale remote branch. Honored unless --skip-git is passed (re-trigger only).
    if not config["skip_git"]:
        git_operations(config)

    # Step 2: Trigger pipeline
    pipeline_id, pipeline_url = trigger_pipeline(config)

    # Step 3: Poll for completion
    status, duration = poll_pipeline(config, pipeline_id)

    # Step 4: Report
    if status == "timeout":
        print_summary(config, pipeline_url, "⏰ timeout", duration)
        print(f"\n{Colors.YELLOW}Pipeline is still running. Check the URL above.{Colors.RESET}")
        sys.exit(2)
    elif status == "success":
        print_summary(config, pipeline_url, f"{Colors.GREEN}✅ success{Colors.RESET}", duration)
        print(f"\n{Colors.GREEN}Content deployed to tenant(s) {config['tenant_ids']}!{Colors.RESET}")
        sys.exit(0)
    else:
        failed_jobs = get_failed_jobs(config, pipeline_id)
        print_summary(config, pipeline_url, f"{Colors.RED}❌ {status}{Colors.RESET}", duration, failed_jobs)
        sys.exit(1)


if __name__ == "__main__":
    main()
