#!/usr/bin/env python3
"""
Unified Connectors Content — Dev Deployment Tool

Automates: branch creation → push → pipeline trigger → poll → report

Configuration priority: CLI args > env vars > .env file > defaults
"""

import os
import re
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

# Make the shared connectus env loader importable (connectus/ is not a package).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from env_loader import load_env  # noqa: E402

# Load the canonical root .env via the single unified loader.
_ENV_PATH = load_env()


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
  %(prog)s --skip-git                   # Skip git ops, just trigger pipeline
  %(prog)s --repo-dir /path/to/repo     # Override repo directory

Environment variables (set in .env or shell):
  GITLAB_TOKEN, CONNECTUS_REPO_DIR, CONNECTUS_BRANCH, TENANT_ID
  (PROJECT_PATH, GITLAB_URL and OVERRIDE_REASON are hardcoded;
   POLL_INTERVAL/MAX_WAIT are CLI-only.)
        """,
    )
    parser.add_argument("--token", default=None, help="GitLab personal access token")
    parser.add_argument("--project", default=None, help="GitLab project path (defaults to the hardcoded PROJECT_PATH)")
    parser.add_argument("--repo-dir", default=None, help="Path to the local unified-connectors-content repo (overrides CONNECTUS_REPO_DIR)")
    parser.add_argument("--branch", default=None, help="Personal branch IN THE CONNECTUS REPO to commit+push (must be xsoar-migration-<name>; overrides CONNECTUS_BRANCH)")
    parser.add_argument("--tenant", default=None, help="Comma-separated tenant IDs for dev override")
    parser.add_argument("--skip-git", action="store_true", help="Skip git operations")
    parser.add_argument("--skip-pipeline", action="store_true", help="Skip triggering/polling the GitLab pipeline (upload packs only).")
    parser.add_argument("--poll-interval", type=int, default=None, help="Seconds between status polls")
    parser.add_argument("--max-wait", type=int, default=None, help="Max seconds to wait for pipeline")
    parser.add_argument("--diagnose", action="store_true", help="Run connectivity diagnostics and exit")
    parser.add_argument("--ssh-key", default=None, help="Path to the SSH private key git should use (overrides CONNECTUS_SSH_KEY; default ~/.ssh/id_ed25519)")
    parser.add_argument("--commit-path", default=None, help="Repo-relative path of the connector dir to stage+commit before pushing (e.g. connectors/aws). If unset, no commit is made (assumes content already committed).")
    parser.add_argument("--upload-pack", action="append", default=None, dest="upload_packs", help="Content-repo pack dir to upload to the tenant via demisto-sdk BEFORE the connector deploy (repeatable, e.g. Packs/Base, Packs/AMP). Removes the manual 'upload Base + integration pack' prerequisite. If unset, no packs are uploaded.")
    parser.add_argument("--upload-insecure", action="store_true", help="Pass --insecure to demisto-sdk upload (skip TLS cert validation). Needed for tenants with a self-signed cert in the chain.")
    parser.add_argument("--skip-pack-upload", action="store_true", help="Skip the pack-upload step even if --upload-pack is given (e.g. packs already current on the tenant).")
    return parser.parse_args()


# The GitLab project that hosts unified-connectors-content. Hardcoded — there is
# only ever one project; it does not vary per developer.
PROJECT_PATH = "xdr/development/platform/unified-connectors-content"

# GitLab base URL for triggering the deploy pipeline. Hardcoded — there is only
# ever one GitLab instance; it does not vary per developer.
GITLAB_URL = "https://gitlab.xdr.pan.local"

# Reason recorded for the deploy override in the GitLab pipeline. Hardcoded — all
# deploys from this tooling are xsoar migration testing.
OVERRIDE_REASON = "xsoar migration testing"

# Personal-branch rule: every engineer deploys ONLY to their own long-lived
# branch `xsoar-migration-<name>`. The deploy commits + pushes this branch, so
# this guard makes it IMPOSSIBLE to commit/push to a shared/protected branch
# (stable, dev, master, xsoar-playground, etc.) even if preflight is skipped.
BRANCH_PATTERN = re.compile(r"^xsoar-migration-[a-z0-9][a-z0-9-]*$")

# Polling defaults (seconds). Not exposed as env vars — override via --poll-interval
# / --max-wait if ever needed.
DEFAULT_POLL_INTERVAL = 2
DEFAULT_MAX_WAIT = 600


def _assert_personal_branch(branch: str) -> None:
    """Hard guardrail: refuse to operate on any branch that is not a personal
    `xsoar-migration-<name>` branch. Called before ANY commit/push."""
    if not branch or not BRANCH_PATTERN.match(branch):
        error(f"Refusing to deploy: branch {branch!r} is not a personal "
              f"'xsoar-migration-<name>' branch (lowercase, e.g. "
              f"xsoar-migration-joey). The deploy commits + pushes this branch; "
              f"only a personal, namespaced branch is allowed.")
        sys.exit(1)


def get_config(args):
    """Build config from env vars (loaded by dotenv) with CLI overrides.

    Env vars consumed:
      * CONNECTUS_REPO_DIR — local clone of the unified-connectors-content repo
        (git ops run here). REQUIRED for git operations.
      * CONNECTUS_BRANCH — the engineer's PERSONAL branch (xsoar-migration-<name>)
        that is committed to and fast-forward pushed + deployed. REQUIRED for git ops.
      * TENANT_ID (single tenant; sent to the GitLab pipeline as TENANT_IDS),
        GITLAB_TOKEN.
    PROJECT_PATH, GITLAB_URL and OVERRIDE_REASON are hardcoded;
    POLL_INTERVAL/MAX_WAIT are CLI-only.
    """
    return {
        "gitlab_url": GITLAB_URL,
        "gitlab_token": args.token or os.getenv("GITLAB_TOKEN", ""),
        "project_path": args.project or PROJECT_PATH,
        "repo_dir": args.repo_dir or os.getenv("CONNECTUS_REPO_DIR", ""),
        "branch_name": args.branch or os.getenv("CONNECTUS_BRANCH", "xsoar"),
        # Single tenant per shell. Input var is TENANT_ID; it is sent to the
        # GitLab pipeline as the CI-expected `TENANT_IDS` variable (see
        # trigger_pipeline). --tenant overrides.
        "tenant_ids": args.tenant or os.getenv("TENANT_ID", ""),
        "override_reason": OVERRIDE_REASON,
        "poll_interval": args.poll_interval if args.poll_interval is not None else DEFAULT_POLL_INTERVAL,
        "max_wait": args.max_wait if args.max_wait is not None else DEFAULT_MAX_WAIT,
        "skip_git": args.skip_git,
        "skip_pipeline": args.skip_pipeline,
        "diagnose": args.diagnose,
        # SSH key git should use, so auth does NOT depend on a pre-loaded
        # ssh-agent. Empty = use default resolution (~/.ssh/id_ed25519, id_rsa).
        "ssh_key": args.ssh_key or os.getenv("CONNECTUS_SSH_KEY", ""),
        # Repo-relative connector dir staged+committed before the fast-forward push.
        # Comes from --commit-path only (deploy_and_test.py derives it from the
        # integration id via the resolver); it is NOT an env var.
        # Empty = no commit (assumes content already committed).
        "commit_path": args.commit_path or "",
        # Content-repo pack dirs uploaded to the tenant (via demisto-sdk) BEFORE
        # the connector deploy, so deploying no longer requires the engineer to
        # manually upload the patched Base pack + the integration's own pack.
        # Comes from --upload-pack only (deploy_and_test.py derives them from the
        # integration id via the resolver); empty list = upload nothing.
        "upload_packs": list(args.upload_packs or []),
        # Skip TLS cert validation for the upload (self-signed tenant cert).
        "upload_insecure": args.upload_insecure,
        # Bypass the upload step even if packs were supplied.
        "skip_pack_upload": args.skip_pack_upload,
    }


def validate_config(config):
    """Validate required configuration values."""
    if not config["gitlab_token"] or config["gitlab_token"] == "your-gitlab-personal-access-token":
        error("GITLAB_TOKEN is required")
        print(f"  Set it in {_ENV_PATH} or via --token flag")
        print(f"  Create a token at: {config['gitlab_url']}/-/user_settings/personal_access_tokens")
        print(f"  Required scope: {Colors.BOLD}api{Colors.RESET}")
        sys.exit(1)

    if not config["skip_git"] and not config["repo_dir"]:
        error("CONNECTUS_REPO_DIR is required for git operations")
        print(f"  Set it in {_ENV_PATH} or via --repo-dir flag")
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

def _git_ssh_command(config) -> str | None:
    """Build a GIT_SSH_COMMAND that forces git to use an explicit key, so git
    does NOT depend on a pre-loaded ssh-agent. Resolves the key from config
    ssh_key (CONNECTUS_SSH_KEY / --ssh-key) else the first existing default
    (~/.ssh/id_ed25519, ~/.ssh/id_rsa). Returns None if no key file is found
    (let ssh fall back to its own default behavior / agent)."""
    candidates = []
    if config.get("ssh_key"):
        candidates.append(Path(config["ssh_key"]).expanduser())
    candidates += [
        Path("~/.ssh/id_ed25519").expanduser(),
        Path("~/.ssh/id_rsa").expanduser(),
        Path("~/.ssh/id_ecdsa").expanduser(),
    ]
    for key in candidates:
        if key.is_file():
            return f"ssh -i {key} -o IdentitiesOnly=yes"
    return None


def run_git(config, *args):
    """Run a git command in the repo directory."""
    cmd = ["git"] + list(args)
    # Inject GIT_SSH_COMMAND for the subprocess WITHOUT clobbering the rest of
    # the environment, so git auth works without a loaded ssh-agent. Respect an
    # already-set GIT_SSH_COMMAND in the environment.
    env = os.environ.copy()
    ssh_cmd = _git_ssh_command(config)
    if ssh_cmd and "GIT_SSH_COMMAND" not in env:
        env["GIT_SSH_COMMAND"] = ssh_cmd
    result = subprocess.run(
        cmd,
        cwd=config["repo_dir"],
        capture_output=True,
        text=True,
        env=env,
    )
    if result.returncode != 0:
        error(f"Git command failed: {' '.join(cmd)}")
        if result.stderr:
            print(f"  {result.stderr.strip()}")
        return False, result.stderr
    return True, result.stdout.strip()


def git_operations(config):
    """Commit the connector dir to the engineer's personal branch and push.

    Branch model (simple + safe):
      * Each engineer works on ONE long-lived personal branch
        (``xsoar-migration-<name>``, enforced by preflight).
      * There is NO base branch and NO ``reset --hard``. We never overwrite
        local/remote history. The engineer is responsible for keeping their
        branch current (``git rebase origin/stable`` when they want stable's
        changes) — the deploy does not do it for them.
      * The push is a PLAIN, fast-forward-only ``git push`` (never ``--force``).
        If it is rejected as non-fast-forward, the engineer's local branch is
        behind its own remote → they must rebase/pull first. We never force.
    """
    header("Step 1: Git Operations")
    branch = config["branch_name"]

    # HARD GUARDRAIL: never commit/push to anything but a personal branch. Runs
    # before fetch/checkout/commit/push so even --skip-preflight cannot bypass it.
    _assert_personal_branch(branch)

    # Fetch latest (so the remote-tracking ref for the branch is current).
    info(f"Fetching from origin...")
    ok, _ = run_git(config, "fetch", "origin")
    if not ok:
        error("Failed to fetch from origin")
        print("  Check your SSH keys or git credentials")
        sys.exit(1)
    success("Fetched latest from origin")

    # Check out the engineer's personal branch WITHOUT resetting it.
    #   * local exists            → checkout (keep its history).
    #   * remote exists only      → create local tracking origin/<branch>.
    #   * neither exists          → create a fresh branch at current HEAD.
    local_ok, _ = run_git(config, "show-ref", "--verify", "--quiet", f"refs/heads/{branch}")
    if local_ok:
        info(f"Checking out existing local branch '{branch}' (no reset)...")
        ok, err = run_git(config, "checkout", branch)
        if not ok:
            error(f"Failed to checkout branch '{branch}'")
            sys.exit(1)
    else:
        remote_ok, _ = run_git(
            config, "show-ref", "--verify", "--quiet", f"refs/remotes/origin/{branch}"
        )
        if remote_ok:
            info(f"Creating local '{branch}' tracking origin/{branch} (no reset)...")
            ok, err = run_git(config, "checkout", "-b", branch, f"origin/{branch}")
        else:
            info(f"Branch '{branch}' is new — creating it at current HEAD...")
            ok, err = run_git(config, "checkout", "-b", branch)
        if not ok:
            error(f"Failed to create branch '{branch}'")
            sys.exit(1)
    success(f"On branch '{branch}'")

    # Stage + commit ONLY the connector dir for the integration being deployed.
    commit_path = config.get("commit_path")
    if commit_path:
        info(f"Staging connector path: {commit_path}")
        ok, err = run_git(config, "add", "--", commit_path)
        if not ok:
            error(f"Failed to stage {commit_path}")
            sys.exit(1)
        # Commit only if something is actually staged (avoid 'nothing to commit'
        # failure). `git diff --cached --quiet` exits 0 when NOTHING is staged
        # and 1 when there ARE staged changes. run_git returns ok=True on rc==0,
        # so ok==True here means "nothing staged" → skip the commit.
        nothing_staged, _ = run_git(config, "diff", "--cached", "--quiet")
        if nothing_staged:
            info("No connector changes to commit (already up to date).")
        else:
            ok, err = run_git(config, "commit", "-m", f"param-parity: deploy {commit_path}")
            if not ok:
                error("Failed to commit connector changes")
                sys.exit(1)
            success(f"Committed {commit_path}")

    # Plain, fast-forward-only push. NEVER --force / --force-with-lease: we never
    # rewrite history on push. If the remote rejects this as non-fast-forward,
    # the engineer's branch is behind its own remote and they must rebase first.
    info(f"Pushing '{branch}' to origin (fast-forward only)...")
    ok, err = run_git(config, "push", "origin", branch)
    if not ok:
        error(f"Failed to push branch '{branch}'")
        print("  This push is fast-forward-only (never forced). If it was rejected")
        print("  as non-fast-forward, your local branch is behind origin/" + branch)
        print("  — run `git pull --rebase origin " + branch + "` then re-deploy.")
        print("  Otherwise check your SSH key / git credentials.")
        sys.exit(1)
    success(f"Pushed '{branch}' to origin")


# ── Content Pack Upload ─────────────────────────────────────────────────────

# Content-repo root = the directory holding the canonical root .env (loaded by
# load_env above). Pack paths (Packs/Base, Packs/<pack>) are resolved against it.
_CONTENT_REPO_ROOT = Path(_ENV_PATH).resolve().parent


def upload_packs(config):
    """Upload the required content packs to the tenant BEFORE the connector deploy.

    Replaces the old manual prerequisite ("upload the patched Base pack + the
    integration's own pack with demisto-sdk"). Each pack dir in
    ``config['upload_packs']`` is uploaded with::

        demisto-sdk upload -i <pack> -z -mp platform [--insecure]

    The tenant/auth come from the env (DEMISTO_BASE_URL / DEMISTO_API_KEY /
    XSIAM_AUTH_ID), already loaded from the root .env and inherited by the
    subprocess. ``--insecure`` (config['upload_insecure']) skips TLS validation
    for tenants whose chain has a self-signed cert.

    Exits non-zero on the first failed upload — a missing Base probe or integration
    pack makes the downstream param-parity capture meaningless.
    """
    header("Step 0: Upload Content Packs To Tenant")

    if config.get("skip_pack_upload"):
        warn("--skip-pack-upload set: not uploading content packs (assuming they "
             "are already current on the tenant).")
        return

    packs = config.get("upload_packs") or []
    if not packs:
        info("No content packs to upload (none supplied) — skipping.")
        return

    for pack in packs:
        pack_path = Path(pack)
        if not pack_path.is_absolute():
            pack_path = (_CONTENT_REPO_ROOT / pack).resolve()
        if not pack_path.is_dir():
            error(f"Pack directory not found: {pack_path}")
            print(f"  Resolved from --upload-pack {pack!r} against {_CONTENT_REPO_ROOT}")
            sys.exit(1)

        cmd = ["demisto-sdk", "upload", "-i", str(pack_path), "-z", "-mp", "platform"]
        if config.get("upload_insecure"):
            cmd.append("--insecure")

        info(f"Uploading pack '{pack}' → tenant {config['tenant_ids']} ...")
        info(f"  {' '.join(cmd)}")
        # Inherit the current environment (carries the .env-loaded DEMISTO_*
        # auth vars that demisto-sdk reads). Stream output so the engineer sees
        # demisto-sdk progress live.
        result = subprocess.run(cmd, cwd=str(_CONTENT_REPO_ROOT), env=os.environ.copy())
        if result.returncode != 0:
            error(f"Failed to upload pack '{pack}' (demisto-sdk exit {result.returncode})")
            print("  Check DEMISTO_BASE_URL / DEMISTO_API_KEY / XSIAM_AUTH_ID in your .env,")
            print("  network/VPN access to the tenant, and (for a self-signed cert) that")
            print("  --upload-insecure is set.")
            sys.exit(1)
        success(f"Uploaded pack '{pack}'")


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
    print(f"{Colors.DIM}Config: {_ENV_PATH}{Colors.RESET}\n")

    # Step 0: Upload required content packs (patched Base pack + the integration's
    # own pack) to the tenant. This used to be a manual prerequisite; it is now
    # part of the deploy so the param-parity capture has the probe + integration
    # present. No-op when no packs are supplied or --skip-pack-upload is set.
    upload_packs(config)

    # Step 1: Git operations — commit the connector dir to the engineer's personal
    # branch (xsoar-migration-<name>) and fast-forward push it so the pipeline
    # deploys FROM that branch. No base reset, no force-push (see git_operations).
    # Honored unless --skip-git is passed (re-trigger only).
    if not config["skip_git"]:
        git_operations(config)

    # Pipeline can be skipped for an upload-only run (--skip-pipeline). The pack
    # upload above (Step 0) still ran; we just do NOT trigger/poll the GitLab
    # skinny pipeline. Return success so an upload-only run exits 0.
    if config["skip_pipeline"]:
        warn("--skip-pipeline set: skipping GitLab pipeline trigger/poll "
             "(packs uploaded only).")
        success("Upload-only run complete (no pipeline triggered).")
        sys.exit(0)

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
