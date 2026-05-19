"""
Verifies that PRs which modify CommonServerPython.py (or its JS/PS counterparts that are
considered runtime-injected helpers) have been validated against the content nightly
pipeline. The check:

  1. Detects whether the PR touches any of the protected CommonServer* files.
  2. If yes, ensures the `nightly-run-passed` label is set on the PR (added manually
     by the developer / reviewer once the content nightly pipeline has run green).
  3. Posts (or updates) a sticky reminder comment on the PR explaining the
     requirement to anyone who opens / updates the PR.

Exit codes:
    0 - No CommonServerPython change OR change exists AND label `nightly-run-passed` is set.
    1 - CommonServerPython change exists but label `nightly-run-passed` is missing.
"""

import argparse
import sys

import urllib3
from blessings import Terminal  # noqa: F401  (kept for parity with other scripts)
from github import Github
from github.PullRequest import PullRequest
from github.Repository import Repository

from utils import timestamped_print

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
print = timestamped_print  # noqa: A001 - intentional, matches existing scripts

NIGHTLY_RUN_PASSED_LABEL = "nightly-run-passed"

# Paths whose changes MUST be validated against the content nightly pipeline.
# CommonServerPython is the primary trigger; the other helpers are included
# because they are runtime-injected the same way and a change to any of them
# can impact most/all content.
PROTECTED_PATHS = (
    "Packs/Base/Scripts/CommonServerPython/CommonServerPython.py",
    "Packs/Base/Scripts/CommonServerPowerShell/CommonServerPowerShell.ps1",
    "Packs/Base/Scripts/CommonServer/CommonServer.js",
)

# Marker used to find / update the sticky reminder comment so we don't spam the PR
# with a new comment on every workflow run.
COMMENT_MARKER = "<!-- commonserverpython-nightly-reminder -->"

REMINDER_COMMENT_BODY = (
    f"{COMMENT_MARKER}\n"
    "### ⚠️ `CommonServerPython` change detected\n\n"
    "This PR modifies one of the runtime-injected helper scripts "
    "(`CommonServerPython.py` / `CommonServerPowerShell.ps1` / `CommonServer.js`).\n"
    "A change here can impact **every integration and script** in the repository, "
    "so the standard PR pipeline is **not** enough.\n\n"
    "**Required before merge:**\n"
    "1. Trigger the **content nightly** pipeline against this branch.\n"
    "2. Make sure the nightly run is **green** (all jobs passed).\n"
    f"3. Add the **`{NIGHTLY_RUN_PASSED_LABEL}`** label to this PR so this check turns green.\n\n"
    "If you believe nightly is not required for this change, please justify it in a PR "
    "comment and add the label to unblock the check."
)


def arguments_handler() -> argparse.Namespace:
    """Validates and parses script arguments."""
    parser = argparse.ArgumentParser(
        description="Check that PRs touching CommonServerPython have been validated " "by the content nightly pipeline."
    )
    parser.add_argument("-p", "--pr_number", required=True, help="The PR number to check.")
    parser.add_argument(
        "-g",
        "--github_token",
        required=True,
        help="The GitHub token to authenticate the GitHub client.",
    )
    return parser.parse_args()


def pr_changes_protected_files(pr: PullRequest) -> list[str]:
    """Return the list of protected files modified by the PR (empty if none)."""
    changed = [f.filename for f in pr.get_files()]
    return [path for path in PROTECTED_PATHS if path in changed]


def reminder_comment_already_posted(pr: PullRequest) -> bool:
    """Return True if a reminder comment (identified by COMMENT_MARKER) already exists on the PR."""
    return any(COMMENT_MARKER in (comment.body or "") for comment in pr.get_issue_comments())


def post_reminder_comment_once(pr: PullRequest) -> None:
    """
    Create the sticky reminder comment **only if** none has been posted yet on this PR.

    Idempotency is enforced by looking for the hidden HTML marker
    `COMMENT_MARKER` inside existing comment bodies. This guarantees the
    reminder appears exactly once per PR, regardless of how many times the
    workflow re-runs (synchronize / labeled / unlabeled / reopened events).
    """
    if reminder_comment_already_posted(pr):
        print(
            f"Reminder comment already present on PR #{pr.number} " f"(marker '{COMMENT_MARKER}' found); not posting a duplicate."
        )
        return
    pr.create_issue_comment(REMINDER_COMMENT_BODY)
    print(f"Posted CommonServerPython nightly reminder comment on PR #{pr.number} (first time).")


def main() -> None:
    options = arguments_handler()
    pr_number = int(options.pr_number)

    github_client: Github = Github(options.github_token, verify=False)
    content_repo: Repository = github_client.get_repo("demisto/content")
    pr: PullRequest = content_repo.get_pull(pr_number)

    changed_protected = pr_changes_protected_files(pr)
    if not changed_protected:
        print(f"PR #{pr_number} does not modify CommonServerPython or related helpers. Nothing to enforce.")
        sys.exit(0)

    print(
        f"PR #{pr_number} modifies protected files: {', '.join(changed_protected)}. "
        "Verifying that the content nightly pipeline has been run and labeled."
    )

    # Post the reminder comment at most once per PR (idempotent — guarded by COMMENT_MARKER).
    post_reminder_comment_once(pr)

    pr_label_names = {label.name for label in pr.labels}
    if NIGHTLY_RUN_PASSED_LABEL in pr_label_names:
        print(f"Label '{NIGHTLY_RUN_PASSED_LABEL}' is set on PR #{pr_number}. Check passes.")
        sys.exit(0)

    print(
        f"ERROR: PR #{pr_number} modifies CommonServerPython (or a runtime helper) but "
        f"the '{NIGHTLY_RUN_PASSED_LABEL}' label is missing. "
        "Please run the content nightly pipeline against this branch and, once it "
        "passes, add the label to unblock this check."
    )
    sys.exit(1)


if __name__ == "__main__":
    main()
