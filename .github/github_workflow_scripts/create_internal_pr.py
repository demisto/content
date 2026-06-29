#!/usr/bin/env python3

import json
from pathlib import Path
import subprocess
import re

import urllib3
from blessings import Terminal
from github import Github
from github.PullRequest import PullRequest

from handle_external_pr import EXTERNAL_LABEL

from utils import (
    get_env_var,
    timestamped_print,
    get_doc_reviewer,
    get_mapping_reviewer,
    get_content_roles,
    post_ai_review_introduction,
    is_organization_member,
)

from urllib3.exceptions import InsecureRequestWarning

urllib3.disable_warnings(InsecureRequestWarning)

print = timestamped_print
INTERNAL_LABEL = "Internal PR"
MAPPING_LABEL = "Mapping Contribution"
XSIAM_CONTENT = [
    "ModelingRules",
    "ParsingRules",
    "CorrelationRules",
    "XSIAMDashboards",
]
RELEASE_NOTES_ITEMS = ["ReleaseNotes", "pack_metadata.json"]


# -----------------------------
# Git utilities
# -----------------------------
def run_git_command(cmd, github_token, raise_on_error=True):
    log_cmd = [c.replace(github_token, "***") for c in cmd]
    print(f"Running: {' '.join(log_cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0 and raise_on_error:
        print(f"Error: {result.stderr}")
        raise Exception(f"Git command failed: {result.stderr}")
    if result.stdout:
        print(result.stdout)

    return result


def prepare_git(head_branch: str):
    token = get_env_var("CONTENTBOT_GH_ADMIN_TOKEN")

    run_git_command(["git", "config", "--global", "user.name", "content-bot"], token, raise_on_error=False)
    run_git_command(
        ["git", "config", "--global", "user.email", "content-bot@users.noreply.github.com"], token, raise_on_error=False
    )

    remote_url = f"https://x-access-token:{token}@github.com/demisto/content.git"  # disable-secrets-detection
    run_git_command(
        ["git", "remote", "set-url", "origin", remote_url],
        token,
    )
    run_git_command(["git", "remote", "-v"], token)
    print(f"Token exists: {bool(token)}")
    run_git_command(["git", "fetch", "origin", "master"], token)
    run_git_command(["git", "fetch", "origin", head_branch], token)


# -----------------------------
# File separation
# -----------------------------
def separate_pr_files(pr_files: dict):
    xsoar_files = []
    xsiam_files = []
    release_notes_files = []
    for file_path, file in pr_files.items():
        is_xsiam = any(item in Path(file_path).parts for item in XSIAM_CONTENT)
        parts = Path(file_path).parts
        if any(x in parts for x in RELEASE_NOTES_ITEMS):
            release_notes_files.append(file)

        if is_xsiam:
            xsiam_files.append(file)
        else:
            xsoar_files.append(file)
    if all(file in release_notes_files for file in xsoar_files):  # we only have xsiam files, and the only xsoar files are RN
        xsiam_files.extend(xsoar_files)
        xsoar_files = []

    return xsoar_files, xsiam_files


# -----------------------------
# Branch splitting
# -----------------------------
def split_branch_with_git(head_branch: str, xsoar_files: list, xsiam_files: list, token: str):
    prepare_git(head_branch)

    main_branch = f"{head_branch}-main"
    mapping_branch = f"{head_branch}-mapping"

    # ---------------- mapping branch ----------------
    run_git_command(["git", "checkout", "-b", mapping_branch, f"origin/{head_branch}"], token)

    for file in xsoar_files:
        filename = file.filename
        if file.status == "added":
            run_git_command(["git", "rm", "--ignore-unmatch", filename], token, raise_on_error=False)
        elif file.status == "renamed":
            run_git_command(["git", "rm", "--ignore-unmatch", filename], token, raise_on_error=False)
            if hasattr(file, "previous_filename") and file.previous_filename:
                res = run_git_command(
                    ["git", "checkout", "origin/master", "--", file.previous_filename], token, raise_on_error=False
                )
                if res.returncode != 0:
                    run_git_command(["git", "rm", "--ignore-unmatch", file.previous_filename], token, raise_on_error=False)
        else:
            res = run_git_command(
                ["git", "checkout", "origin/master", "--", filename],
                token,
                raise_on_error=False,
            )
            if res.returncode != 0:
                run_git_command(["git", "rm", "--ignore-unmatch", filename], token, raise_on_error=False)

    if run_git_command(["git", "status", "--porcelain"], token).stdout.strip():
        run_git_command(["git", "commit", "-m", "Remove XSOAR files from mapping PR"], token)
    run_git_command(["git", "push", "origin", mapping_branch], token)

    # ---------------- main branch ----------------
    run_git_command(["git", "checkout", "-b", main_branch, f"origin/{head_branch}"], token)

    for file in xsiam_files:
        filename = file.filename
        if file.status == "added":
            run_git_command(["git", "rm", "--ignore-unmatch", filename], token, raise_on_error=False)
        elif file.status == "renamed":
            run_git_command(["git", "rm", "--ignore-unmatch", filename], token, raise_on_error=False)
            if hasattr(file, "previous_filename") and file.previous_filename:
                res = run_git_command(
                    ["git", "checkout", "origin/master", "--", file.previous_filename], token, raise_on_error=False
                )
                if res.returncode != 0:
                    run_git_command(["git", "rm", "--ignore-unmatch", file.previous_filename], token, raise_on_error=False)
        else:
            res = run_git_command(
                ["git", "checkout", "origin/master", "--", filename],
                token,
                raise_on_error=False,
            )
            if res.returncode != 0:
                run_git_command(["git", "rm", "--ignore-unmatch", filename], token, raise_on_error=False)

    if run_git_command(["git", "status", "--porcelain"], token).stdout.strip():
        run_git_command(["git", "commit", "-m", "Remove XSIAM files from main PR"], token)
    run_git_command(["git", "push", "origin", main_branch], token)

    return main_branch, mapping_branch


# -----------------------------
# PR body utils
# -----------------------------
def replace_related_with_fixes_in_pr_body(body: str) -> str:
    pattern = r"(relates?:\s?)(.*)"

    if re.search(pattern, body, re.IGNORECASE):
        return re.sub(pattern, r"fixes: \2", body, flags=re.IGNORECASE)

    return body + "\n\nfixes: link to the issue"


def replace_fixes_with_relates_in_pr_body(body: str) -> str:
    pattern = r"(fixes?:\s?)(.*)"

    if re.search(pattern, body, re.IGNORECASE):
        return re.sub(pattern, r"relates: \2", body, flags=re.IGNORECASE)

    return body + "\n\nrelates: link to the issue"


# -----------------------------
# PR creation
# -----------------------------
def create_pr(repo, title, body, base, head, labels, assignees, reviewers, t):
    pr = repo.create_pull(title=title, body=body, base=base, head=head, draft=False)

    print(f"{t.cyan}Internal PR Created - {pr.html_url}{t.normal}")

    for label in labels:
        pr.add_to_labels(label)
        print(f"{t.cyan}{label} label added{t.normal}")

    if reviewers:
        pr.create_review_request(reviewers=reviewers)

    if assignees:
        pr.add_to_assignees(*assignees)

    return pr


# -----------------------------
# branch protection cleanup
# -----------------------------
def remove_branch_protection(repo, branch_name, t):
    try:
        print(f'{t.cyan}Removing protection from branch "{branch_name}"{t.normal}')
        branch = repo.get_branch(branch_name)
        branch.remove_protection()
        branch.remove_required_status_checks()
        branch.remove_required_pull_request_reviews()
    except Exception as e:
        print(f"{t.red}Failed to remove protection from {branch_name}: {e}{t.normal}")


def prepare_body(pr: PullRequest):
    body = f"## Original External PR\r\n[external pull request]({pr.html_url})\r\n\r\n"
    if "## Contributor" not in pr.body:
        merged_pr_author = pr.user.login
        body += f"## Contributor\r\n@{merged_pr_author}\r\n\r\n"
    body += pr.body
    return replace_related_with_fixes_in_pr_body(body)


def prepare_labels(pr: PullRequest):
    labels = [label.name.replace(EXTERNAL_LABEL, INTERNAL_LABEL) for label in pr.labels]
    labels.append("ready-for-pipeline-running")
    if MAPPING_LABEL in labels:
        labels.remove(MAPPING_LABEL)
    return labels


def prepare_reviewers(pr: PullRequest):
    merged_by = getattr(pr.merged_by, "login", None)
    reviewers, _ = pr.get_review_requests()
    reviewer_logins = [r.login for r in reviewers]

    return [merged_by] if merged_by else reviewer_logins


def remove_doc_reviewers(assignees: list, content_roles):
    try:
        doc_reviewer = get_doc_reviewer(content_roles)
        if doc_reviewer in assignees:
            assignees.remove(doc_reviewer)
    except Exception as e:
        print(f"Failed removing doc reviewers. Error: {e}")


# -----------------------------
# main
# -----------------------------
def main():
    """Creates Internal PRs from Merged External PRs

    Performs the following operations:
    1. Creates new PR.
        A) Uses body of merged external PR as the body of the new PR.
        B) Uses base branch of merged external PR as head branch of the new PR to master.
        C) Adds 'docs-approved' label if it was on the merged external PR.
        D) Requests review from the same users as on the merged external PR.
        E) Add the same labels that the external PR had to the internal PR (including contribution label).
        F) Assigns the same users as on the merged external PR.

    Will use the following env vars:
    - CONTENTBOT_GH_ADMIN_TOKEN: token to use to update the PR
    - EVENT_PAYLOAD: json data from the pull_request event
    """
    t = Terminal()
    payload_str = get_env_var("EVENT_PAYLOAD")
    if not payload_str:
        raise ValueError("EVENT_PAYLOAD env variable not set or empty")
    payload = json.loads(payload_str)

    org_name = "demisto"
    repo_name = "content"
    github_token = get_env_var("CONTENTBOT_GH_ADMIN_TOKEN")
    gh = Github(github_token, verify=False)
    content_repo = gh.get_repo(f"{org_name}/{repo_name}")
    pr_number = payload.get("pull_request", {}).get("number")
    merged_pr = content_repo.get_pull(pr_number)

    pr_files = {f.filename: f for f in merged_pr.get_files()}
    xsoar_files, xsiam_files = separate_pr_files(pr_files)

    body = prepare_body(merged_pr)
    labels = prepare_labels(merged_pr)
    title = merged_pr.title

    base_branch = "master"
    head_branch = merged_pr.base.ref

    new_reviewers = prepare_reviewers(merged_pr)
    assignees = [a.login for a in merged_pr.assignees]

    content_roles = get_content_roles()
    if content_roles:
        remove_doc_reviewers(assignees, content_roles)

    main_branch = None
    mapping_branch = None

    if xsiam_files and xsoar_files:
        main_branch, mapping_branch = split_branch_with_git(head_branch, xsoar_files, xsiam_files, github_token)

    elif xsiam_files and not xsoar_files:
        print(f"{t.cyan}Only XSIAM items files → one pr only{t.normal}")
        mapping_branch = head_branch

    elif xsoar_files and not xsiam_files:
        print(f"{t.cyan}No XSIAM items files →  one pr only{t.normal}")
        main_branch = head_branch

    created = []

    if xsoar_files and main_branch:
        try:
            pr = create_pr(content_repo, title, body, base_branch, main_branch, labels, assignees, new_reviewers, t)

            org_reviewers = [r for r in new_reviewers if is_organization_member(gh, r)]
            if org_reviewers:
                post_ai_review_introduction(pr, org_reviewers, t)

            created.append(pr)

        except Exception as e:
            print(f"{t.red}Main PR failed: {e}{t.normal}")

    if xsiam_files and mapping_branch:
        mapping_title = f"[Mapping] {title}"
        mapping_body = replace_fixes_with_relates_in_pr_body(body)

        mapping_labels = [label for label in labels if label != "ready-for-pipeline-running"]
        mapping_labels.append(MAPPING_LABEL)

        mapping_reviewers = get_mapping_reviewer(content_roles) if content_roles else []
        mapping_assignees = list(mapping_reviewers)
        try:
            pr = create_pr(
                content_repo,
                mapping_title,
                mapping_body,
                base_branch,
                mapping_branch,
                mapping_labels,
                mapping_assignees,
                mapping_reviewers,
                t,
            )

            created.append(pr)

        except Exception as e:
            print(f"{t.red}Mapping PR failed: {e}{t.normal}")

    for pr in created:
        remove_branch_protection(content_repo, pr.head.ref, t)


if __name__ == "__main__":
    main()
