#!/usr/bin/env python3

import json
from pathlib import Path
import subprocess
import re

import urllib3
from blessings import Terminal
from github import Github
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
    "Dashboards",
    "XSIAMDashboards",
]


# -----------------------------
# Git utilities
# -----------------------------
def run_git_command(cmd, raise_on_error=True):
    log_cmd = [c.replace(get_env_var("CONTENTBOT_GH_ADMIN_TOKEN"), "***") for c in cmd]
    print(f"Running: {' '.join(log_cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0 and raise_on_error:
        print(f"Error: {result.stderr}")
        raise Exception(f"Git command failed: {result.stderr}")

    return result


def prepare_git(head_branch: str):
    token = get_env_var("CONTENTBOT_GH_ADMIN_TOKEN")

    run_git_command(["git", "config", "--global", "user.name", "content-bot"], raise_on_error=False)
    run_git_command(["git", "config", "--global", "user.email", "content-bot@users.noreply.github.com"], raise_on_error=False)

    remote_url = f"https://x-access-token:{token}@github.com/demisto/content.git"  # disable-secrets-detection
    run_git_command(["git", "remote", "set-url", "origin", remote_url])

    run_git_command(["git", "fetch", "origin", "master"])
    run_git_command(["git", "fetch", "origin", head_branch])


# -----------------------------
# File separation
# -----------------------------
def seperate_pr_files(pr_files: dict):
    xsoar_files = []
    xsiam_files = []

    for file_path, file in pr_files.items():
        is_xsiam = any(item in Path(file_path).parts for item in XSIAM_CONTENT)

        if is_xsiam:
            xsiam_files.append(file)
        else:
            xsoar_files.append(file)

    return xsoar_files, xsiam_files


# -----------------------------
# Branch splitting
# -----------------------------
def split_branch_with_git(head_branch, xsoar_files, xsiam_files):
    prepare_git(head_branch)

    main_branch = f"{head_branch}-main"
    mapping_branch = f"{head_branch}-mapping"

    # ---------------- mapping branch ----------------
    run_git_command(["git", "checkout", "-b", mapping_branch, f"origin/{head_branch}"])

    for file in xsoar_files:
        filename = file.filename
        if file.status == "added":
            run_git_command(["git", "rm", "--ignore-unmatch", filename], raise_on_error=False)
        elif file.status == "renamed":
            run_git_command(["git", "rm", "--ignore-unmatch", filename], raise_on_error=False)
            if hasattr(file, "previous_filename") and file.previous_filename:
                res = run_git_command(["git", "checkout", "origin/master", "--", file.previous_filename], raise_on_error=False)
                if res.returncode != 0:
                    run_git_command(["git", "rm", "--ignore-unmatch", file.previous_filename], raise_on_error=False)
        else:
            res = run_git_command(
                ["git", "checkout", "origin/master", "--", filename],
                raise_on_error=False,
            )
            if res.returncode != 0:
                run_git_command(["git", "rm", "--ignore-unmatch", filename], raise_on_error=False)

    if run_git_command(["git", "status", "--porcelain"]).stdout.strip():
        run_git_command(["git", "commit", "-m", "Remove XSOAR files from mapping PR"])
        run_git_command(["git", "push", "origin", mapping_branch])

    # ---------------- main branch ----------------
    run_git_command(["git", "checkout", "-b", main_branch, f"origin/{head_branch}"])

    for file in xsiam_files:
        filename = file.filename
        if file.status == "added":
            run_git_command(["git", "rm", "--ignore-unmatch", filename], raise_on_error=False)
        elif file.status == "renamed":
            run_git_command(["git", "rm", "--ignore-unmatch", filename], raise_on_error=False)
            if hasattr(file, "previous_filename") and file.previous_filename:
                res = run_git_command(["git", "checkout", "origin/master", "--", file.previous_filename], raise_on_error=False)
                if res.returncode != 0:
                    run_git_command(["git", "rm", "--ignore-unmatch", file.previous_filename], raise_on_error=False)
        else:
            res = run_git_command(
                ["git", "checkout", "origin/master", "--", filename],
                raise_on_error=False,
            )
            if res.returncode != 0:
                run_git_command(["git", "rm", "--ignore-unmatch", filename], raise_on_error=False)

    if run_git_command(["git", "status", "--porcelain"]).stdout.strip():
        run_git_command(["git", "commit", "-m", "Remove XSIAM files from main PR"])
        run_git_command(["git", "push", "origin", main_branch])

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


def get_mapping_pr_body(merged_pr_url: str, merged_pr_author: str, original_body: str) -> str:
    body = f"## Original External PR\r\n[external pull request]({merged_pr_url})\r\n\r\n"

    if "## Contributor" not in original_body:
        body += f"## Contributor\r\n@{merged_pr_author}\r\n\r\n"

    body_without_rn = re.sub(
        r"(?i)##\s*Release Notes.*?(?=##\s|$)",
        "",
        original_body,
        flags=re.DOTALL,
    )

    body += body_without_rn
    return replace_fixes_with_relates_in_pr_body(body)


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
        branch = repo.get_branch(branch_name)
        branch.remove_protection()
        branch.remove_required_status_checks()
        branch.remove_required_pull_request_reviews()
    except Exception as e:
        print(f"{t.red}Failed to remove protection from {branch_name}: {e}{t.normal}")


# -----------------------------
# main
# -----------------------------
def main():
    t = Terminal()

    payload = json.loads(get_env_var("EVENT_PAYLOAD"))
    gh = Github(get_env_var("CONTENTBOT_GH_ADMIN_TOKEN"), verify=False)

    repo = gh.get_repo("demisto/content")
    pr_number = payload["pull_request"]["number"]
    merged_pr = repo.get_pull(pr_number)

    pr_files = {f.filename: f for f in merged_pr.get_files()}
    xsoar_files, xsiam_files = seperate_pr_files(pr_files)

    merged_pr_url = merged_pr.html_url
    title = merged_pr.title

    body = f"## Original External PR\r\n[external pull request]({merged_pr_url})\r\n\r\n"

    if "## Contributor" not in merged_pr.body:
        author = merged_pr.user.login
        body += f"## Contributor\r\n@{author}\r\n\r\n"

    body += merged_pr.body
    body = replace_related_with_fixes_in_pr_body(body)

    base_branch = "master"
    head_branch = merged_pr.base.ref

    labels = [label.name.replace(EXTERNAL_LABEL, INTERNAL_LABEL) for label in merged_pr.labels]
    labels.append("ready-for-pipeline-running")
    labels.remove(MAPPING_LABEL)

    merged_by = getattr(merged_pr.merged_by, "login", None)
    reviewers, _ = merged_pr.get_review_requests()
    reviewer_logins = [r.login for r in reviewers]

    new_reviewers = reviewer_logins or ([merged_by] if merged_by else [])

    assignees = [a.login for a in merged_pr.assignees]

    # tech writer removal
    content_roles = get_content_roles()
    if content_roles:
        try:
            doc_reviewer = get_doc_reviewer(content_roles)
            if doc_reviewer in assignees:
                assignees.remove(doc_reviewer)
        except Exception:
            pass

    main_branch = None
    mapping_branch = None

    if xsiam_files and xsoar_files:
        main_branch, mapping_branch = split_branch_with_git(head_branch, xsoar_files, xsiam_files)

    elif xsiam_files and not xsoar_files:
        print(f"{t.cyan}Only XSIAM files → mapping only{t.normal}")

        mapping_branch = f"{head_branch}-mapping"

        main_branch = None

        prepare_git(head_branch)

        run_git_command(["git", "checkout", "-b", mapping_branch, f"origin/{head_branch}"])

        run_git_command(["git", "push", "origin", mapping_branch])

    elif xsoar_files and not xsiam_files:
        print(f"{t.cyan}Only XSOAR files → main only{t.normal}")
        main_branch = f"{head_branch}-main"
        mapping_branch = None
        prepare_git(head_branch)
        run_git_command(["git", "checkout", "-b", main_branch, f"origin/{head_branch}"])
        run_git_command(["git", "push", "origin", main_branch])

    created = []

    if xsoar_files and main_branch:
        try:
            pr = create_pr(repo, title, body, base_branch, main_branch, labels, assignees, new_reviewers, t)

            org_reviewers = [r for r in new_reviewers if is_organization_member(gh, r)]
            if org_reviewers:
                post_ai_review_introduction(pr, org_reviewers, t)

            created.append(pr)

        except Exception as e:
            print(f"{t.red}Main PR failed: {e}{t.normal}")

    if xsiam_files and mapping_branch:
        mapping_title = f"[Mapping] {title}"
        mapping_body = get_mapping_pr_body(merged_pr_url, merged_pr.user.login, merged_pr.body)

        mapping_labels = [label for label in labels if label != "ready-for-pipeline-running"]
        mapping_labels.append(MAPPING_LABEL)

        mapping_reviewers = get_mapping_reviewer(content_roles) if content_roles else []
        mapping_assignees = list(mapping_reviewers)
        try:
            pr = create_pr(
                repo,
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
        remove_branch_protection(repo, pr.head.ref, t)


if __name__ == "__main__":
    main()
