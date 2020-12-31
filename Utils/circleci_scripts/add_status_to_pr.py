#!/usr/bin/env python3
import urllib3
from github import Github

from utils import get_env_var, timestamped_print

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
print = timestamped_print


def main():
    # pr_number = get_env_var("PULL_REQUEST_NUMBER")
    pr_number = '10535'
    # repo_name = get_env_var("REPO")
    repo_name = 'DeanArbel/content'
    # branch_name = get_env_var("BRANCH")
    branch_name = 'master'
    token = get_env_var("GITHUB_TOKEN")
    print(f"{pr_number = }\n{repo_name = }\n{branch_name = }")
    try:
        gh = Github(token, verify=False)
        repo = gh.get_repo(repo_name)
        branch = repo.get_branch(branch=branch_name)
        status = repo.get_commit(sha=branch.commit.sha).create_status(
            state="pending",
            description="ready-for-dev-instance was not added",
            context="Ready For Dev Instance Created"
        )
        print(status)

    except Exception as e:
        print(e)


if __name__ == '__main__':
    main()
