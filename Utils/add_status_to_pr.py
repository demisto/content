#!/usr/bin/env python3
import argparse
from github import Github


def main():
    parser = argparse.ArgumentParser(description='Add a status to a PR')
    parser.add_argument('-p', '--pr_number', help='PR number')
    parser.add_argument('-b', '--branch', help='The branch')
    parser.add_argument('-r', '--repo', help='The repo')
    parser.add_argument('-t', '--github_token', help='Admin GitHub token')
    args = parser.parse_args()

    pr_number = args.pr_number
    repo_arg = args.repo
    branch_arg = args.branch
    token = args.github_token
    print(f"{pr_number = }\n{repo_arg = }\n{branch_arg = }\n{token = }")
    try:
        gh = Github(token, verify=False)
        repo = gh.get_repo(repo_arg)
        branch = repo.get_branch(branch=branch_arg)
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
