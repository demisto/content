#!/usr/bin/env python3

import gitlab
from github import Github
from Utils.github_workflow_scripts.utils import timestamped_print, get_env_var


# ANSI Colors
RED = '\033[0;31m'
GREEN = '\033[0;32m'
RESET = '\033[0m'


GITLAB_PROJECT_ID = get_env_var('CI_PROJECT_ID', '2596')  # the default is the id of the content project in code.pan.run
GITLAB_SERVER_URL = get_env_var('CI_SERVER_URL', 'https://code.pan.run')  # disable-secrets-detection
GITLAB_WRITE_TOKEN = get_env_var('GITLAB_WRITE_TOKEN')

print = timestamped_print


def main():
    """
    Remove branches from GitLab content repository that do not exist in the Github repository it is mirrored from

    Head branches in Github that are deleted upon a PR merge event, persist in GitLab despite having been deleted
    from the Github repository from which we mirror from. This script deletes from GitLab the branches which no
    longer exist in Github.
    """
    # get github content repo's branches
    github = Github(get_env_var('CONTENT_GITHUB_TOKEN'), verify=False)
    organization = 'demisto'
    repo = 'content'
    content_repo = github.get_repo(f'{organization}/{repo}')

    github_branches = content_repo.get_branches()
    print(f'{github_branches.totalCount=}')
    github_branch_names = set()
    for github_branch in github_branches:
        github_branch_names.add(github_branch.name)

    # get gitlab content repo's branches
    gitlab_client = gitlab.Gitlab(GITLAB_SERVER_URL, private_token=GITLAB_WRITE_TOKEN, ssl_verify=False)
    gl_project = gitlab_client.projects.get(int(GITLAB_PROJECT_ID))
    gitlab_branches = gl_project.branches.list(as_list=False)
    print(f'{gitlab_branches.total=}')

    diff_count = gitlab_branches.total - github_branches.totalCount
    print(f'{diff_count} branches require deletion')

    # delete gitlab branches
    for gitlab_branch in gitlab_branches:
        if (gitlab_branch_name := gitlab_branch.name) not in github_branch_names:
            try:
                gitlab_branch.delete()
                print(f'{GREEN}deleted "{gitlab_branch_name}"{RESET}')
            except gitlab.exceptions.GitlabError as e:
                print(f'{RED}Deletion of {gitlab_branch_name} encountered an issue: {str(e)}{RESET}')


if __name__ == "__main__":
    main()
