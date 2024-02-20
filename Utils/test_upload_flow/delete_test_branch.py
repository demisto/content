import argparse

from git import GitCommandError, Repo

from Tests.scripts.utils import logging_wrapper as logging
from Tests.scripts.utils.log_util import install_logging
from Utils.github_workflow_scripts.utils import get_env_var

GITLAB_SERVER_HOST = get_env_var('CI_SERVER_HOST', 'gitlab.xdr.pan.local')  # disable-secrets-detection
GITLAB_PROJECT_NAMESPACE = get_env_var('CI_PROJECT_NAMESPACE', 'xdr/cortex-content')  # disable-secrets-detection


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--path", nargs="?", default='.',
                        help="Content directory path, default is current directory.")
    parser.add_argument("-tb", "--test-branch", nargs="?",
                        help="The content test branch name to delete.")
    parser.add_argument("-g", "--gitlab-token",
                        help="Gitlab token for deleting the test branch.")
    return parser.parse_args()


def main():
    install_logging('delete_test_branch.log', logger=logging)

    args = parse_arguments()
    repo = Repo(args.path)
    branch = args.test_branch

    try:

        logging.info(f"Start deleting branch: '{branch}'")
        repo.git.push('--set-upstream',
                      f'https://GITLAB_PUSH_TOKEN:{args.gitlab_token}@'  # disable-secrets-detection
                      f'{GITLAB_SERVER_HOST}/{GITLAB_PROJECT_NAMESPACE}/content.git',  # disable-secrets-detection
                      f":{branch}")

        logging.info("Successfully deleted branch.")

    except GitCommandError as e:
        logging.error(e)


if __name__ == "__main__":
    main()
