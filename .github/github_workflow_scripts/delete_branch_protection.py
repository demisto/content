#!/usr/bin/env python3
"""
A CLI to manage stale branch protection rules.

It uses GitHub GraphQL API to query and remove
branch protection rules.
"""

__author__ = "Kobbi"
__version__ = "0.1.0"
__license__ = "MIT"

import argparse
import logging
import os
import sys

from github import Github
import github
import github.Requester


DEFAULT_ORG = "demisto"
DEFAULT_REPO = "content"

GH_TOKEN_ENV_VAR = "GITHUB_TOKEN"

# https://docs.github.com/en/actions/learn-github-actions/variables#default-environment-variables
GH_OWNER_ENV_VAR = "GITHUB_REPOSITORY_OWNER"
GH_REPO_ENV_VAR = "GITHUB_REPOSITORY"


GET_BRANCH_PROTECTION_GRAPHQL_QUERY = '''query($owner: String!, $name: String!) {
  repository(owner: $owner, name: $name) {
    branchProtectionRules(first: 100) {
      nodes {
        id
        pattern
        matchingRefs(first: 10) {
          totalCount
        }
      }
    }
  }
}'''

def setup_logging():
    """
    Set up a logger for file and stdout streams.
    """

    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    f_handler = logging.FileHandler("remove_branch_protection_rules.log")
    f_handler.setLevel(logging.DEBUG)

    c_handler = logging.StreamHandler(sys.stdout)
    c_handler.setLevel(logging.DEBUG)

    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    f_handler.setFormatter(formatter)
    c_handler.setFormatter(formatter)

    logger.addHandler(f_handler)
    logger.addHandler(c_handler)

    return logger


def main(args: argparse.Namespace) -> int:

    exit_code = 0

    try:
        logger = setup_logging()
        token = validate_gh_token()

        logger.info("Authenticating with GitHub...")
        auth = github.Auth.Token(token)

        # TODO rm verify after testing (throwing self-signed cert errors)
        gh = Github(auth=auth, verify=False)
        logger.info("Finished authenticating with GitHub")

        org = args.org
        repo = args.repo
        branch = args.branch_name

        logger.info(f"{org=}")
        logger.info(f"{repo=}")

        logger.info(f"Getting protection rules for repo '{org}/{repo}'...")
        res_header, data = gh._Github__requester.graphql_query(query=GET_BRANCH_PROTECTION_GRAPHQL_QUERY, variables={"owner": org, "name": repo})

        logger.debug(f"{res_header=}")
        logger.debug(f"{data=}")

    except EnvironmentError as env_err:
        logger.error(env_err)
        exit_code = 1
    except Exception as err:
        logger.error(f"Error returned from GitHub: {err}")
        exit_code = 1
    finally:
        sys.exit(exit_code)


def validate_gh_token() -> str:
    """
    Check if GITHUB_TOKEN env var is set.

    Returns:
    - The token as an `str`.

    Raises:
    - `EnvironmentError` if it's not set.
    """

    token = os.getenv(GH_TOKEN_ENV_VAR)
    if not token:
        raise EnvironmentError(f"Error: The '{GH_TOKEN_ENV_VAR}' environment variable is not set.")
    else:
        return token


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="A CLI to manage branch protection rules."
    )

    parser.add_argument(
        "branch_name",
        help="The branch to remove the branch protection rules from"
    )

    parser.add_argument(
        "-o",
        "--org",
        help=f"The GitHub organization. Default is env var {GH_OWNER_ENV_VAR} or '{DEFAULT_ORG}' if GH_ORG is not set.",
        default=os.environ.get(GH_OWNER_ENV_VAR, DEFAULT_ORG)
    )

    parser.add_argument(
        "-r",
        "--repo",
        help=f"The GitHub repo. Default is env var {GH_REPO_ENV_VAR} or '{DEFAULT_REPO}' if GH_ORG is not set.",
        default=os.environ.get(GH_REPO_ENV_VAR, DEFAULT_REPO)
    )

    # Optional argument flag which defaults to False
    parser.add_argument(
        "-d",
        "--dry-run",
        action="store_true",
        default=False,
        help="Whether to run in 'dry-run' mode. No changes will be made in GitHub. Useful for testing."
    )

    args = parser.parse_args()
    main(args)