"""
A CLI to manage GitHub branch protection rules.

It uses GitHub GraphQL API to query and remove
branch protection rules.
"""

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import logging
import os
import sys
from pathlib import Path
from typing import Any

from github import Github
import github
import github.Requester


DEFAULT_REPO = "demisto/content"

GH_TOKEN_ENV_VAR = "GITHUB_TOKEN"

# https://docs.github.com/en/actions/learn-github-actions/variables#default-environment-variables
# e.g. 'demisto/content'
GH_REPO_ENV_VAR = "GITHUB_REPOSITORY"

GH_JOB_SUMMARY_ENV_VAR = "GITHUB_STEP_SUMMARY"

# Logging setup
LOG_FORMAT = "%(asctime)s %(levelname)s %(message)s"
logging.basicConfig(level=logging.DEBUG,
                    format=LOG_FORMAT,
                    handlers=[
                        logging.FileHandler(f"{Path(__file__).stem}.log"),
                        logging.StreamHandler()
                    ])

logger = logging.getLogger()


class GitHubGraphQLRateLimit:

    # GitHub GraphQL API rate limit
    HEADER_LIMIT = "x-ratelimit-limit"  # e.g. '5000'
    HEADER_REMAINING = "x-ratelimit-remaining"  # e.g. '4997'
    HEADER_RESET = "x-ratelimit-reset"  # e.g. '1721130684'
    HEADER_USED = "x-ratelimit-used"  # e.g. '3'
    HEADERS = [
        HEADER_LIMIT,
        HEADER_REMAINING,
        HEADER_RESET,
        HEADER_USED
    ]

    def __init__(
        self,
        limit: str,
        remaining: str,
        reset: str,
        used: str
    ) -> None:
        self.limit = int(limit)
        self.remaining = int(remaining)
        self.reset = datetime.fromtimestamp(int(reset), timezone.utc)
        self.used = int(used)

    def exceeded(self) -> bool:
        """
        Whether the rate limit was exceeded.

        Returns:
        - True` if rate limit was exceeded, `False` otherwise.
        """

        return self.remaining == 0


@dataclass
class BranchProtectionRule:
    id: str
    pattern: str
    matching_refs: int


class GitHubBranchProtectionRulesManager:
    # These are the protection rules that should never be deleted
    PROTECTED_RULES = ["contrib/**/*"]

    RULES_FETCH_LIMIT = 100

    # TODO check how we can set RULES_FETCH_LIMIT to first: 100
    GET_BRANCH_PROTECTION_GRAPHQL_QUERY_TEMPLATE = """query($owner: String!, $name: String!) {
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
    }"""

    DELETE_BRANCH_PROTECTION_RULE_QUERY_TEMPLATE = """mutation deleteBranchProtectionRule($branchProtectionRuleId: ID!) {
        deleteBranchProtectionRule(input: {branchProtectionRuleId: $branchProtectionRuleId}) {
            clientMutationId
        }
    }"""

    def __init__(self, gh: Github, repo: str = None) -> None:
        self.gh_client = gh
        self.owner, self.repo_name = self._get_repo_name_and_owner(repo)
        self.existing_rules: list[BranchProtectionRule] = self.get_branch_protection_rules()
        self.deleted: list[BranchProtectionRule] = []

    def _get_repo_name_and_owner(self, repo: str | None) -> tuple[str, str]:
        """
        Extracts the repository owner and name from a given repository string.

        Args:
            `repo` (``str``): The repository string in the format 'owner/repository'.

        Returns:
            A `Tuple[str, str]` containing the repository owner and name.

        Raises:
            `ValueError`: If the input string is not in the expected 'owner/repository' format.
        """

        if not repo:
            logger.debug("No repo passed as an argument. Taking from env var or defaults...")
            # Try to get the repo from the env var
            repo = os.getenv(GH_REPO_ENV_VAR, DEFAULT_REPO)

        parts = repo.split('/')

        if len(parts) != 2:
            raise ValueError("Input string must be in the format 'owner/repository'.")

        owner, name = parts
        return owner, name

    def _should_delete_rule(self, rule: BranchProtectionRule) -> bool:
        """
        Check whether we should delete this rule.
        To determine if we should delete the rule we check that:

        * The rule is not in the list of protected rules (see `self.PROTECTED_RULES`)
        * The rule does not apply to any branches.

        Returns:
        - `True` if we can delete the rule, `False` otherwise.
        """

        should = False

        if rule.pattern in self.PROTECTED_RULES:
            logger.info(f"{rule=} not deleted because it's in the list of protected rules '{','.join(self.PROTECTED_RULES)}'")
        elif rule.matching_refs > 0:
            logger.info(f"{rule} not deleted because it's associated to {rule.matching_refs} existing branches/refs")
        else:
            should = True

        return should

    def handle_rate_limit(self, headers: dict[str, str]):
        """
        Handle rate limiting.

        Arguments:
        - `headers` (``dict[str, str]): The response headers.
        """

        rl = GitHubGraphQLRateLimit(
            limit=headers.get(GitHubGraphQLRateLimit.HEADER_LIMIT),
            remaining=headers.get(GitHubGraphQLRateLimit.HEADER_REMAINING),
            reset=headers.get(GitHubGraphQLRateLimit.HEADER_RESET),
            used=headers.get(GitHubGraphQLRateLimit.HEADER_USED)
        )

        if rl.exceeded():
            logger.warning(f"The  GitHub GraphQL API request rate limit ({rl.limit}) has been exceeded. It resets at {rl.reset}. Terminating...")
            sys.exit(0)

    def get_branch_protection_rules(self) -> list[BranchProtectionRule]:
        """
        Get all branch protection rules
        """

        result: list[BranchProtectionRule] = []

        variables = {
            "owner": self.owner,
            "name": self.repo_name
        }

        data = self.send_request(
            query=self.GET_BRANCH_PROTECTION_GRAPHQL_QUERY_TEMPLATE,
            variables=variables
        )

        result.extend(self._convert_dict_to_bpr(data))

        return result

    def delete_branch_protection_rule(self, pattern: str) -> None:
        """
        Delete a specified branch protection rule. If no pattern
        is supplied, delete all branch protection rules.

        Arguments:
        - `pattern` (``str``): The rule pattern to remove.
        """

        rule_to_delete = None

        # If a pattern is supplied, we try to find the rule
        # matching this pattern
        for rule in self.existing_rules:
            if pattern and rule.pattern == pattern:
                rule_to_delete = rule
                break

        if rule_to_delete and self._should_delete_rule(rule_to_delete):
            logger.debug(f"Deleting branch protection rule {rule_to_delete}...")
            self.send_rule_delete_request(rule_to_delete.id)
            logger.info(f"Rule {rule_to_delete} was deleted successfully.")
            self.deleted.append(rule_to_delete)
        else:
            logger.info(f"Rule with pattern '{pattern}' was not deleted as it was either not found or exists in the list of exceptions.")

    def purge_branch_protection_rules(self) -> None:
        """
        Delete all branch protection rules except for the ones
        specified in the exception list.
        """

        for rule in self.existing_rules:
            if self._should_delete_rule(rule):
                logger.debug(f"Deleting branch protection rule {rule}...")
                self.send_rule_delete_request(rule.id)
                logger.info(f"Rule {rule} was deleted successfully.")
                self.deleted.append(rule)

    def _convert_dict_to_bpr(self, response: dict[str, Any]) -> list[BranchProtectionRule]:

        """
        Helper method to convert the response to an instance of
        `BranchProtectionRule`.

        Arguments:
        - `response` (``dict[str, Any]``): The response data.

        Returns:
        - a `list[BranchProtectionRule]`. In case we have an issue
        parsing the response, we return an empty list.
        """

        rules: list[BranchProtectionRule] = []

        try:
            for node in response.get('data').get('repository').get('branchProtectionRules').get('nodes'):
                rule = BranchProtectionRule(
                    id=node.get("id"),
                    pattern=node.get("pattern"),
                    matching_refs=node.get("matchingRefs").get("totalCount")
                )

                rules.append(rule)
        except KeyError as ke:
            logger.error(f"Error parsing '{response=}' as a branch protection rule: {ke}")
        finally:
            return rules

    def send_request(self, query: str, variables: dict[str, str]) -> dict[str, str]:
        """
        Wrapper function to send a request to the GraphQL endpoint.

        Arguments:
        - `query` (``str``): The query to send.
        - `variables` (``dict[str, str]``): The variables to send the query.

        Returns:
        - A `dict[str, str]` with the response. If the response fails, 
        we exit 1.
        """

        logger.debug("Sending GraphQL request...")
        logger.debug(f"{query}")
        logger.debug(f"{variables}")

        try:
            headers, data = self.gh_client._Github__requester.graphql_query(
                query=query,
                variables=variables
            )

            self.handle_rate_limit(headers)

            logger.debug(data)
            return data
        except github.GithubException as gh_exc:
            logger.error(f"Error sending GraphQL request: {gh_exc}")
            sys.exit(1)

    def send_rule_delete_request(self, rule_id: str):
        """
        Send a request to GitHub GraphQL API to delete a specific
        branch protection rule.

        Arguments:
        - `rule_id` (``str``): The rule ID to delete
        """

        variables = {
            "branchProtectionRuleId": rule_id
        }

        self.send_request(
            self.DELETE_BRANCH_PROTECTION_RULE_QUERY_TEMPLATE,
            variables=variables
        )

    def write_deleted_summary_to_file(self) -> None:
        """
        Helper function to create a Markdown summary file for deleted branches.
        """

        if os.getenv(GH_JOB_SUMMARY_ENV_VAR):
            fp = Path(os.getenv(GH_JOB_SUMMARY_ENV_VAR))

            header = "## Deleted Branch Protection Rules"
            table_header = "| ID | Pattern | Matching Refs |\n| --- | ------- | ------------- |"
            table_rows = [f"| {rule.id} | {rule.pattern} | {rule.matching_refs} |" for rule in self.deleted]

            table_body = "\n".join(table_rows)

            markdown_content = f"{header}\n\n{table_header}\n{table_body}\n"

            logger.debug(f"Writing deleted jobs summary to Markdown to file '{fp}'...")
            logger.debug(markdown_content)
            fp.write_text(markdown_content)
            logger.debug("Finished writing jobs summary to Markdown to file")
        else:
            logger.info(f"Environmental variable '{GH_JOB_SUMMARY_ENV_VAR}' not set. Skipping writing job summary for deleted rules...")


def validate_gh_token() -> str:
    """
    Check if GITHUB_TOKEN env var is set.

    Returns:
    - The token as an `str`.

    Raises:
    - `OSError` if it's not set.
    """

    token = os.getenv(GH_TOKEN_ENV_VAR)
    if not token:
        raise OSError(f"Error: The '{GH_TOKEN_ENV_VAR}' environment variable is not set.")
    else:
        return token


def main(args: list[str] | None):

    exit_code = 0

    parser = argparse.ArgumentParser(
        description="A CLI to manage branch protection rules."
    )

    parser.add_argument(
        "-o",
        "--org",
        help="The GitHub repo organization/owner"
    )

    parser.add_argument(
        "-r",
        "--repo",
        help="The GitHub repo name."
    )

    # TODO implement
    parser.add_argument(
        "-d",
        "--dry-run",
        action="store_true",
        default=False,
        help="Whether to run in 'dry-run' mode. No changes will be made in GitHub. Useful for testing."
    )

    subparsers = parser.add_subparsers(title="commands", description="Available commands", dest="command")

    # Delete command
    delete_parser = subparsers.add_parser('delete', help="Delete a branch protection rule")
    delete_parser.add_argument(
        "branch_name",
        help="The branch to remove the branch protection rules from"
    )

    # Purge command
    subparsers.add_parser(
        'purge',
        help="Purge branch protection rules that have no matching branches",
    )

    args = parser.parse_args()

    try:
        if args.command in ["purge", "delete"]:
            token = validate_gh_token()

            logger.info("Authenticating with GitHub...")
            auth = github.Auth.Token(token)

            # TODO rm verify after testing (throwing self-signed cert errors)
            gh = Github(auth=auth, verify=False)
            logger.info("Finished authenticating with GitHub")

            if args.org and args.repo:
                manager = GitHubBranchProtectionRulesManager(gh=gh, repo=f"{args.org}/{args.repo}")
            else:
                manager = GitHubBranchProtectionRulesManager(gh=gh)

            if args.command == "purge":
                manager.purge_branch_protection_rules()
            elif args.command == "delete":
                manager.delete_branch_protection_rule(pattern=args.branch_name)
            else:
                raise NotImplementedError

            manager.write_deleted_summary_to_file()
        else:
            parser.print_help()
    except Exception as e:
        logger.error(f"Error running script '{__file__}': {e}")
        exit_code = 1
    finally:
        sys.exit(exit_code)


if __name__ == "__main__":
    main(sys.argv)
