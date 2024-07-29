"""
A CLI to manage GitHub branch protection rules.

It uses GitHub GraphQL API to query and remove
branch protection rules.
"""

from dataclasses import dataclass
import os
from pathlib import Path
import sys
from typing import Any

import tabulate
from utils import get_logger

from github import Github
import github
import github.Requester


DEFAULT_REPO = "demisto/content"

GH_TOKEN_ENV_VAR = "GITHUB_TOKEN"

# https://docs.github.com/en/actions/learn-github-actions/variables#default-environment-variables
# e.g. 'demisto/content'
GH_REPO_ENV_VAR = "GITHUB_REPOSITORY"
GH_JOB_SUMMARY_ENV_VAR = "GITHUB_STEP_SUMMARY"
PROTECTED_RULES = ["contrib/**/*", "master"]

logger = get_logger(f"{Path(__file__).stem}")


@dataclass
class BranchProtectionRule:
    id: str
    pattern: str
    matching_refs: int


# Queries
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


# Helper Functions

def get_repo_owner_and_name() -> tuple[str, str]:
    """
    Extracts the repository owner and name from a given repository string.

    Returns:
        A `Tuple[str, str]` containing the repository owner and name.

    Raises:
        `ValueError`: If the input string is not in the expected 'owner/repository' format.
    """

    repo = os.getenv(GH_REPO_ENV_VAR, DEFAULT_REPO)

    parts = repo.split('/')

    if len(parts) != 2:
        raise ValueError("Input string must be in the format 'owner/repository'.")

    owner, name = parts
    return owner, name


def convert_response_to_rules(response: dict[str, Any]) -> list[BranchProtectionRule]:
    """
    Helper method to convert the response to a list
    of `BranchProtectionRule`.

    Arguments:
    - `response` (``dict[str, Any]``): The response data.

    Returns:
    - a `list[BranchProtectionRule]`.

    Raises:
    - `KeyError | AttributeError` in case the conversion fails.
    """

    rules: list[BranchProtectionRule] = []

    try:
        for node in response.get('data', {}).get('repository').get('branchProtectionRules').get('nodes'):
            rule = BranchProtectionRule(
                id=node.get("id"),
                pattern=node.get("pattern"),  # ignore: type
                matching_refs=node.get("matchingRefs").get("totalCount")
            )

            rules.append(rule)
    except (KeyError, AttributeError) as e:
        raise e.__class__(f"{e.__class__.__name__} parsing '{response=}' as a branch protection rule: {e}")

    return rules


def should_delete_rule(rule: BranchProtectionRule) -> bool:
    """
    Check whether we should delete this rule.
    To determine if we should delete the rule we check that:

    * The rule is not in the list of protected rules (see `self.PROTECTED_RULES`)
    * The rule does not apply to any branches.

    Returns:
    - `True` if we can delete the rule, `False` otherwise.
    """

    if rule.pattern in PROTECTED_RULES:
        logger.info(f"{rule} not deleted because it's in the list of protected rules '{','.join(PROTECTED_RULES)}'")
        return False
    elif rule.matching_refs > 0:
        logger.info(f"{rule} not deleted because it's associated to {rule.matching_refs} existing branches/refs")
        return False
    else:
        return True


def write_deleted_summary_to_file(deleted: list[BranchProtectionRule]) -> None:
    """
    Helper function to create a Markdown summary file for deleted branches
    if the `GITHUB_STEP_SUMMARY` is set. See
    https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions#adding-a-job-summary

    Arguments:
    - `deleted` (``list[BranchProtectionRule]``): A list of deleted `BranchProtectionRule`s.
    """

    if os.getenv(GH_JOB_SUMMARY_ENV_VAR):
        fp = Path(str(os.getenv(GH_JOB_SUMMARY_ENV_VAR)))

        if not fp.is_file():
            logger.warning(f"The env var {GH_JOB_SUMMARY_ENV_VAR} is not set to a file. Not writing summary...")
            return

        header = "## Deleted Branch Protection Rules"

        if not deleted:
            body = "### No branch protection rules were deleted"
            markdown_content = f"{header}\n\n{body}\n"
        else:
            headers = ["ID", "Pattern", "Matching Refs"]
            table_rows = [[rule.id, rule.pattern, rule.matching_refs] for rule in deleted]

            table_body = tabulate.tabulate(
                tabular_data=table_rows,
                headers=headers,
                tablefmt='github'
            )
            markdown_content = f"{header}\n\n{table_body}\n"

        logger.debug(f"Writing deleted jobs summary to Markdown to file '{fp}'...")
        logger.debug(markdown_content)
        fp.write_text(markdown_content)
        logger.debug("Finished writing jobs summary to Markdown to file")
    else:
        logger.info(
            f"Environmental variable '{GH_JOB_SUMMARY_ENV_VAR}' not set. Skipping writing job summary for deleted rules...")


def get_token():
    """
    Helper method to retrieve the GitHub token
    from the environmental variables.

    Returns:
    - `token` (``str``): The GitHub token.

    Raises:
    `OSError` if the `GITHUB_TOKEN` env var is not set.
    """
    token = os.getenv(GH_TOKEN_ENV_VAR)
    if not token:
        raise OSError(f"Error: The '{GH_TOKEN_ENV_VAR}' environment variable is not set.")
    return token


def send_request(gh_requester: github.Requester.Requester, query: str, variables: dict[str, str]) -> dict[str, str]:
    """
    Wrapper function to send a request to the GraphQL endpoint.

    Arguments:
    - `query` (``str``): The query to send.
    - `variables` (``dict[str, str]``): The variables to send the query.

    Returns:
    - A `dict[str, str]` with the response.

    Raises:
    If the request fails, we raise
    """

    logger.debug(f"Sending GraphQL request...\n{query=}\n{variables=}\n")

    response_headers, response_data = gh_requester.graphql_query(  # type:ignore[attr-defined]
        query=query,
        variables=variables
    )

    logger.debug(f"Response received:\n{response_data}\n{response_headers}")

    return response_data


# API Functions
def purge_branch_protection_rules(
    gh_requester: github.Requester.Requester,
    rules: list[BranchProtectionRule]
) -> list[BranchProtectionRule]:
    """
    Delete all branch protection rules except for the ones
    specified in the exception list.

    Arguments:
    - `gh_requester` (``github.Requester.Requester``): The instance
    of the GitHub client.
    - `rules` (``list[BranchProtectionRule]``): The rules to iterate over
    and delete.

    Returns:
    - `list[BranchProtectionRule]` that were deleted
    """

    deleted: list[BranchProtectionRule] = []

    for rule in rules:
        if should_delete_rule(rule):
            logger.info(f"Deleting {rule}...")

            query = DELETE_BRANCH_PROTECTION_RULE_QUERY_TEMPLATE
            variables = {
                "branchProtectionRuleId": rule.id
            }
            send_request(gh_requester, query, variables)
            logger.info(f"{rule} was deleted successfully.")
            deleted.append(rule)

    return deleted


def get_branch_protection_rules(
    gh_requester: github.Requester.Requester,
    owner: str,
    repo_name: str
) -> list[BranchProtectionRule]:
    """
    Retrieve all branch protection rules. The API limits us to getting
    100 rules at a time.

    Arguments:
    - `gh_requester` (``github.Requester.Requester``): The instance
    of the GitHub client.
    - `owner` (``str``): The GitHub repo owner.
    - `repo_name` (``str``): The GitHub repo name.

    Returns:
    - `list[BranchProtectionRule]` of rules found
    in GitHub.
    """

    data = send_request(
        gh_requester=gh_requester,
        query=GET_BRANCH_PROTECTION_GRAPHQL_QUERY_TEMPLATE,
        variables={"owner": owner, "name": repo_name}
    )

    logger.debug("Converting response to BranchProtectionRules...")
    existing_rules = convert_response_to_rules(data)
    logger.debug("Finished converting response to BranchProtectionRules")
    return existing_rules


# Entrypoint

def main():
    """
    The method purges all branch protection rules using
    the GitHub GraphQL API.

    To do so, it:

    1. Checks that the mandatory env vars (`GITHUB_TOKEN`, `GITHUB_REPOSITORY`) are set.
    2. Sends a request to retrieve the first 100 rules (API limitation).
    3. Iterate over each rule and check if it should be deleted.
    4. If env var `GH_JOB_SUMMARY_ENV_VAR` is set to a file path,
    it prints a summary of deleted rules to a Markdown-formatted file.
    """

    try:
        token = get_token()
        owner, repo_name = get_repo_owner_and_name()

        logger.info("Authenticating with GitHub...")
        auth = github.Auth.Token(token)

        gh_client = Github(auth=auth)
        logger.info("Finished authenticating with GitHub")

        requester: github.Requester.Requester = gh_client._Github__requester  # type:ignore[attr-defined]

        logger.info("Sending request to get protection rules...")
        existing_rules = get_branch_protection_rules(
            requester,
            owner,
            repo_name
        )
        logger.info(f"{len(existing_rules)} rules returned.")
        logger.debug(f"{existing_rules=}")

        deleted = purge_branch_protection_rules(requester, existing_rules)

        write_deleted_summary_to_file(deleted)
    except Exception as e:
        logger.exception(f"Error {e.__class__.__name__} running script '{__file__}': {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
