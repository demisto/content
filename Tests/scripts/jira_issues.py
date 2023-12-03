import json
import os
import re
from collections import defaultdict
from datetime import datetime, timedelta
from distutils.util import strtobool
from typing import Any

from jira import JIRA, Issue
from jira.client import ResultList

from Tests.scripts.utils import logging_wrapper as logging

GITLAB_PROJECT_ID = os.getenv('CI_PROJECT_ID')
GITLAB_SERVER_URL = os.getenv('CI_SERVER_URL')
CI_PIPELINE_URL = os.getenv('CI_PIPELINE_URL', '')
JIRA_SERVER_URL = os.environ["JIRA_SERVER_URL"]
JIRA_VERIFY_SSL = bool(strtobool(os.environ.get("JIRA_VERIFY_SSL", "true")))
JIRA_API_KEY = os.environ["JIRA_API_KEY"]
JIRA_PROJECT_ID = os.environ["JIRA_PROJECT_ID"]
JIRA_ISSUE_TYPE = os.environ.get("JIRA_ISSUE_TYPE", "")  # Default to empty string if not set
JIRA_COMPONENT = os.environ.get("JIRA_COMPONENT", "")  # Default to empty string if not set
JIRA_ISSUE_UNRESOLVED_TRANSITION_NAME = os.environ["JIRA_ISSUE_UNRESOLVED_TRANSITION_NAME"]
JIRA_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%f%z"
# Jira additional fields are a json string that will be parsed into a dictionary containing the name of the field
# as the key and the value as a dictionary containing the value of the field.
JIRA_ADDITIONAL_FIELDS = json.loads(os.environ.get("JIRA_ADDITIONAL_FIELDS", "{}"))
# Jira label are a json string that will be parsed into a list of labels.
JIRA_LABELS = json.loads(os.environ.get("JIRA_LABELS", "[]"))


def generate_ticket_summary(prefix: str) -> str:
    # This is the existing conventions of the Content Gold Bot, don't change as it will break backward compatibility.
    summary = f"{prefix} fails nightly"
    return summary


def generate_query_by_component_and_issue_type() -> str:
    jira_labels = "".join(f" AND labels = \"{x}\"" for x in JIRA_LABELS) if JIRA_LABELS else ""
    return (f"project = \"{JIRA_PROJECT_ID}\" AND issuetype = \"{JIRA_ISSUE_TYPE}\" "
            f"AND component = \"{JIRA_COMPONENT}\" {jira_labels}")


def generate_query_with_summary(summary: str) -> str:
    jql_query = f"{generate_query_by_component_and_issue_type()} AND summary ~ \"{summary}\" ORDER BY created DESC"
    return jql_query


def convert_jira_time_to_datetime(jira_time: str) -> datetime:
    return datetime.strptime(jira_time, JIRA_TIME_FORMAT)


def jira_file_link(file_name: str) -> str:
    return f"[^{file_name}]"


def jira_sanitize_file_name(file_name: str) -> str:
    return re.sub(r'[^\w-]', '-', file_name).lower()


def jira_color_text(text: str, color: str) -> str:
    return f"{{color:{color}}}{text}{{color}}"


def find_existing_jira_ticket(jira_server: JIRA,
                              now: datetime,
                              max_days_to_reopen: int,
                              jira_issue: Issue | None,
                              ) -> tuple[Issue | None, Issue | None, bool]:
    link_to_issue = None
    jira_issue_to_use = None
    if use_existing_issue := (jira_issue is not None):
        searched_issue: Issue = jira_issue
        if searched_issue.get_field("resolution"):
            resolution_date = convert_jira_time_to_datetime(searched_issue.get_field("resolutiondate"))
            if use_existing_issue := (resolution_date
                                      and (now - resolution_date)
                                      <= timedelta(days=max_days_to_reopen)):  # type: ignore[assignment]

                #  Get the available transitions for the issue
                transitions = jira_server.transitions(searched_issue)

                # Find the transition with the specified ID
                unresolved_transition = None
                for transition in transitions:
                    if transition['name'] == JIRA_ISSUE_UNRESOLVED_TRANSITION_NAME:
                        unresolved_transition = transition
                        break
                if unresolved_transition:
                    jira_server.transition_issue(searched_issue, unresolved_transition['id'])
                    jira_issue_to_use = searched_issue
                else:
                    logging.error(f"Failed to find the '{JIRA_ISSUE_UNRESOLVED_TRANSITION_NAME}' "
                                  f"transition for issue {searched_issue.key}")
                    jira_issue_to_use = None
                    use_existing_issue = False
                    link_to_issue = searched_issue

            else:
                link_to_issue = searched_issue
        else:
            jira_issue_to_use = searched_issue
    return jira_issue_to_use, link_to_issue, use_existing_issue


def generate_build_markdown_link(ci_pipeline_id: str) -> str:
    ci_pipeline_id_hash = f" #{ci_pipeline_id}" if ci_pipeline_id else ""
    ci_pipeline_markdown_link = f"[Nightly{ci_pipeline_id_hash}|{CI_PIPELINE_URL}]" \
        if CI_PIPELINE_URL else f"Nightly{ci_pipeline_id_hash}"
    return ci_pipeline_markdown_link


def jira_server_information(jira_server: JIRA):
    jira_server_info = jira_server.server_info()
    logging.info("Jira server information:")
    for key, value in jira_server_info.items():
        logging.info(f"\t{key}: {value}")


def jira_search_all_by_query(jira_server: JIRA,
                             jql_query: str,
                             max_results_per_request: int = 100,
                             ) -> dict[str, list[Issue]]:

    start_at = 0  # Initialize pagination parameters
    issues: dict[str, list[Issue]] = defaultdict(list)
    while True:
        issues_batch: ResultList[Issue] = jira_server.search_issues(jql_query,  # type: ignore[assignment]
                                                                    startAt=start_at,
                                                                    maxResults=max_results_per_request)
        for issue in issues_batch:
            summary: str = issue.get_field("summary").lower()
            issues[summary].append(issue)

        # Update the startAt value for the next page
        start_at += max_results_per_request
        if start_at >= issues_batch.total:
            break

    return issues


def jira_ticket_to_json_data(jira_ticket: Issue) -> dict[str, Any]:
    return {
        "url": jira_ticket.permalink(),
        "key": jira_ticket.key,
    }
