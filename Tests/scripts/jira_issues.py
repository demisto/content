import json
import os
from datetime import datetime, timedelta
from distutils.util import strtobool

from jira import JIRA, Issue

from Tests.scripts.utils import logging_wrapper as logging

GITLAB_PROJECT_ID = os.getenv('CI_PROJECT_ID')
GITLAB_SERVER_URL = os.getenv('CI_SERVER_URL')
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
    summary = f"{prefix} failed nightly"
    return summary


def generate_query(summary: str) -> str:
    jql_query = (f"project = \"{JIRA_PROJECT_ID}\" AND issuetype = \"{JIRA_ISSUE_TYPE}\" "
                 f"AND component = \"{JIRA_COMPONENT}\" AND summary ~ \"{summary}\" ORDER BY created DESC")
    return jql_query


def find_existing_jira_ticket(jira_server: JIRA,
                              now: datetime,
                              max_days_to_reopen: int,
                              jira_issue: Issue | None) -> tuple[Issue | None, Issue | None, bool]:
    link_to_issue = None
    jira_issue_to_use = None
    if use_existing_issue := (jira_issue is not None):
        searched_issue: Issue = jira_issue
        if searched_issue.get_field("resolution"):
            resolution_date = datetime.strptime(searched_issue.get_field("resolutiondate"), JIRA_TIME_FORMAT)
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
    pipeline_url = f"{GITLAB_SERVER_URL}/{GITLAB_PROJECT_ID}/-/pipelines/{ci_pipeline_id}" if ci_pipeline_id else ""
    ci_pipeline_id_hash = f" #{ci_pipeline_id}" if ci_pipeline_id else ""
    ci_pipeline_markdown_link = f"[Nightly{ci_pipeline_id_hash}|{pipeline_url}]" \
        if ci_pipeline_id else f"Nightly{ci_pipeline_id_hash}"
    return ci_pipeline_markdown_link


def jira_server_information(jira_server: JIRA):
    jira_server_info = jira_server.server_info()
    logging.info("Jira server information:")
    for key, value in jira_server_info.items():
        logging.info(f"\t{key}: {value}")
