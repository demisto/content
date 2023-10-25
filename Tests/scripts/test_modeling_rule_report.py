from collections import defaultdict
from datetime import datetime
from pathlib import Path
from tempfile import NamedTemporaryFile

import tenacity
from jira import JIRA, Issue, JIRAError
from jira.client import ResultList
from junitparser import TestSuite, JUnitXml
from tabulate import tabulate

from Tests.scripts.common import get_properties_for_test_suite
from Tests.scripts.jira_issues import generate_ticket_summary, generate_query, \
    find_existing_jira_ticket, JIRA_PROJECT_ID, JIRA_ISSUE_TYPE, JIRA_COMPONENT, JIRA_LABELS, JIRA_ADDITIONAL_FIELDS, \
    generate_build_markdown_link
from Tests.scripts.utils import logging_wrapper as logging

TEST_MODELING_RULES_BASE_HEADERS = ["Test Modeling Rule"]


def get_summary_for_test_modeling_rule(properties: dict[str, str]) -> str | None:
    if 'pack_id' not in properties or 'file_name' not in properties:
        return None
    return f"{properties['pack_id']} - {properties['file_name']}"


def create_jira_issue_for_test_modeling_rule(jira_server: JIRA,
                                             test_suite: TestSuite,
                                             max_days_to_reopen: int,
                                             now: datetime) -> Issue | None:
    properties = get_properties_for_test_suite(test_suite)
    ci_pipeline_id = properties.get("ci_pipeline_id", "")
    ci_pipeline_id_dash = f"-{ci_pipeline_id}" if ci_pipeline_id else ""
    junit_file_name = (f"unit-test{ci_pipeline_id_dash}-{properties['start_time']}-{properties['pack_id']}-"
                       f"{properties['file_name']}.xml")
    description = generate_description_for_test_modeling_rule(ci_pipeline_id, properties, test_suite, junit_file_name)
    summary = generate_ticket_summary(get_summary_for_test_modeling_rule(properties))  # type: ignore[arg-type]
    jql_query = generate_query(summary)
    search_issues: ResultList[Issue] = jira_server.search_issues(jql_query, maxResults=1)  # type: ignore[assignment]
    jira_issue, link_to_issue, use_existing_issue = find_existing_jira_ticket(jira_server, now, max_days_to_reopen,
                                                                              search_issues[0] if search_issues else None)

    if jira_issue is not None:
        if test_suite.failures == 0 and test_suite.errors == 0 and (resolution := jira_issue.get_field("resolution")) is not None:
            logging.info(f"Skipping updating Jira issue {jira_issue.key} as it has no failures or errors "
                         f"and the Jira ticket is resolved with resolution:{resolution}")
            return None
        jira_server.add_comment(issue=jira_issue, body=description)
    else:
        if test_suite.failures == 0 and test_suite.errors == 0:
            logging.info(f"Skipping creating Jira issue for {test_suite.name} as it has no failures or errors")
            return None
        jira_issue = jira_server.create_issue(project=JIRA_PROJECT_ID,
                                              summary=summary,
                                              description=description,
                                              issuetype={'name': JIRA_ISSUE_TYPE},
                                              components=[{'name': JIRA_COMPONENT}],
                                              labels=['nightly'] + JIRA_LABELS,
                                              **JIRA_ADDITIONAL_FIELDS
                                              )
        # Create a back link to the previous issue, which is resolved.
        if link_to_issue:
            jira_server.create_issue_link(type="Relates", inwardIssue=jira_issue.key,
                                          outwardIssue=link_to_issue.key)

    with NamedTemporaryFile() as attachment_file_name:
        xml = JUnitXml()
        xml.add_testsuite(test_suite)
        xml.write(attachment_file_name.name, pretty=True)
        jira_server.add_attachment(issue=jira_issue.key, attachment=attachment_file_name.name, filename=junit_file_name)

    back_link_to = f" with back link to {link_to_issue.key}" if link_to_issue else ""
    logging.info(f"{'Updated' if use_existing_issue else 'Created'} Jira issue: {jira_issue.key} {back_link_to}"
                 f"for {test_suite.name} with {test_suite.failures} failures and {test_suite.errors} errors")

    return jira_issue


def generate_description_for_test_modeling_rule(ci_pipeline_id: str,
                                                properties: dict[str, str],
                                                test_suite: TestSuite,
                                                junit_file_name: str) -> str:
    build_markdown_link = generate_build_markdown_link(ci_pipeline_id)
    table = tabulate(tabular_data=[
        ["Total", test_suite.tests],
        ["Failed", test_suite.failures],
        ["Errors", test_suite.errors],
        ["Skipped", test_suite.skipped],
        ["Successful", test_suite.tests - test_suite.failures - test_suite.errors - test_suite.skipped],
        ["Duration", f"{test_suite.time}s"]
    ], tablefmt="jira", headers=["Tests", "Result"])
    description = f"""
        *{properties['pack_id']}* - *{properties['file_name']}* failed in {build_markdown_link}
        Test Results file: {junit_file_name}

        {table}
        """
    return description


@tenacity.retry(
    wait=tenacity.wait_exponential(multiplier=1, min=2, max=10),
    stop=tenacity.stop_after_attempt(2),
    reraise=True,
    retry=tenacity.retry_if_exception_type(JIRAError),
    before_sleep=tenacity.before_sleep_log(logging.getLogger(), logging.DEBUG)
)
def search_in_jira_ticket_for_test_modeling_rule(jira_server: JIRA, summary: str) -> Issue | None:
    ticket_summary = generate_ticket_summary(summary)
    jql_query = generate_query(ticket_summary)
    search_issues: ResultList[Issue] = jira_server.search_issues(jql_query)  # type: ignore[assignment]
    if search_issues:
        summary_lower = summary.lower()
        for issue in search_issues:
            if summary_lower in issue.get_field("summary").lower():
                return issue
    return None


def calculate_test_modeling_rule_results(test_modeling_rules_results_files: dict[str, Path],
                                         jira_server: JIRA | None = None
                                         ) -> tuple[dict[str, dict[str, TestSuite]], dict[str, Issue], set[str]]:
    modeling_rules_to_test_suite: dict[str, dict[str, TestSuite]] = defaultdict(dict)
    jira_tickets_for_modeling_rule: dict[str, Issue] = {}
    server_versions: set[str] = set()
    for instance_role, result_file in test_modeling_rules_results_files.items():
        xml = JUnitXml.fromfile(result_file.as_posix())
        server_versions.add(instance_role)
        for test_suite in xml.iterchildren(TestSuite):
            properties = get_properties_for_test_suite(test_suite)
            if summary := get_summary_for_test_modeling_rule(properties):
                modeling_rules_to_test_suite[summary][instance_role] = test_suite
                if jira_server:
                    try:
                        if issue := search_in_jira_ticket_for_test_modeling_rule(jira_server, summary):
                            jira_tickets_for_modeling_rule[summary] = issue
                    except JIRAError:
                        logging.error(f"Failed to search for Jira ticket for {summary}")

    return modeling_rules_to_test_suite, jira_tickets_for_modeling_rule, server_versions
