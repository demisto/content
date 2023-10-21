from datetime import datetime
from pathlib import Path
from tempfile import NamedTemporaryFile

from jira import JIRA, Issue
from jira.client import ResultList
from junitparser import TestSuite, JUnitXml
from tabulate import tabulate

from Tests.scripts.common import get_instance_directories
from Tests.scripts.jira_issues import generate_ticket_summary, generate_query, \
    find_existing_jira_ticket, JIRA_PROJECT_ID, JIRA_ISSUE_TYPE, JIRA_COMPONENT, JIRA_LABELS, JIRA_ADDITIONAL_FIELDS, \
    generate_build_markdown_link
from Tests.scripts.utils import logging_wrapper as logging


def create_jira_issue_for_test_modeling_rule(jira_server: JIRA,
                                             test_suite: TestSuite,
                                             max_days_to_reopen: int,
                                             now: datetime) -> Issue | None:
    properties = {prop.name: prop.value for prop in test_suite.properties()}
    ci_pipeline_id = properties.get("ci_pipeline_id", "")
    ci_pipeline_id_dash = f"-{ci_pipeline_id}" if ci_pipeline_id else ""
    junit_file_name = (f"unit-test{ci_pipeline_id_dash}-{properties['start_time']}-{properties['pack_id']}-"
                       f"{properties['file_name']}.xml")
    description = generate_description_for_test_modeling_rule(ci_pipeline_id, properties, test_suite, junit_file_name)
    summary = generate_ticket_summary(f"{properties['pack_id']} - {properties['file_name']}")
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


def get_test_modeling_rules_results_files(artifacts_path: Path) -> list[Path]:
    result_files_list: list[Path] = []
    for instance_role, directory in get_instance_directories(artifacts_path).items():
        logging.info(f"Found instance directory: {directory} for instance role: {instance_role}")
        test_playbooks_report_file = Path(artifacts_path) / directory / "test_playbooks_report.xml"
        if test_playbooks_report_file.exists():
            logging.info(f"Found test playbook result files list file: {test_playbooks_report_file}")
            result_files_list.append(test_playbooks_report_file)
    return result_files_list
