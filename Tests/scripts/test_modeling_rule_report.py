import contextlib
import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from tempfile import NamedTemporaryFile

from jira import JIRA, Issue
from jira.client import ResultList
from junitparser import TestSuite, JUnitXml
from tabulate import tabulate

from Tests.scripts.common import get_properties_for_test_suite, FAILED_TO_COLOR_NAME, FAILED_TO_MSG
from Tests.scripts.jira_issues import generate_ticket_summary, generate_query_with_summary, \
    find_existing_jira_ticket, JIRA_PROJECT_ID, JIRA_ISSUE_TYPE, JIRA_COMPONENT, JIRA_LABELS, JIRA_ADDITIONAL_FIELDS, \
    generate_build_markdown_link, convert_jira_time_to_datetime, jira_ticket_to_json_data, jira_file_link, \
    jira_sanitize_file_name, jira_color_text
from Tests.scripts.utils import logging_wrapper as logging

TEST_MODELING_RULES_BASE_HEADERS = ["Test Modeling Rule"]
TEST_MODELING_RULES_TO_JIRA_MAPPING = "test_modeling_rule_to_jira_mapping.json"
TEST_MODELING_RULES_TO_JIRA_TICKETS_CONVERTED = "test_modeling_rule_to_jira_tickets_converted.txt"


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

    junit_file_name = jira_sanitize_file_name(f"unit-test{ci_pipeline_id_dash}-{properties['pack_id']}-{properties['file_name']}")
    junit_file_name_with_suffix = f"{junit_file_name}.xml"
    description = generate_description_for_test_modeling_rule(ci_pipeline_id, properties, test_suite, junit_file_name_with_suffix)
    summary = generate_ticket_summary(get_summary_for_test_modeling_rule(properties))  # type: ignore[arg-type]
    jql_query = generate_query_with_summary(summary)
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
                                              labels=JIRA_LABELS,
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
        jira_server.add_attachment(issue=jira_issue.key, attachment=attachment_file_name.name,
                                   filename=junit_file_name_with_suffix)

    back_link_to = f" with back link to {link_to_issue.key}" if link_to_issue else ""
    logging.info(f"{'Updated' if use_existing_issue else 'Created'} Jira issue: {jira_issue.key} {back_link_to}"
                 f"for {test_suite.name} with {test_suite.failures} failures and {test_suite.errors} errors")

    return jira_issue


def generate_description_for_test_modeling_rule(ci_pipeline_id: str,
                                                properties: dict[str, str],
                                                test_suite: TestSuite,
                                                junit_file_name: str,
                                                ) -> str:
    build_markdown_link = generate_build_markdown_link(ci_pipeline_id)
    table = tabulate(tablefmt="jira", headers=["Tests", "Result"], tabular_data=[
        ["Successful", jira_color_text(test_suite.tests, FAILED_TO_COLOR_NAME[test_suite.tests == 0])],
        ["Failed", jira_color_text(test_suite.failures, FAILED_TO_COLOR_NAME[test_suite.failures > 0])],
        ["Errors", jira_color_text(test_suite.errors, FAILED_TO_COLOR_NAME[test_suite.errors > 0])],
        ["Skipped", test_suite.skipped],  # no color for skipped.
        ["Duration", f"{test_suite.time}s"]
    ])
    failed = test_suite.failures > 0 or test_suite.errors > 0
    msg = jira_color_text(FAILED_TO_MSG[failed], FAILED_TO_COLOR_NAME[failed])
    description = f"""
        *{properties['pack_id']}* - *{properties['file_name']}* {msg} in {build_markdown_link}
        Test Results file: {jira_file_link(junit_file_name)}

        {table}
        """
    return description


def calculate_test_modeling_rule_results(test_modeling_rules_results_files: dict[str, Path],
                                         issues: dict[str, list[Issue]] | None = None,
                                         ) -> tuple[dict[str, dict[str, TestSuite]], dict[str, Issue], set[str]]:
    issues = issues or {}
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
                ticket_summary = generate_ticket_summary(summary).lower()
                if issues_matching_summary := issues.get(ticket_summary, []):
                    sorted_issues_matching_summary = sorted(issues_matching_summary,
                                                            key=lambda issue: convert_jira_time_to_datetime(
                                                                issue.get_field("created")),
                                                            reverse=True)
                    jira_tickets_for_modeling_rule[summary] = sorted_issues_matching_summary[0]

    return modeling_rules_to_test_suite, jira_tickets_for_modeling_rule, server_versions


def write_test_modeling_rule_to_jira_mapping(artifacts_path: Path, jira_tickets_for_modeling_rule: dict[str, Issue]):
    test_modeling_rule_to_jira_mapping_file = artifacts_path / TEST_MODELING_RULES_TO_JIRA_MAPPING
    logging.info(f"Writing test_modeling_rules_to_jira_mapping to {test_modeling_rule_to_jira_mapping_file}")
    with open(test_modeling_rule_to_jira_mapping_file, "w") as test_modeling_rule_to_jira_mapping_fp:
        test_modeling_rule_to_jira_mapping = {modeling_rule: jira_ticket_to_json_data(jira_ticket)
                                              for modeling_rule, jira_ticket in jira_tickets_for_modeling_rule.items()}
        test_modeling_rule_to_jira_mapping_fp.write(json.dumps(test_modeling_rule_to_jira_mapping, indent=4, sort_keys=True,
                                                               default=str))


def read_test_modeling_rule_to_jira_mapping(artifacts_path: Path) -> dict[str, dict[str, str]]:
    logging.debug(f"Reading test_modeling_rules_to_jira_mapping from {TEST_MODELING_RULES_TO_JIRA_MAPPING}")
    with (contextlib.suppress(Exception),
          open(artifacts_path / TEST_MODELING_RULES_TO_JIRA_MAPPING) as playbook_to_jira_mapping_file):
        return json.load(playbook_to_jira_mapping_file)
    return {}
