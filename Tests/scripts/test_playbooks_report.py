from pathlib import Path
from typing import Any

from jira import Issue
from junitparser import JUnitXml, TestSuite

from Tests.scripts.common import get_properties_for_test_suite
from Tests.scripts.jira_issues import generate_ticket_summary, convert_jira_time_to_datetime
from Tests.scripts.utils import logging_wrapper as logging

TEST_PLAYBOOKS_BASE_HEADERS = ["Playbook ID"]


def calculate_test_playbooks_results(test_playbooks_result_files_list: dict[str, Path]
                                     ) -> tuple[dict[str, dict[str, Any]], set[str]]:
    playbooks_results: dict[str, dict[str, Any]] = {}
    server_versions = set()
    for instance_role, test_playbook_result_file in test_playbooks_result_files_list.items():
        logging.debug(f"Processing test playbook result file: {test_playbook_result_file} for instance role: {instance_role}")
        xml = JUnitXml.fromfile(test_playbook_result_file.as_posix())
        for test_suite_item in xml.iterchildren(TestSuite):
            properties = get_properties_for_test_suite(test_suite_item)
            if "playbook_id" in properties:
                playbooks_result = playbooks_results.setdefault(properties["playbook_id"], {})
                server_version = properties["server_version"]
                server_versions.add(server_version)
                playbooks_result[server_version] = test_suite_item
    return playbooks_results, server_versions


def get_jira_tickets_for_playbooks(playbook_ids: list[str],
                                   issues: dict[str, list[Issue]],
                                   ) -> dict[str, Issue]:
    playbook_ids_to_jira_tickets: dict[str, Issue] = {}
    for playbook_id in playbook_ids:
        jira_ticket_summary = generate_ticket_summary(playbook_id)
        if jira_ticket_summary.lower() in issues:
            sorted_issues = sorted(issues[jira_ticket_summary.lower()],
                                   key=lambda issue: convert_jira_time_to_datetime(issue.get_field("created")),
                                   reverse=True)
            playbook_ids_to_jira_tickets[playbook_id] = sorted_issues[0]
    return playbook_ids_to_jira_tickets
