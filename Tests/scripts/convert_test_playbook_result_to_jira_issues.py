import argparse
import os
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any

import urllib3
from jira import Issue
from jira.client import JIRA
from junitparser import JUnitXml
from tabulate import tabulate

from Tests.scripts.common import calculate_results_table, get_all_failed_results, \
    get_test_results_files, TEST_PLAYBOOKS_REPORT_FILE_NAME, TEST_SUITE_CELL_EXPLANATION, FAILED_TO_COLOR_NAME, FAILED_TO_MSG
from Tests.scripts.jira_issues import JIRA_SERVER_URL, JIRA_VERIFY_SSL, JIRA_API_KEY, \
    JIRA_PROJECT_ID, JIRA_ISSUE_TYPE, JIRA_COMPONENT, JIRA_ISSUE_UNRESOLVED_TRANSITION_NAME, JIRA_LABELS, \
    find_existing_jira_ticket, JIRA_ADDITIONAL_FIELDS, generate_ticket_summary, generate_build_markdown_link, \
    jira_server_information, jira_search_all_by_query, generate_query_by_component_and_issue_type, jira_file_link, \
    jira_sanitize_file_name, jira_color_text
from Tests.scripts.test_playbooks_report import calculate_test_playbooks_results, \
    TEST_PLAYBOOKS_BASE_HEADERS, get_jira_tickets_for_playbooks, TEST_PLAYBOOKS_JIRA_BASE_HEADERS, \
    write_test_playbook_to_jira_mapping, TEST_PLAYBOOKS_TO_JIRA_TICKETS_CONVERTED
from Tests.scripts.utils import logging_wrapper as logging
from Tests.scripts.utils.log_util import install_logging

urllib3.disable_warnings()  # Disable insecure warnings
JIRA_MAX_DAYS_TO_REOPEN_DEFAULT = 30
JIRA_MAX_DAYS_TO_REOPEN = (os.environ.get("JIRA_MAX_DAYS_TO_REOPEN", JIRA_MAX_DAYS_TO_REOPEN_DEFAULT)
                           or JIRA_MAX_DAYS_TO_REOPEN_DEFAULT)
JIRA_MAX_TEST_PLAYBOOKS_FAILURES_TO_HANDLE_DEFAULT = 20
JIRA_MAX_TEST_PLAYBOOKS_FAILURES_TO_HANDLE = (os.environ.get("JIRA_MAX_TEST_PLAYBOOKS_FAILURES_TO_HANDLE",
                                                             JIRA_MAX_TEST_PLAYBOOKS_FAILURES_TO_HANDLE_DEFAULT)
                                              or JIRA_MAX_TEST_PLAYBOOKS_FAILURES_TO_HANDLE_DEFAULT)


def options_handler() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Converts Test Playbook report to Jira issues')
    parser.add_argument("-a", "--artifacts-path", help='Artifacts path', required=True)
    parser.add_argument('--build-number', help='CI job number where the instances were created', required=True)
    parser.add_argument('-d', '--max-days-to-reopen', default=JIRA_MAX_DAYS_TO_REOPEN, type=int, required=False,
                        help='The max days to reopen a closed issue')
    parser.add_argument('-f', '--max-failures-to-handle', default=JIRA_MAX_TEST_PLAYBOOKS_FAILURES_TO_HANDLE,
                        type=int, required=False, help='The max days to reopen a closed issue')
    return parser.parse_args()


def generate_description_for_test_playbook(playbook_id: str,
                                           build_number: str,
                                           junit_file_name: str,
                                           table_data: Any,
                                           failed: bool) -> str:
    build_markdown_link = generate_build_markdown_link(build_number)
    table = tabulate(table_data, headers="firstrow", tablefmt="jira")
    msg = jira_color_text(FAILED_TO_MSG[failed], FAILED_TO_COLOR_NAME[failed])
    description = f"""
        *{playbook_id}* {msg} in {build_markdown_link}
        Test Results file: {jira_file_link(junit_file_name)}

        {table}
        """
    return description


def create_jira_issue(jira_server: JIRA,
                      jira_issue: Issue,
                      xml: JUnitXml,
                      playbook_id: str,
                      build_number: str,
                      table_data: list[list[str]],
                      max_days_to_reopen: int,
                      now: datetime,
                      junit_file_name: str,
                      failed: bool,
                      ) -> Issue:
    summary = generate_ticket_summary(playbook_id)
    description = generate_description_for_test_playbook(playbook_id, build_number, junit_file_name, table_data, failed)
    jira_issue, link_to_issue, use_existing_issue = find_existing_jira_ticket(jira_server, now, max_days_to_reopen, jira_issue)

    if jira_issue is not None:
        jira_server.add_comment(issue=jira_issue, body=description)
    else:
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
        xml.write(attachment_file_name.name, pretty=True)
        jira_server.add_attachment(issue=jira_issue.key, attachment=attachment_file_name.name, filename=junit_file_name)

    back_link_to = f" with back link to {link_to_issue.key}" if link_to_issue else ""
    logging.success(f"{'Updated' if use_existing_issue else 'Created'} Jira issue: {jira_issue.key} {back_link_to}"
                    f"for {playbook_id}")

    return jira_issue


def get_attachment_file_name(playbook_id: str, build_number: str) -> str:
    build_number_dash = f"-{build_number}" if build_number else ""
    junit_file_name = jira_sanitize_file_name(f"test-playbook{build_number_dash}-{playbook_id}")
    return f"{junit_file_name}.xml"


def main():
    try:
        install_logging('convert_test_playbook_result_to_jira_issues.log', logger=logging)
        now = datetime.now(tz=timezone.utc)
        options = options_handler()
        artifacts_path = Path(options.artifacts_path)
        logging.info("Converting test playbook results to Jira issues with the following settings:")
        logging.info(f"\tArtifacts path: {artifacts_path}")
        logging.info(f"\tJira server url: {JIRA_SERVER_URL}")
        logging.info(f"\tJira verify SSL: {JIRA_VERIFY_SSL}")
        logging.info(f"\tJira project id: {JIRA_PROJECT_ID}")
        logging.info(f"\tJira issue type: {JIRA_ISSUE_TYPE}")
        logging.info(f"\tJira component: {JIRA_COMPONENT}")
        logging.info(f"\tJira labels: {', '.join(JIRA_LABELS)}")
        logging.info(f"\tJira issue unresolved transition name: {JIRA_ISSUE_UNRESOLVED_TRANSITION_NAME}")
        logging.info(f"\tMax days to reopen: {options.max_days_to_reopen}")
        logging.info(f"\tMax failures to handle: {options.max_failures_to_handle}")
        logging.info(f"\tBuild number: {options.build_number}")

        jira_server = JIRA(JIRA_SERVER_URL, token_auth=JIRA_API_KEY, options={'verify': JIRA_VERIFY_SSL})
        jira_server_information(jira_server)

        if not (test_playbooks_result_files_list := get_test_results_files(Path(options.artifacts_path),
                                                                           TEST_PLAYBOOKS_REPORT_FILE_NAME)):
            logging.critical(f"Could not find any test playbook result files in {options.artifacts_path}")
            sys.exit(1)

        logging.info(f"Found {len(test_playbooks_result_files_list)} test playbook result files")

        playbooks_results, server_versions = calculate_test_playbooks_results(test_playbooks_result_files_list)

        issues = jira_search_all_by_query(jira_server, generate_query_by_component_and_issue_type())
        jira_tickets_for_playbooks: dict[str, Issue] = get_jira_tickets_for_playbooks(list(playbooks_results.keys()), issues)
        logging.info(f"Found {len(jira_tickets_for_playbooks)} Jira tickets out of {len(playbooks_results)} playbooks")

        # Search if we have too many test playbooks that failed beyond the max allowed limit to open, if so we print the
        # list and exit. This is to avoid opening too many Jira issues.
        failed_playbooks = get_all_failed_results(playbooks_results)

        if len(failed_playbooks) >= options.max_failures_to_handle:
            column_align, tabulate_data, _, _ = calculate_results_table(jira_tickets_for_playbooks,
                                                                        failed_playbooks,
                                                                        server_versions,
                                                                        TEST_PLAYBOOKS_BASE_HEADERS)
            table = tabulate(tabulate_data, headers="firstrow", tablefmt="pretty", colalign=column_align)
            logging.info(f"Test Playbook Results: {TEST_SUITE_CELL_EXPLANATION}\n{table}")
            logging.critical(f"Found {len(failed_playbooks)} failed test playbooks, "
                             f"which is more than the max allowed limit of {options.max_failures_to_handle} to handle.")

            sys.exit(1)
        for playbook_id, test_suites in playbooks_results.items():
            # We create the table without Jira tickets columns, as we don't want to have them within the Jira issue.
            # We also add the skipped tests, as we want to have them within the Jira issue.
            # The table should be created without colors, as we don't want to have them within the Jira issue.
            # We also don't want to have the total row, as we don't want to have it within the Jira issue
            # since it's a single playbook.
            _, tabulate_data, xml, total_errors = calculate_results_table(jira_tickets_for_playbooks,
                                                                          {
                                                                              playbook_id: test_suites
                                                                          },
                                                                          server_versions,
                                                                          TEST_PLAYBOOKS_JIRA_BASE_HEADERS,
                                                                          add_total_row=False,
                                                                          no_color=True,
                                                                          without_jira=True,
                                                                          with_skipped=True,
                                                                          multiline_headers=False,
                                                                          transpose=True,
                                                                          )

            jira_ticket = jira_tickets_for_playbooks.get(playbook_id)
            if jira_ticket or total_errors:
                # if the ticket isn't resolved, or we found new errors, we update it, otherwise we skip it.
                if jira_ticket and jira_ticket.get_field("resolution") and not total_errors:
                    jira_tickets_for_playbooks[playbook_id] = jira_ticket
                    logging.debug(f"Skipped updating Jira issue for resolved test playbook:{playbook_id}")
                    continue
                junit_file_name = get_attachment_file_name(playbook_id, options.build_number)
                jira_ticket = create_jira_issue(jira_server, jira_ticket, xml, playbook_id, options.build_number, tabulate_data,
                                                options.max_days_to_reopen, now, junit_file_name, total_errors > 0)
                jira_tickets_for_playbooks[playbook_id] = jira_ticket
            else:
                logging.debug(f"Skipped creating Jira issue for successful test playbook:{playbook_id}")

        write_test_playbook_to_jira_mapping(artifacts_path, jira_tickets_for_playbooks)
        open(artifacts_path / TEST_PLAYBOOKS_TO_JIRA_TICKETS_CONVERTED, "w")
        logging.info("Finished creating/updating Jira issues")

    except Exception as e:
        logging.exception(f'Failed to convert Test playbook results to Jira issues, Additional info: {e}')
        logging.error(traceback.format_exc())
        sys.exit(1)


if __name__ == '__main__':
    main()
