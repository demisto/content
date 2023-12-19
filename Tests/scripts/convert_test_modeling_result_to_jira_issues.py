import argparse
import os
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path

import urllib3
from jira import JIRA
from junitparser import TestSuite, JUnitXml
from tabulate import tabulate

from Tests.scripts.common import get_all_failed_results, calculate_results_table, TEST_MODELING_RULES_REPORT_FILE_NAME, \
    get_test_results_files, TEST_SUITE_CELL_EXPLANATION, get_properties_for_test_suite
from Tests.scripts.jira_issues import JIRA_SERVER_URL, JIRA_VERIFY_SSL, JIRA_API_KEY, \
    JIRA_PROJECT_ID, JIRA_ISSUE_TYPE, JIRA_COMPONENT, JIRA_ISSUE_UNRESOLVED_TRANSITION_NAME, JIRA_LABELS, \
    jira_server_information, jira_search_all_by_query, generate_query_by_component_and_issue_type
from Tests.scripts.test_modeling_rule_report import (create_jira_issue_for_test_modeling_rule,
                                                     TEST_MODELING_RULES_BASE_HEADERS,
                                                     calculate_test_modeling_rule_results,
                                                     write_test_modeling_rule_to_jira_mapping, get_summary_for_test_modeling_rule,
                                                     TEST_MODELING_RULES_TO_JIRA_TICKETS_CONVERTED)
from Tests.scripts.utils import logging_wrapper as logging
from Tests.scripts.utils.log_util import install_logging

urllib3.disable_warnings()  # Disable insecure warnings
JIRA_MAX_DAYS_TO_REOPEN_DEFAULT = 30
JIRA_MAX_DAYS_TO_REOPEN = (os.environ.get("JIRA_MAX_DAYS_TO_REOPEN", JIRA_MAX_DAYS_TO_REOPEN_DEFAULT)
                           or JIRA_MAX_DAYS_TO_REOPEN_DEFAULT)
JIRA_MAX_TEST_MODELING_RULE_FAILURES_TO_HANDLE_DEFAULT = 20
JIRA_MAX_TEST_MODELING_RULE_FAILURES_TO_HANDLE = (os.environ.get("JIRA_MAX_TEST_MODELING_RULE_FAILURES_TO_HANDLE",
                                                                 JIRA_MAX_TEST_MODELING_RULE_FAILURES_TO_HANDLE_DEFAULT)
                                                  or JIRA_MAX_TEST_MODELING_RULE_FAILURES_TO_HANDLE_DEFAULT)


def options_handler() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Converts Test modeling rule report to Jira issues')
    parser.add_argument("-a", "--artifacts-path", help='Artifacts path', required=True)
    parser.add_argument('--build-number', help='CI job number where the instances were created', required=True)
    parser.add_argument('-d', '--max-days-to-reopen', default=JIRA_MAX_DAYS_TO_REOPEN, type=int, required=False,
                        help='The max days to reopen a closed issue')
    parser.add_argument('-f', '--max-failures-to-handle', default=JIRA_MAX_TEST_MODELING_RULE_FAILURES_TO_HANDLE,
                        type=int, required=False, help='The max days to reopen a closed issue')
    return parser.parse_args()


def main():
    try:
        install_logging('convert_test_modeling_result_to_jira_issues.log', logger=logging)
        now = datetime.now(tz=timezone.utc)
        options = options_handler()
        artifacts_path = Path(options.artifacts_path)
        logging.info("Converting test modeling rule report to Jira issues with the following settings:")
        logging.info(f"\tArtifacts path: {artifacts_path}")
        logging.info(f"\tJira server url: {JIRA_SERVER_URL}")
        logging.info(f"\tJira verify SSL: {JIRA_VERIFY_SSL}")
        logging.info(f"\tJira project id: {JIRA_PROJECT_ID}")
        logging.info(f"\tJira issue type: {JIRA_ISSUE_TYPE}")
        logging.info(f"\tJira component: {JIRA_COMPONENT}")
        logging.info(f"\tJira labels: {', '.join(JIRA_LABELS)}")
        logging.info(f"\tJira issue unresolved transition name: {JIRA_ISSUE_UNRESOLVED_TRANSITION_NAME}")
        logging.info(f"\tMax days to reopen: {options.max_days_to_reopen}")

        jira_server = JIRA(JIRA_SERVER_URL, token_auth=JIRA_API_KEY, options={'verify': JIRA_VERIFY_SSL})
        jira_server_information(jira_server)
        if not (test_modeling_rules_results_files := get_test_results_files(artifacts_path,
                                                                            TEST_MODELING_RULES_REPORT_FILE_NAME)):
            logging.critical(f"Could not find any test modeling rules result files in {artifacts_path}")
            sys.exit(1)

        logging.info(f"Found {len(test_modeling_rules_results_files)} test modeling rules files")

        issues = jira_search_all_by_query(jira_server, generate_query_by_component_and_issue_type())

        modeling_rules_to_test_suite, jira_tickets_for_modeling_rule, server_versions = (
            calculate_test_modeling_rule_results(test_modeling_rules_results_files, issues)
        )

        logging.info(f"Found {len(jira_tickets_for_modeling_rule)} Jira tickets out "
                     f"of {len(modeling_rules_to_test_suite)} Test modeling rules")

        # Search if we have too many test modeling rules that failed beyond the max allowed limit to open, if so we print the
        # list and exit. This is to avoid opening too many Jira issues.
        failed_test_modeling_rule = get_all_failed_results(modeling_rules_to_test_suite)

        if len(failed_test_modeling_rule) >= options.max_failures_to_handle:
            column_align, tabulate_data, _, _ = calculate_results_table(jira_tickets_for_modeling_rule,
                                                                        failed_test_modeling_rule,
                                                                        server_versions,
                                                                        TEST_MODELING_RULES_BASE_HEADERS)
            table = tabulate(tabulate_data, headers="firstrow", tablefmt="pretty", colalign=column_align)
            logging.info(f"Test Modeling rule Results: {TEST_SUITE_CELL_EXPLANATION}\n{table}")
            logging.critical(f"Found {len(failed_test_modeling_rule)} failed test modeling rule, "
                             f"which is more than the max allowed limit of {options.max_failures_to_handle} to handle.")

            sys.exit(1)

        for result_file in test_modeling_rules_results_files.values():
            xml = JUnitXml.fromfile(result_file.as_posix())
            for test_suite in xml.iterchildren(TestSuite):
                if issue := create_jira_issue_for_test_modeling_rule(jira_server, test_suite, options.max_days_to_reopen, now):
                    # if the ticket was created/updated successfully, we add it to the mapping and override the previous ticket.
                    properties = get_properties_for_test_suite(test_suite)
                    if summary := get_summary_for_test_modeling_rule(properties):
                        jira_tickets_for_modeling_rule[summary] = issue

        write_test_modeling_rule_to_jira_mapping(artifacts_path, jira_tickets_for_modeling_rule)
        open(artifacts_path / TEST_MODELING_RULES_TO_JIRA_TICKETS_CONVERTED, "w")

        logging.info("Finished creating/updating Jira issues for test modeling rules")

    except Exception as e:
        logging.exception(f'Failed to create jira issues from JUnit results: {e}')
        logging.error(traceback.format_exc())
        sys.exit(1)


if __name__ == '__main__':
    main()
