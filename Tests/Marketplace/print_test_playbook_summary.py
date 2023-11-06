import argparse
import sys
import traceback
from pathlib import Path

import urllib3
from jira import JIRA
from junitparser import JUnitXml, TestSuite
from tabulate import tabulate

from Tests.scripts.common import calculate_results_table, TEST_PLAYBOOKS_REPORT_FILE_NAME, get_test_results_files, \
    TEST_SUITE_CELL_EXPLANATION
from Tests.scripts.jira_issues import JIRA_SERVER_URL, JIRA_VERIFY_SSL, JIRA_PROJECT_ID, JIRA_ISSUE_TYPE, JIRA_COMPONENT, \
    JIRA_API_KEY, jira_server_information, generate_query_by_component_and_issue_type, jira_search_all_by_query, JIRA_LABELS
from Tests.scripts.test_playbooks_report import calculate_test_playbooks_results, \
    TEST_PLAYBOOKS_BASE_HEADERS, get_jira_tickets_for_playbooks
from Tests.scripts.utils import logging_wrapper as logging
from Tests.scripts.utils.log_util import install_logging

urllib3.disable_warnings()  # Disable insecure warnings


def options_handler() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Utility for printing the test playbooks summary')
    parser.add_argument('--artifacts-path', help='Path to the artifacts directory', required=True)
    parser.add_argument('--without-jira', help='Print the summary without Jira tickets', action='store_true')
    return parser.parse_args()


def read_file_contents(file_path: Path) -> list | None:
    """
        Returns the file contents as a list of lines if the file exists, else returns None.
    """
    if file_path.exists():
        with open(file_path) as file:
            return file.read().splitlines()
    else:
        logging.error(f"{file_path} does not exist.")
    return None


def print_test_playbooks_summary_without_junit_report(artifacts_path: Path) -> bool:
    """
    Takes the information stored in the files and prints it in a human-readable way.
    """
    instance_path = Path(artifacts_path) / "instance_Server Master"
    failed_tests_path = instance_path / "failed_tests.txt"
    succeeded_tests_path = instance_path / "succeeded_tests.txt"
    succeeded_playbooks = read_file_contents(succeeded_tests_path)
    failed_playbooks = read_file_contents(failed_tests_path)

    # if one of the files isn't existing, we want to fail.
    if succeeded_playbooks is None or failed_playbooks is None:
        return True

    succeeded_count = len(succeeded_playbooks)
    failed_count = len(failed_playbooks)

    logging.info("TEST RESULTS:")
    logging.info(f"Number of playbooks tested - {succeeded_count + failed_count}")

    if succeeded_count:
        logging.success(f"Number of succeeded tests - {succeeded_count}")
        logging.success("Successful Tests:")
        for playbook_id in succeeded_playbooks:
            logging.success(f"\t- {playbook_id}")

    if failed_count:
        logging.error(f"Number of failed tests - {failed_count}:")
        logging.error("Failed Tests:")
        for playbook_id in failed_playbooks:
            logging.error(f"\t- {playbook_id}")
        return True
    return False


def filter_skipped_playbooks(playbooks_results: dict[str, dict[str, TestSuite]]) -> list[str]:
    filtered_playbooks_ids = []
    for playbook_id, playbook_results in playbooks_results.items():
        skipped_count = sum(bool(test_suite.skipped
                                 and test_suite.failures == 0
                                 and test_suite.errors == 0)
                            for test_suite in playbook_results.values())
        # If all the test suites were skipped, don't add the row to the table.
        if skipped_count != len(playbook_results):
            filtered_playbooks_ids.append(playbook_id)
        else:
            logging.debug(f"Skipping playbook {playbook_id} because it was skipped in the test")

    return filtered_playbooks_ids


def print_test_playbooks_summary(artifacts_path: Path, without_jira: bool) -> tuple[bool, bool]:
    test_playbooks_report = artifacts_path / TEST_PLAYBOOKS_REPORT_FILE_NAME

    # iterate over the artifacts path and find all the test playbook result files
    if not (test_playbooks_result_files_list := get_test_results_files(artifacts_path, TEST_PLAYBOOKS_REPORT_FILE_NAME)):
        # Write an empty report file to avoid failing the build artifacts collection.
        JUnitXml().write(test_playbooks_report.as_posix(), pretty=True)
        logging.error(f"Could not find any test playbook result files in {artifacts_path}")
        return False, False

    logging.info(f"Found {len(test_playbooks_result_files_list)} test playbook result files")
    playbooks_results, server_versions = calculate_test_playbooks_results(test_playbooks_result_files_list)

    playbooks_ids = filter_skipped_playbooks(playbooks_results)
    logging.info(f"Found {len(playbooks_ids)} playbooks out of {len(playbooks_results)} after filtering skipped playbooks")

    if without_jira:
        logging.info("Printing test playbook summary without Jira tickets")
        jira_tickets_for_playbooks = {}
    else:
        logging.info("Searching for Jira tickets for playbooks with the following settings:")
        logging.info(f"\tJira server url: {JIRA_SERVER_URL}")
        logging.info(f"\tJira verify SSL: {JIRA_VERIFY_SSL}")
        logging.info(f"\tJira project id: {JIRA_PROJECT_ID}")
        logging.info(f"\tJira issue type: {JIRA_ISSUE_TYPE}")
        logging.info(f"\tJira component: {JIRA_COMPONENT}")
        logging.info(f"\tJira labels: {', '.join(JIRA_LABELS)}")
        jira_server = JIRA(JIRA_SERVER_URL, token_auth=JIRA_API_KEY, options={'verify': JIRA_VERIFY_SSL})
        jira_server_information(jira_server)

        issues = jira_search_all_by_query(jira_server, generate_query_by_component_and_issue_type())
        jira_tickets_for_playbooks = get_jira_tickets_for_playbooks(playbooks_ids, issues)
        logging.info(f"Found {len(jira_tickets_for_playbooks)} Jira tickets out of {len(playbooks_ids)} filtered playbooks")

    headers, column_align, tabulate_data, xml, total_errors = calculate_results_table(jira_tickets_for_playbooks,
                                                                                      playbooks_results,
                                                                                      server_versions,
                                                                                      TEST_PLAYBOOKS_BASE_HEADERS,
                                                                                      without_jira=without_jira)
    logging.info(f"Writing test playbook report to {test_playbooks_report}")
    xml.write(test_playbooks_report.as_posix(), pretty=True)
    table = tabulate(tabulate_data, headers, tablefmt="pretty", colalign=column_align)
    logging.info(f"Test Playbook Results: {TEST_SUITE_CELL_EXPLANATION}\n{table}")
    return True, total_errors != 0


def main():
    try:
        install_logging('print_test_playbook_summary.log', logger=logging)
        options = options_handler()
        artifacts_path = Path(options.artifacts_path)
        logging.info(f"Printing test playbook summary - artifacts path: {artifacts_path}")
        junit_result_exist, errors_found = print_test_playbooks_summary(artifacts_path, options.without_jira)
        if not junit_result_exist:
            errors_found = print_test_playbooks_summary_without_junit_report(artifacts_path)
        if errors_found:
            logging.critical("Test playbook summary found errors")
            sys.exit(1)

        logging.info("Test playbook summary finished successfully")
    except Exception as e:
        logging.error(f'Failed to get the test playbook summary: {e}')
        logging.error(traceback.format_exc())
        sys.exit(1)


if __name__ == '__main__':
    main()
