import argparse
import os
import sys
import traceback
from pathlib import Path

import urllib3
from jira import JIRA
from junitparser import JUnitXml
from tabulate import tabulate

from Tests.scripts.jira_issues import JIRA_SERVER_URL, JIRA_VERIFY_SSL, JIRA_PROJECT_ID, JIRA_ISSUE_TYPE, JIRA_COMPONENT, \
    JIRA_API_KEY, jira_server_information
from Tests.scripts.test_playbooks import calculate_test_playbooks_results, get_jira_tickets_for_playbooks, \
    calculate_test_playbooks_results_table, get_test_playbook_results_files
from Tests.scripts.utils import logging_wrapper as logging
from Tests.scripts.utils.log_util import install_logging

urllib3.disable_warnings()  # Disable insecure warnings


def options_handler():
    parser = argparse.ArgumentParser(description='Utility for printing the test playbooks summary')
    parser.add_argument('--artifacts-path', help='Path to the artifacts directory', required=True)
    parser.add_argument('--without-jira', help='Print the summary without Jira tickets', action='store_true')
    return parser.parse_args()


def read_file_contents(file_path: str) -> list | None:
    """
        Returns the file contents as a list of lines if the file exists, else returns None.
    """
    if os.path.isfile(file_path):
        with open(file_path) as file:
            return file.read().splitlines()
    else:
        logging.error(f"{file_path} does not exist.")
    return None


def old_print_test_summary(artifacts_path: str) -> None:
    """
    Takes the information stored in the files and prints it in a human-readable way.
    """
    instance_path = Path(artifacts_path) / "instance_Server Master"
    failed_tests_path = instance_path / "failed_tests.txt"
    succeeded_tests_path = instance_path / "succeeded_tests.txt"
    succeeded_playbooks = read_file_contents(succeeded_tests_path.as_posix())
    failed_playbooks = read_file_contents(failed_tests_path.as_posix())

    # if one of the files isn't existing, we want to fail.
    if succeeded_playbooks is None or failed_playbooks is None:
        sys.exit(1)

    succeeded_count = len(succeeded_playbooks)
    failed_count = len(failed_playbooks)

    logging.info("TEST RESULTS:")
    logging.info(f"Number of playbooks tested - { succeeded_count + failed_count}")

    if succeeded_count:
        logging.success(f"Number of succeeded tests - { succeeded_count}")
        logging.success("Successful Tests:")
        for playbook_id in succeeded_playbooks:
            logging.success(f"\t- {playbook_id}")

    if failed_count:
        logging.error(f"Number of failed tests - {failed_count}:")
        logging.error("Failed Tests:")
        for playbook_id in failed_playbooks:
            logging.error(f"\t- {playbook_id}")
        sys.exit(1)


def filter_skipped_playbooks(playbooks_results):
    filtered_playbooks_ids = []
    for playbook_id, playbook_results in playbooks_results.items():
        skipped_count = 0
        for test_suite in playbook_results.values():
            if test_suite.skipped and test_suite.failures == 0 and test_suite.errors == 0:
                skipped_count += 1

        # If all the test suites were skipped, don't add the row to the table.
        if skipped_count != len(playbook_results):
            filtered_playbooks_ids.append(playbook_id)
    return filtered_playbooks_ids


def print_test_summary(artifacts_path: str, without_jira: bool) -> bool:
    test_playbooks_report = Path(artifacts_path) / "test_playbooks_report.xml"

    # iterate over the artifacts path and find all the test playbook result files
    test_playbooks_result_files_list = get_test_playbook_results_files(artifacts_path)

    if not test_playbooks_result_files_list:
        # Write an empty report file to avoid failing the build artifacts collection.
        JUnitXml().write(test_playbooks_report.as_posix(), pretty=True)
        logging.error(f"Could not find any test playbook result files in {artifacts_path}")
        return False

    logging.info(f"Found {len(test_playbooks_result_files_list)} test playbook result files")
    playbooks_results, server_versions = calculate_test_playbooks_results(test_playbooks_result_files_list)

    if without_jira:
        logging.info("Printing test playbook summary without Jira tickets")
        jira_tickets_for_playbooks = {}
    else:
        logging.info("Searching for Jira tickets for playbooks with the following settings:\n"
                     f'Jira server url: {JIRA_SERVER_URL}\n'
                     f'Jira verify SSL: {JIRA_VERIFY_SSL}\n'
                     f'Jira project id: {JIRA_PROJECT_ID}\n'
                     f'Jira issue type: {JIRA_ISSUE_TYPE}\n'
                     f'Jira component: {JIRA_COMPONENT}\n')
        jira_server = JIRA(JIRA_SERVER_URL, token_auth=JIRA_API_KEY, options={'verify': JIRA_VERIFY_SSL})
        jira_server_information(jira_server)

        playbooks_ids = filter_skipped_playbooks(playbooks_results)
        logging.info(f"Found {len(playbooks_ids)} playbooks out of {len(playbooks_results)} after filtering skipped playbooks")
        jira_tickets_for_playbooks = get_jira_tickets_for_playbooks(jira_server, playbooks_ids)
        logging.info(f"Found {len(jira_tickets_for_playbooks)} Jira tickets out of {len(playbooks_ids)} playbooks")

    headers, tabulate_data, xml, total_errors = calculate_test_playbooks_results_table(jira_tickets_for_playbooks,
                                                                                       playbooks_results,
                                                                                       server_versions,
                                                                                       without_jira=without_jira)
    xml.write(test_playbooks_report.as_posix(), pretty=True)
    table = tabulate(tabulate_data, headers, tablefmt="pretty", stralign="left", numalign="center")
    logging.info(f"Test Playbook Results:\n{table}")
    logging.info(f"Writing test playbook report to {test_playbooks_report}")
    return True


def main():
    try:
        install_logging('print_test_playbook_summary.log', logger=logging)
        options = options_handler()
        logging.info(f"Printing test playbook summary - artifacts path: {options.artifacts_path}")
        if not print_test_summary(artifacts_path=options.artifacts_path, without_jira=options.without_jira):
            old_print_test_summary(artifacts_path=options.artifacts_path)
        logging.info("Finished printing test summary")
    except Exception as e:
        logging.error(f'Failed to get the test playbook summary: {e}')
        logging.error(traceback.format_exc())
        sys.exit(1)


if __name__ == '__main__':
    main()
