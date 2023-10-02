import argparse
import copy
import os
import sys
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import tenacity
import urllib3
from jira import JIRA, Issue, JIRAError
from jira.client import ResultList
from junitparser import JUnitXml, TestSuite
from tabulate import tabulate
from tqdm import tqdm

from Tests.scripts.jira_issues import JIRA_SERVER_URL, JIRA_VERIFY_SSL, JIRA_API_KEY, \
    generate_ticket_summary, generate_query, JIRA_PROJECT_ID, JIRA_ISSUE_TYPE, JIRA_COMPONENT
from Tests.scripts.utils import logging_wrapper as logging
from Tests.scripts.utils.log_util import install_logging

urllib3.disable_warnings()  # Disable insecure warnings

TEST_SUITE_STATUSES = ["Failures", "Errors", "Skipped", "Total"]
NOT_AVAILABLE = "N/A"
TEST_SUITE_JIRA_HEADERS = ["Jira Ticket", "Jira Ticket Resolution"]
TEST_SUITE_FIXED_HEADERS = ["Playbook ID"] + TEST_SUITE_JIRA_HEADERS


def options_handler():
    parser = argparse.ArgumentParser(description='Utility for printing the test playbooks summary')
    parser.add_argument('--artifacts-path', help='Path to the artifacts directory', required=True)
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
    failed_tests_path = Path(artifacts_path) / "failed_tests.txt"
    succeeded_tests_path = Path(artifacts_path) / "succeeded_tests.txt"
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


def calculate_test_summary(test_playbooks_result_files_list: list[Path]) -> tuple[dict[str, dict[str, Any]], set[str]]:
    playbooks_results: dict[str, dict[str, Any]] = {}
    server_versions = set()
    for test_playbook_result_file in test_playbooks_result_files_list:
        xml = JUnitXml.fromfile(test_playbook_result_file.as_posix())
        for test_suite_item in xml.iterchildren(TestSuite):
            properties = {prop.name: prop.value for prop in test_suite_item.properties()}
            playbooks_result = playbooks_results.setdefault(properties["playbook_id"], {})
            server_version = properties["server_version"]
            server_versions.add(server_version)
            playbooks_result[server_version] = test_suite_item
            #
            # # FIXME!!
            # if len(playbooks_results) > 100:
            #     return playbooks_results, server_versions
    return playbooks_results, server_versions


@tenacity.retry(
    wait=tenacity.wait_exponential(multiplier=1, min=2, max=10),
    stop=tenacity.stop_after_attempt(5),
    reraise=True,
    retry=tenacity.retry_if_exception_type(JIRAError),
    before_sleep=tenacity.before_sleep_log(logging.getLogger(), logging.DEBUG)
)
def search_ticket_in_jira(jira_server: JIRA, playbook_id: str) -> Issue | None:
    jira_ticket_summary = generate_ticket_summary(playbook_id)
    jql_query = generate_query(jira_ticket_summary)
    search_issues: ResultList[Issue] = jira_server.search_issues(jql_query)  # type: ignore[assignment]
    if search_issues:
        playbook_id_lower = playbook_id.lower()
        for issue in search_issues:
            if playbook_id_lower in issue.get_field("summary").lower():
                return issue
        logging.debug(f"Failed to find a jira ticket for playbook id: {playbook_id}")
    return None


def get_jira_tickets_for_playbooks(playbook_ids: list[str],
                                   max_workers: int = 5) -> dict[str, Issue]:
    playbook_ids_to_jira_tickets: dict[str, Issue] = {}
    jira_server = JIRA(JIRA_SERVER_URL, token_auth=JIRA_API_KEY, options={'verify': JIRA_VERIFY_SSL})
    with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix='jira-search') as executor:
        futures = {
            executor.submit(search_ticket_in_jira, jira_server, playbook_id): playbook_id
            for playbook_id in playbook_ids
        }
        for future in tqdm(as_completed(futures.keys()), total=len(futures), desc='Searching for Jira tickets', unit='ticket',
                           miniters=10, mininterval=5.0, leave=True, colour='green'):
            try:
                if jira_ticket := future.result():
                    playbook_ids_to_jira_tickets[futures[future]] = jira_ticket
            except Exception:
                logging.error(f'Failed to search for a jira ticket for playbook id:"{futures[future]}"')

    return playbook_ids_to_jira_tickets


def print_test_summary(artifacts_path: str) -> bool:
    test_playbooks_report = Path(artifacts_path) / "test_playbooks_report.xml"
    xml = JUnitXml()

    # iterate over the artifacts path and find all the test playbook result files
    test_playbooks_result_files_list = get_test_playbook_results_files(artifacts_path)

    if not test_playbooks_result_files_list:
        xml.write(test_playbooks_report.as_posix(), pretty=True)
        logging.error(f"Could not find any test playbook result files in {artifacts_path}")
        return False

    logging.info(f"Found {len(test_playbooks_result_files_list)} test playbook result files")
    playbooks_results, server_versions = calculate_test_summary(test_playbooks_result_files_list)

    logging.info("Searching for Jira tickets for playbooks with the following settings:\n"
                 f'Jira server url: {JIRA_SERVER_URL}\n'
                 f'Jira verify SSL: {JIRA_VERIFY_SSL}\n'
                 f'Jira project id: {JIRA_PROJECT_ID}\n'
                 f'Jira issue type: {JIRA_ISSUE_TYPE}\n'
                 f'Jira component: {JIRA_COMPONENT}\n')

    jira_tickets_for_playbooks = get_jira_tickets_for_playbooks(list(playbooks_results.keys()))
    logging.info(f"Found {len(jira_tickets_for_playbooks)} Jira tickets out of {len(playbooks_results)} playbooks")

    headers = copy.copy(TEST_SUITE_FIXED_HEADERS)
    server_versions_list: list[str] = sorted(server_versions)
    for server_version in server_versions_list:
        for status in TEST_SUITE_STATUSES:
            headers.append(f"{status} ({server_version})")
    tabulate_data = []
    total_row: list[Any] = (["Total"] + [""] * len(TEST_SUITE_JIRA_HEADERS)
                            + [0] * (len(server_versions_list) * len(TEST_SUITE_STATUSES)))
    for playbook_id, playbook_results in tqdm(playbooks_results.items(), desc="Generating test summary", unit="playbook",
                                              leave=True, colour='green', miniters=10, mininterval=5.0):
        row = [playbook_id]
        jira_ticket = jira_tickets_for_playbooks.get(playbook_id)
        if jira_ticket:
            row.append(jira_ticket.key)
            row.append(jira_ticket.get_field("resolution") if jira_ticket.get_field("resolution") else NOT_AVAILABLE)
        else:
            row.extend([NOT_AVAILABLE] * len(TEST_SUITE_JIRA_HEADERS))

        skipped_count = 0
        for server_version in server_versions_list:
            test_suite: TestSuite = playbook_results.get(server_version)
            if test_suite:
                xml.add_testsuite(test_suite)
                row.append(test_suite.failures)
                row.append(test_suite.errors)
                row.append(test_suite.skipped)
                row.append(test_suite.tests)
                if test_suite.skipped and test_suite.failures == 0 and test_suite.errors == 0:
                    skipped_count += 1
            else:
                row.extend([NOT_AVAILABLE] * len(TEST_SUITE_STATUSES))

        # If all the test suites were skipped, don't add the row to the table.
        if skipped_count != len(server_versions_list):
            tabulate_data.append(row)

            # Offset the total row by the number of fixed headers
            for i, cell in enumerate(row[len(TEST_SUITE_FIXED_HEADERS):], start=len(TEST_SUITE_FIXED_HEADERS)):
                if cell != NOT_AVAILABLE:
                    total_row[i] += cell
        else:
            logging.debug(f"Skipping playbook {playbook_id} since all the test suites were skipped")

    logging.info(f"Writing test playbook report to {test_playbooks_report}")
    xml.write(test_playbooks_report.as_posix(), pretty=True)
    tabulate_data.append(total_row)
    table = tabulate(tabulate_data, headers, tablefmt="pretty", stralign="left")
    logging.info(f"Test Playbook Results:\n{table}")
    return True


def get_test_playbook_results_files(artifacts_path):
    test_playbooks_result_files_list: list[Path] = []
    for directory in Path(artifacts_path).iterdir():
        if directory.is_dir() and directory.name.startswith("instance_"):
            logging.info(f"Found instance directory: {directory}")
            has_test_playbooks_result_files_list = Path(artifacts_path) / directory / "has_test_playbooks_result_files_list.txt"
            if has_test_playbooks_result_files_list.exists():
                logging.info(f"Found test playbook result files list file: {has_test_playbooks_result_files_list}")
                test_playbooks_result_files_list.append(Path(artifacts_path) / directory / "test_playbooks_report.xml")
    return test_playbooks_result_files_list


def main():
    try:
        install_logging('print_test_playbook_summary.log', logger=logging)
        options = options_handler()
        logging.info(f"Printing test playbook summary - artifacts path: {options.artifacts_path}")
        if not print_test_summary(artifacts_path=options.artifacts_path):
            old_print_test_summary(artifacts_path=options.artifacts_path)
        logging.info("Finished printing test summary")
    except Exception as e:
        logging.error(f'Failed to get the test playbook summary: {e}')
        logging.error(traceback.format_exc())
        sys.exit(1)


if __name__ == '__main__':
    main()
