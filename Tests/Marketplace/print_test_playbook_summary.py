import argparse
import traceback
import sys
import os
from pathlib import Path
from typing import Any, Dict

from junitparser import JUnitXml, TestSuite
from tabulate import tabulate

from Tests.scripts.utils.log_util import install_logging
from Tests.scripts.utils import logging_wrapper as logging


def options_handler():
    parser = argparse.ArgumentParser(description='Utility for printing the tests summary')
    parser.add_argument('--artifacts-path', help='Path to the artifacts directory', required=True)
    parser.add_argument('--server-type', help='The server type', required=True)
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


def print_test_summary(failed_tests_path: str, succeeded_tests_path: str) -> None:
    """
    Takes the information stored in the files and prints it in a human-readable way.
    """
    succeeded_playbooks = read_file_contents(succeeded_tests_path)
    failed_playbooks = read_file_contents(failed_tests_path)

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


def new_print_test_summary(artifacts_path: str, server_type: str) -> bool:
    test_playbooks_result_files_list = Path(artifacts_path) / f"{server_type}_test_playbooks_result_files_list.txt"
    playbooks_results: Dict[str, Dict[str, Any]] = {}
    server_versions = set()
    if not test_playbooks_result_files_list.exists():
        return False

    with open(test_playbooks_result_files_list) as f:
        test_playbooks_result_files_list = f.read().splitlines()
        for test_playbook_result_file in test_playbooks_result_files_list:
            if not Path(test_playbook_result_file).exists():
                logging.error(f"{test_playbook_result_file} does not exist.")
                return False
            xml = JUnitXml.fromfile(test_playbook_result_file)
            for test_suite in xml.iterchildren(TestSuite):
                properties = {prop.name: prop.value for prop in test_suite.properties()}

            playbooks_result = playbooks_results.setdefault(properties["playbook_id"], {})
            server_numeric_version = properties["server_numeric_version"]
            server_versions.add(server_numeric_version)
            playbooks_result[server_numeric_version] = test_suite

    statuses = ["Failed", "Skipped", "Passed", "Total"]
    tabulate_data = []
    headers = ["Playbook ID"]
    for server_numeric_version in sorted(server_versions):
        for status in statuses:
            headers.append(f"{status} ({server_numeric_version})")
    for playbook_id, playbook_results in sorted(playbooks_results.items()):
        row = [playbook_id]
        for server_numeric_version in sorted(server_versions):
            test_suite: TestSuite = playbook_results.get(server_numeric_version)
            if test_suite:
                row.append(test_suite.failures)
                row.append(test_suite.skipped)
                row.append(test_suite.tests - test_suite.failures - test_suite.skipped)
                row.append(test_suite.tests)
            else:
                row.extend(["N/A"] * len(statuses))
        tabulate_data.append(row)
    table = tabulate(tabulate_data, headers, tablefmt="fancy_grid")
    logging.info(f"TEST RESULTS:\n{table}")
    return True


def main():
    try:
        install_logging('print_test_playbook_summary.log', logger=logging)
        options = options_handler()
        if not new_print_test_summary(artifacts_path=options.artifacts_path, server_type=options.server_type):
            print_test_summary(failed_tests_path=options.failed_tests_path,
                               succeeded_tests_path=options.succeeded_tests_path)
    except Exception as e:
        logging.error(f'Failed to get the summary: {e}')
        logging.error(traceback.format_exc())
        sys.exit(1)


if __name__ == '__main__':
    main()
