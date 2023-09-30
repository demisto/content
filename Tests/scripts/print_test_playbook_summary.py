import argparse
import traceback
import sys
import os
from pathlib import Path
from typing import Any, Tuple

from junitparser import JUnitXml, TestSuite
from tabulate import tabulate

from Tests.scripts.utils.log_util import install_logging
from Tests.scripts.utils import logging_wrapper as logging

TEST_SUITE_STATUSES = ["Failed", "Skipped", "Passed", "Total"]
NOT_AVAILABLE = "N/A"


def options_handler():
    parser = argparse.ArgumentParser(description='Utility for printing the test playbooks summary')
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


def calculate_test_summary(test_playbooks_result_files_list: list[Path]) -> Tuple[dict[str, dict[str, Any]], set[str]]:
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
    return playbooks_results, server_versions


def print_test_summary(artifacts_path: str, server_type: str) -> bool:
    test_playbooks_result_files_list_file_name = Path(artifacts_path) / f"{server_type}_test_playbooks_result_files_list.txt"
    test_playbooks_report = Path(artifacts_path) / "test_playbooks_report.xml"
    xml = JUnitXml()

    # iterate over the artifacts path and find all the test playbook result files
    test_playbooks_result_files_list: list[Path] = []
    for directory in Path(artifacts_path).iterdir():
        if directory.is_dir() and directory.name.startswith("instance_"):
            logging.info(f"Found instance directory: {directory}")
            has_test_playbooks_result_files_list = Path(artifacts_path) / directory / "has_test_playbooks_result_files_list.txt"
            if has_test_playbooks_result_files_list.exists():
                logging.info(f"Found test playbook result files list file: {has_test_playbooks_result_files_list}")
                test_playbooks_result_files_list.append(Path(artifacts_path) / directory / "test_playbooks_report.xml")

    if not test_playbooks_result_files_list:
        xml.write(test_playbooks_report.as_posix(), pretty=True)
        logging.error(f"Could not find any test playbook result files in {artifacts_path}")
        return False

    playbooks_results, server_versions = calculate_test_summary(test_playbooks_result_files_list)

    xml.write(test_playbooks_report.as_posix(), pretty=True)
    server_versions_list: list[str] = sorted(server_versions)
    headers = ["Playbook ID"]
    for server_version in server_versions_list:
        for status in TEST_SUITE_STATUSES:
            headers.append(f"{status} ({server_version})")
    tabulate_data = []
    total_row: list[Any] = ["Total"] + [0] * (len(server_versions_list) * len(TEST_SUITE_STATUSES))
    for playbook_id, playbook_results in sorted(playbooks_results.items()):
        row = [playbook_id]
        for i, server_version in enumerate(server_versions_list):
            test_suite: TestSuite = playbook_results.get(server_version)
            if test_suite:
                row.append(test_suite.failures)
                row.append(test_suite.skipped)
                row.append(test_suite.tests - test_suite.failures - test_suite.skipped)
                row.append(test_suite.tests)
            else:
                row.extend([NOT_AVAILABLE] * len(TEST_SUITE_STATUSES))
        tabulate_data.append(row)

        for i, cell in enumerate(row[1:], start=1):
            if cell != NOT_AVAILABLE:
                total_row[i] += cell

    tabulate_data.extend(total_row)
    table = tabulate(tabulate_data, headers, tablefmt="fancy_grid")
    logging.info(f"Test Playbook Results:\n{table}")
    return True


def main():
    try:
        install_logging('print_test_playbook_summary.log', logger=logging)
        options = options_handler()
        logging.info(f"Printing test summary for {options.server_type} server type, artifacts path: {options.artifacts_path}")
        if not print_test_summary(artifacts_path=options.artifacts_path, server_type=options.server_type):
            old_print_test_summary(artifacts_path=options.artifacts_path)
        logging.info("Finished printing test summary")
    except Exception as e:
        logging.error(f'Failed to get the summary: {e}')
        logging.error(traceback.format_exc())
        sys.exit(1)


if __name__ == '__main__':
    main()
