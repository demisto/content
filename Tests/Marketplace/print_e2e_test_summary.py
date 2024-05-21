import argparse
import sys
import traceback
from pathlib import Path

import urllib3
from junitparser import JUnitXml, TestSuite
from tabulate import tabulate

from Tests.scripts.common import calculate_results_table, E2E_RESULT_FILE_NAME, get_test_results_files, \
    TEST_SUITE_CELL_EXPLANATION
from Tests.scripts.utils import logging_wrapper as logging
from Tests.scripts.utils.log_util import install_logging

from typing import Any


urllib3.disable_warnings()  # Disable insecure warnings


E2E_BASE_HEADERS = ["Test File Name"]


def calculate_e2e_tests_results(e2e_tests_results_files: dict[str, Path]):

    e2e_tests_results: dict[str, dict[str, Any]] = {}
    server_versions = set()
    for instance_role, e2e_test_result_file in e2e_tests_results_files.items():
        logging.debug(f"Processing test e2e result file: {e2e_test_result_file} for instance role: {instance_role}")
        xml = JUnitXml.fromfile(e2e_test_result_file.as_posix())
        server_versions.add(instance_role)
        for test_suite_item in xml.iterchildren(TestSuite):
            test_names = [case.classname for case in test_suite_item]
            for test_name in test_names:
                e2e_tests_results[test_name] = {instance_role: test_suite_item}

    return e2e_tests_results, server_versions


def print_test_e2e_test_summary(artifacts_path: Path) -> bool:
    e2e_tests_report = artifacts_path / E2E_RESULT_FILE_NAME

    # iterate over the artifacts path and find all the test playbook result files
    if not (e2e_tests_result_files_list := get_test_results_files(artifacts_path, E2E_RESULT_FILE_NAME)):
        # Write an empty report file to avoid failing the build artifacts collection.
        JUnitXml().write(e2e_tests_report.as_posix(), pretty=True)
        logging.error(f"Could not find any e2e test result files in {artifacts_path}")
        return True

    logging.info(f"Found {len(e2e_tests_result_files_list)} e2e test result files")
    e2e_tests_results, server_versions = calculate_e2e_tests_results(e2e_tests_result_files_list)

    column_align, tabulate_data, xml, total_errors = calculate_results_table(
        {},
        e2e_tests_results,
        server_versions,
        E2E_BASE_HEADERS,
        without_jira=True
    )

    logging.info(f"Writing e2e tests report to {e2e_tests_report}")
    xml.write(e2e_tests_report.as_posix(), pretty=True)

    table = tabulate(tabulate_data, headers="firstrow", tablefmt="pretty", colalign=column_align)
    logging.info(f"End-To-End-Test Results: {TEST_SUITE_CELL_EXPLANATION}\n{table}")
    return total_errors != 0


def options_handler() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Utility for printing e2e tests summary')
    parser.add_argument('--artifacts-path', help='Path to the artifacts directory', required=True)
    return parser.parse_args()


def main():
    try:
        install_logging('print_e2e_test_summary.log', logger=logging)
        options = options_handler()
        artifacts_path = Path(options.artifacts_path)
        logging.info(f"Printing end to end test summary - artifacts path: {artifacts_path}")

        if print_test_e2e_test_summary(artifacts_path):
            logging.critical("end to end test summary found errors")
            sys.exit(1)

        logging.info("end to end test summary finished successfully")
    except Exception as e:
        logging.error(f'Failed to get the end to end test summary: {e}')
        logging.error(traceback.format_exc())
        sys.exit(1)


if __name__ == '__main__':
    main()
