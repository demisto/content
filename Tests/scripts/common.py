import copy
from pathlib import Path
from typing import Any

from jira import Issue
from junitparser import TestSuite, JUnitXml

from Tests.scripts.utils import logging_wrapper as logging

CONTENT_NIGHTLY = 'Content Nightly'
CONTENT_PR = 'Content PR'
CONTENT_MERGE = 'Content Merge'
BUCKET_UPLOAD = 'Upload Packs to Marketplace Storage'
SDK_NIGHTLY = 'Demisto SDK Nightly'
PRIVATE_NIGHTLY = 'Private Nightly'
TEST_NATIVE_CANDIDATE = 'Test Native Candidate'
SECURITY_SCANS = 'Security Scans'
BUILD_MACHINES_CLEANUP = 'Build Machines Cleanup'
WORKFLOW_TYPES = {
    CONTENT_NIGHTLY,
    CONTENT_PR,
    CONTENT_MERGE,
    SDK_NIGHTLY,
    BUCKET_UPLOAD,
    PRIVATE_NIGHTLY,
    TEST_NATIVE_CANDIDATE,
    SECURITY_SCANS,
    BUILD_MACHINES_CLEANUP
}
BUCKET_UPLOAD_BRANCH_SUFFIX = '-upload_test_branch'
TOTAL_HEADER = "Total"
NOT_AVAILABLE = "N/A"
TEST_SUITE_JIRA_HEADERS = ["Jira Ticket", "Jira Ticket Resolution"]
TEST_SUITE_DATA_CELL_HEADER = "S/F/E/T"
NO_COLOR_ESCAPE_CHAR = "\033[0m"
RED_COLOR = "\033[91m"
GREEN_COLOR = "\033[92m"
TEST_PLAYBOOKS_REPORT_FILE_NAME = "test_playbooks_report.xml"
TEST_MODELING_RULES_REPORT_FILE_NAME = "test_modeling_rules_report.xml"


def get_instance_directories(artifacts_path: Path) -> dict[str, Path]:
    instance_directories: dict[str, Path] = {}
    for directory in artifacts_path.iterdir():
        if directory.is_dir() and directory.name.startswith("instance_") and \
                (instance_role_txt := directory / "instance_role.txt").exists():
            instance_role: str = instance_role_txt.read_text().replace("\n", "")
            instance_directories[instance_role] = directory
    return instance_directories


def get_test_results_files(artifacts_path: Path, file_name: str) -> dict[str, Path]:
    results_files: dict[str, Path] = {}
    for instance_role, directory in get_instance_directories(artifacts_path).items():
        if (file_path := Path(artifacts_path) / directory / file_name).exists():
            logging.info(f"Found result file: {file_path} for instance role: {instance_role}")
            results_files[instance_role] = file_path
    return results_files


def get_properties_for_test_suite(test_suite: TestSuite) -> dict[str, str]:
    return {prop.name: prop.value for prop in test_suite.properties()}


def green_text(text: str) -> str:
    return f"{GREEN_COLOR}{text}{NO_COLOR_ESCAPE_CHAR}"


def red_text(text: str) -> str:
    return f"{RED_COLOR}{text}{NO_COLOR_ESCAPE_CHAR}"


class TestSuiteStatistics:

    def __init__(self, failures: int = 0, errors: int = 0, skipped: int = 0, tests: int = 0):
        self.failures = failures
        self.errors = errors
        self.skipped = skipped
        self.tests = tests

    def __add__(self, other):
        return TestSuiteStatistics(self.failures + other.failures, self.errors + other.errors, self.skipped + other.skipped,
                                   self.tests + other.tests)

    def __str__(self):
        return f"{self.skipped}/{self.failures}/{self.errors}/{self.tests}"


def calculate_results_table(jira_tickets_for_result: dict[str, Issue],
                            results: dict[str, dict[str, Any]],
                            server_versions: set[str],
                            base_headers: list[str],
                            add_total_row: bool = True,
                            no_color: bool = False,
                            without_jira: bool = False,
                            with_skipped: bool = False,
                            transpose: bool = False) -> tuple[list[str], list[list[Any]], JUnitXml, int]:
    xml = JUnitXml()
    headers = copy.copy(base_headers)
    if not without_jira:
        headers.extend(TEST_SUITE_JIRA_HEADERS)
    fixed_headers_length = len(headers)
    server_versions_list: list[str] = sorted(server_versions)
    headers.extend(
        server_version if transpose else f"{server_version} ({TEST_SUITE_DATA_CELL_HEADER})"
        for server_version in server_versions_list
    )
    tabulate_data = []
    total_row: list[Any] = ([NOT_AVAILABLE] * fixed_headers_length + [TestSuiteStatistics()
                                                                      for _ in range(len(server_versions_list))])
    total_errors = 0
    for result, result_test_suites in results.items():
        row: list[Any] = []
        if not without_jira:
            if jira_ticket := jira_tickets_for_result.get(result):
                row.extend(
                    (
                        jira_ticket.key,
                        jira_ticket.get_field("resolution")
                        if jira_ticket.get_field("resolution")
                        else NOT_AVAILABLE,
                    )
                )
            else:
                row.extend([NOT_AVAILABLE] * len(TEST_SUITE_JIRA_HEADERS))

        skipped_count = 0
        errors_count = 0
        for server_version in server_versions_list:
            test_suite: TestSuite = result_test_suites.get(server_version)
            if test_suite:
                xml.add_testsuite(test_suite)
                row.append(
                    TestSuiteStatistics(
                        test_suite.failures,
                        test_suite.errors,
                        test_suite.skipped,
                        test_suite.tests,
                    )
                )
                errors_count += test_suite.errors + test_suite.failures
                if test_suite.skipped and test_suite.failures == 0 and test_suite.errors == 0:
                    skipped_count += 1
            else:
                row.append(NOT_AVAILABLE)

        total_errors += errors_count
        # If all the test suites were skipped, don't add the row to the table.
        if skipped_count != len(server_versions_list) or with_skipped:
            row_result = f"{result} ({TEST_SUITE_DATA_CELL_HEADER})" if transpose else result
            row.insert(0,
                       (red_text(row_result) if errors_count else green_text(row_result) if not no_color else row_result))
            tabulate_data.append(row)

            # Offset the total row by the number of fixed headers
            for i, cell in enumerate(row[fixed_headers_length:], start=fixed_headers_length):
                if isinstance(cell, TestSuiteStatistics):
                    total_row[i] += cell
        else:
            logging.debug(f"Skipping {result} since all the test suites were skipped")
    if add_total_row:
        total_row[0] = (green_text(TOTAL_HEADER) if total_errors == 0 else red_text(TOTAL_HEADER)) \
            if not no_color else TOTAL_HEADER
        tabulate_data.append(total_row)
    return headers, tabulate_data, xml, total_errors


def get_all_failed_results(results: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    failed_results = {}
    for result, result_test_suites in results.items():
        for test_suite in result_test_suites.values():
            if test_suite.errors or test_suite.failures:
                failed_results[result] = results
                break

    return failed_results
