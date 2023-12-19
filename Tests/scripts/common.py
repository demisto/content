from pathlib import Path
from typing import Any

import pandas as pd
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
UNIT_TESTS_WORKFLOW_SUBSTRINGS = {'lint', 'unit', 'demisto sdk nightly', TEST_NATIVE_CANDIDATE.lower()}

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
TEST_SUITE_JIRA_HEADERS: list[str] = ["Jira\nTicket", "Jira\nTicket\nResolution"]
TEST_SUITE_DATA_CELL_HEADER = "S/F/E/T"
TEST_SUITE_CELL_EXPLANATION = "(Table headers: Skipped/Failures/Errors/Total)"
NO_COLOR_ESCAPE_CHAR = "\033[0m"
RED_COLOR = "\033[91m"
GREEN_COLOR = "\033[92m"
TEST_PLAYBOOKS_REPORT_FILE_NAME = "test_playbooks_report.xml"
TEST_MODELING_RULES_REPORT_FILE_NAME = "test_modeling_rules_report.xml"
E2E_RESULT_FILE_NAME = "e2e_tests_result.xml"

FAILED_TO_COLOR_ANSI = {
    True: RED_COLOR,
    False: GREEN_COLOR,
}
FAILED_TO_COLOR_NAME = {
    True: "red",
    False: "green",
}
FAILED_TO_MSG = {
    True: "failed",
    False: "succeeded",
}


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


def failed_to_ansi_text(text: str, failed: bool) -> str:
    return f"{FAILED_TO_COLOR_ANSI[failed]}{text}{NO_COLOR_ESCAPE_CHAR}"


class TestSuiteStatistics:

    def __init__(self, no_color, failures: int = 0, errors: int = 0, skipped: int = 0, tests: int = 0):
        self.no_color = no_color
        self.failures = failures
        self.errors = errors
        self.skipped = skipped
        self.tests = tests

    def __add__(self, other):
        return TestSuiteStatistics(self.no_color, self.failures + other.failures, self.errors + other.errors,
                                   self.skipped + other.skipped, self.tests + other.tests)

    def show_with_color(self, res: int, show_as_error: bool | None = None) -> str:
        res_str = str(res)
        if self.no_color or show_as_error is None:
            return res_str
        return failed_to_ansi_text(res_str, show_as_error)

    def __str__(self):
        return (f"{self.show_with_color(self.skipped)}/"  # no color for skipped.
                f"{self.show_with_color(self.failures, self.failures > 0)}/"
                f"{self.show_with_color(self.errors, self.errors > 0)}/"
                f"{self.show_with_color(self.tests, self.errors + self.failures > 0)}")


def calculate_results_table(jira_tickets_for_result: dict[str, Issue],
                            results: dict[str, dict[str, Any]],
                            server_versions: set[str],
                            base_headers: list[str],
                            add_total_row: bool = True,
                            no_color: bool = False,
                            without_jira: bool = False,
                            with_skipped: bool = False,
                            multiline_headers: bool = True,
                            transpose: bool = False) -> tuple[list[str], list[list[Any]], JUnitXml, int]:
    xml = JUnitXml()
    headers_multiline_char = "\n" if multiline_headers else " "
    headers = [h.replace("\n", headers_multiline_char) for h in base_headers]
    if not without_jira:
        headers.extend([h.replace("\n", headers_multiline_char) for h in TEST_SUITE_JIRA_HEADERS])
    column_align = ["left"] * len(headers)
    fixed_headers_length = len(headers)
    server_versions_list: list[str] = sorted(server_versions)
    for server_version in server_versions_list:
        server_version_header = server_version.replace(' ', headers_multiline_char)
        headers.append(
            server_version_header
            if transpose else f"{server_version_header}{headers_multiline_char}{TEST_SUITE_DATA_CELL_HEADER}"
        )
        column_align.append("center")
    tabulate_data = [headers]
    total_row: list[Any] = ([""] * fixed_headers_length + [TestSuiteStatistics(no_color)
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
                        no_color,
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
            row_result = f"{result}{headers_multiline_char}({TEST_SUITE_DATA_CELL_HEADER})" if transpose else result
            if no_color:
                row_result_color = row_result
            else:
                row_result_color = failed_to_ansi_text(row_result, errors_count > 0)
            row.insert(0, row_result_color)
            tabulate_data.append(row)

            # Offset the total row by the number of fixed headers
            for i, cell in enumerate(row[fixed_headers_length:], start=fixed_headers_length):
                if isinstance(cell, TestSuiteStatistics):
                    total_row[i] += cell
        else:
            logging.debug(f"Skipping {result} since all the test suites were skipped")
    if add_total_row:
        total_row[0] = TOTAL_HEADER if no_color else failed_to_ansi_text(TOTAL_HEADER, total_errors > 0)
        tabulate_data.append(total_row)

    if transpose:
        tabulate_data = pd.DataFrame(tabulate_data, index=None).transpose().to_numpy()

    return column_align, tabulate_data, xml, total_errors


def get_all_failed_results(results: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    failed_results = {}
    for result, result_test_suites in results.items():
        for test_suite in result_test_suites.values():
            if test_suite.errors or test_suite.failures:
                failed_results[result] = result_test_suites
                break

    return failed_results


def replace_escape_characters(sentence: str, replace_with: str = " ") -> str:
    escape_chars = ["\n", "\r", "\b", "\f", "\t"]
    for escape_char in escape_chars:
        sentence = sentence.replace(escape_char, replace_with)
    return sentence
