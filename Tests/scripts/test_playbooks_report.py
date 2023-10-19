import copy
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import tenacity
from jira import JIRAError, JIRA, Issue
from jira.client import ResultList

from junitparser import JUnitXml, TestSuite
from tqdm import tqdm

from Tests.scripts.jira_issues import generate_ticket_summary, generate_query
from Tests.scripts.utils import logging_wrapper as logging

TOTAL_HEADER = "Total"
NOT_AVAILABLE = "N/A"
TEST_SUITE_JIRA_HEADERS = ["Jira Ticket", "Jira Ticket Resolution"]
TEST_SUITE_BASE_HEADERS = ["Playbook ID"]
TEST_SUITE_FIXED_HEADERS = TEST_SUITE_BASE_HEADERS + TEST_SUITE_JIRA_HEADERS
TEST_SUITE_DATA_CELL_HEADER = "S/F/E/T"
NO_COLOR_ESCAPE_CHAR = "\033[0m"
RED_COLOR = "\033[91m"
GREEN_COLOR = "\033[92m"


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


def calculate_test_playbooks_results(test_playbooks_result_files_list: list[Path]) -> tuple[dict[str, dict[str, Any]], set[str]]:
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
        logging.info(f"Failed to find a jira ticket for playbook id: {playbook_id}")
    return None


def get_jira_tickets_for_playbooks(jira_server: JIRA,
                                   playbook_ids: list[str],
                                   max_workers: int = 5) -> dict[str, Issue]:
    playbook_ids_to_jira_tickets: dict[str, Issue] = {}
    logging.info(f"Searching for Jira tickets for {len(playbook_ids)} playbooks, using {max_workers} workers")
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
            except Exception:  # noqa
                logging.error(f'Failed to search for a jira ticket for playbook id:"{futures[future]}"')

    return playbook_ids_to_jira_tickets


def green_text(text: str) -> str:
    return f"{GREEN_COLOR}{text}{NO_COLOR_ESCAPE_CHAR}"


def red_text(text: str) -> str:
    return f"{RED_COLOR}{text}{NO_COLOR_ESCAPE_CHAR}"


def get_all_failed_playbooks(playbooks_results: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    failed_playbooks = {}
    for playbook_id, playbook_results in playbooks_results.items():
        for test_suite in playbook_results.values():
            if test_suite.errors or test_suite.failures:
                failed_playbooks[playbook_id] = playbooks_results
                break

    return failed_playbooks


def calculate_test_playbooks_results_table(jira_tickets_for_playbooks: dict[str, Issue],
                                           playbooks_results: dict[str, dict[str, Any]],
                                           server_versions: set[str],
                                           add_total_row: bool = True,
                                           no_color: bool = False,
                                           without_jira: bool = False,
                                           with_skipped: bool = False) -> tuple[list[str], list[list[Any]], JUnitXml, int]:
    xml = JUnitXml()
    headers = copy.copy(TEST_SUITE_BASE_HEADERS if without_jira else TEST_SUITE_FIXED_HEADERS)
    fixed_headers_length = len(headers)
    server_versions_list: list[str] = sorted(server_versions)
    for server_version in server_versions_list:
        headers.append(f"{server_version} ({TEST_SUITE_DATA_CELL_HEADER})")
    tabulate_data = []
    total_row: list[Any] = ([NOT_AVAILABLE] * fixed_headers_length + [TestSuiteStatistics()
                                                                      for _ in range(len(server_versions_list))])
    total_errors = 0
    for playbook_id, playbook_results in tqdm(playbooks_results.items(), desc="Generating test summary", unit="playbook",
                                              leave=True, colour='green', miniters=10, mininterval=5.0):
        row: list[Any] = []
        if not without_jira:
            if jira_ticket := jira_tickets_for_playbooks.get(playbook_id):
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
            test_suite: TestSuite = playbook_results.get(server_version)
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
            row.insert(0,
                       (red_text(playbook_id) if errors_count else green_text(playbook_id) if not no_color else playbook_id))
            tabulate_data.append(row)

            # Offset the total row by the number of fixed headers
            for i, cell in enumerate(row[fixed_headers_length:], start=fixed_headers_length):
                if isinstance(cell, TestSuiteStatistics):
                    total_row[i] += cell
        else:
            logging.debug(f"Skipping playbook {playbook_id} since all the test suites were skipped")
    if add_total_row:
        total_row[0] = (green_text(TOTAL_HEADER) if total_errors == 0 else red_text(TOTAL_HEADER)) \
            if not no_color else TOTAL_HEADER
        tabulate_data.append(total_row)
    return headers, tabulate_data, xml, total_errors


def get_test_playbook_results_files(artifacts_path: Path) -> list[Path]:
    test_playbooks_result_files_list: list[Path] = []
    for instance_role, directory in get_instance_directories(artifacts_path).items():
        logging.info(f"Found instance directory: {directory} for instance role: {instance_role}")
        has_test_playbooks_result_files_list = Path(artifacts_path) / directory / "has_test_playbooks_result_files_list.txt"
        if has_test_playbooks_result_files_list.exists():
            logging.info(f"Found test playbook result files list file: {has_test_playbooks_result_files_list}")
            test_playbooks_result_files_list.append(Path(artifacts_path) / directory / "test_playbooks_report.xml")
    return test_playbooks_result_files_list


def get_instance_directories(artifacts_path: Path) -> dict[str, Path]:
    test_playbooks_result_files_list: dict[str, Path] = {}
    for directory in artifacts_path.iterdir():
        if directory.is_dir() and directory.name.startswith("instance_"):
            instance_role_txt = directory / "instance_role.txt"
            if instance_role_txt.exists():
                instance_role: str = instance_role_txt.read_text().replace("\n", "")
                test_playbooks_result_files_list[instance_role] = directory
    return test_playbooks_result_files_list
