from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import tenacity
from jira import JIRAError, JIRA, Issue
from jira.client import ResultList
from junitparser import JUnitXml, TestSuite
from tqdm import tqdm

from Tests.scripts.common import get_properties_for_test_suite
from Tests.scripts.jira_issues import generate_ticket_summary, generate_query
from Tests.scripts.utils import logging_wrapper as logging

TEST_PLAYBOOKS_BASE_HEADERS = ["Playbook ID"]


def calculate_test_playbooks_results(test_playbooks_result_files_list: dict[str, Path]
                                     ) -> tuple[dict[str, dict[str, Any]], set[str]]:
    playbooks_results: dict[str, dict[str, Any]] = {}
    server_versions = set()
    for instance_role, test_playbook_result_file in test_playbooks_result_files_list.items():
        logging.debug(f"Processing test playbook result file: {test_playbook_result_file} for instance role: {instance_role}")
        xml = JUnitXml.fromfile(test_playbook_result_file.as_posix())
        for test_suite_item in xml.iterchildren(TestSuite):
            properties = get_properties_for_test_suite(test_suite_item)
            if "playbook_id" in properties:
                playbooks_result = playbooks_results.setdefault(properties["playbook_id"], {})
                server_version = properties["server_version"]
                server_versions.add(server_version)
                playbooks_result[server_version] = test_suite_item
    return playbooks_results, server_versions


@tenacity.retry(
    wait=tenacity.wait_exponential(multiplier=1, min=2, max=10),
    stop=tenacity.stop_after_attempt(2),
    reraise=True,
    retry=tenacity.retry_if_exception_type(JIRAError),
    before_sleep=tenacity.before_sleep_log(logging.getLogger(), logging.DEBUG)
)
def search_in_jira_ticket_for_playbook(jira_server: JIRA, playbook_id: str) -> Issue | None:
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
            executor.submit(search_in_jira_ticket_for_playbook, jira_server, playbook_id): playbook_id
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
