import argparse
import sys
import traceback
from pathlib import Path

import urllib3
from jira import JIRA
from junitparser import JUnitXml
from tabulate import tabulate

from Tests.scripts.jira_issues import JIRA_SERVER_URL, JIRA_VERIFY_SSL, JIRA_PROJECT_ID, JIRA_ISSUE_TYPE, JIRA_COMPONENT, \
    JIRA_API_KEY, jira_server_information
from Tests.scripts.test_modeling_rule_report import get_test_modeling_rules_results_files
from Tests.scripts.test_playbooks_report import calculate_test_playbooks_results, get_jira_tickets_for_playbooks, \
    calculate_test_playbooks_results_table, get_test_playbook_results_files
from Tests.scripts.utils import logging_wrapper as logging
from Tests.scripts.utils.log_util import install_logging

urllib3.disable_warnings()  # Disable insecure warnings


def options_handler() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Utility for printing the test modeling rule summary')
    parser.add_argument('--artifacts-path', help='Path to the artifacts directory', required=True)
    parser.add_argument('--without-jira', help='Print the summary without Jira tickets', action='store_true')
    return parser.parse_args()


def filter_skipped_playbooks(playbooks_results: dict[str, dict[str, JUnitXml]]) -> list[str]:
    filtered_playbooks_ids = []
    for playbook_id, playbook_results in playbooks_results.items():
        skipped_count = 0
        for test_suite in playbook_results.values():
            if test_suite.skipped and test_suite.failures == 0 and test_suite.errors == 0:
                logging.debug(f"Skipping playbook {playbook_id} because it was skipped in the test")
                skipped_count += 1

        # If all the test suites were skipped, don't add the row to the table.
        if skipped_count != len(playbook_results):
            filtered_playbooks_ids.append(playbook_id)
    return filtered_playbooks_ids


def print_test_modeling_rule_summary(artifacts_path: Path, without_jira: bool) -> bool:

    logging.info(f"Printing test modeling rule summary - artifacts path: {artifacts_path}")
    # iterate over the artifacts path and find all the test playbook result files
    if not (test_playbooks_result_files_list := get_test_modeling_rules_results_files(artifacts_path)):
        logging.error(f"Could not find any test modeling rule result files in {artifacts_path}")
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
        logging.info(f"Found {len(jira_tickets_for_playbooks)} Jira tickets out of {len(playbooks_ids)} filtered playbooks")

    headers, tabulate_data, xml, total_errors = calculate_test_playbooks_results_table(jira_tickets_for_playbooks,
                                                                                       playbooks_results,
                                                                                       server_versions,
                                                                                       without_jira=without_jira)
    table = tabulate(tabulate_data, headers, tablefmt="pretty", stralign="left", numalign="center")
    logging.info(f"Test Playbook Results:\n{table}")
    return total_errors == 0


def main():
    try:
        install_logging('print_test_modeling_rule_summary.log', logger=logging)
        options = options_handler()
        artifacts_path = Path(options.artifacts_path)
        logging.info(f"Printing test modeling rule summary - artifacts path: {artifacts_path}")

        if print_test_modeling_rule_summary(artifacts_path, options.without_jira):
            logging.critical("Test modeling rule summary found errors")
            sys.exit(1)

        logging.info("Test modeling rule summary finished successfully")
    except Exception as e:
        logging.error(f'Failed to get the test modeling rule summary: {e}')
        logging.error(traceback.format_exc())
        sys.exit(1)


if __name__ == '__main__':
    main()
