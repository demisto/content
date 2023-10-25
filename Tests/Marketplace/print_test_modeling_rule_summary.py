import argparse
import sys
import traceback
from pathlib import Path

import urllib3
from jira import JIRA
from tabulate import tabulate

from Tests.scripts.common import calculate_results_table, TEST_MODELING_RULES_REPORT_FILE_NAME, get_test_results_files
from Tests.scripts.jira_issues import JIRA_SERVER_URL, JIRA_VERIFY_SSL, JIRA_PROJECT_ID, JIRA_ISSUE_TYPE, JIRA_COMPONENT, \
    JIRA_API_KEY, jira_server_information
from Tests.scripts.test_modeling_rule_report import TEST_MODELING_RULES_BASE_HEADERS, calculate_test_modeling_rule_results
from Tests.scripts.utils import logging_wrapper as logging
from Tests.scripts.utils.log_util import install_logging

urllib3.disable_warnings()  # Disable insecure warnings


def options_handler() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Utility for printing the test modeling rule summary')
    parser.add_argument('--artifacts-path', help='Path to the artifacts directory', required=True)
    parser.add_argument('--without-jira', help='Print the summary without Jira tickets', action='store_true')
    return parser.parse_args()


def print_test_modeling_rule_summary(artifacts_path: Path, without_jira: bool) -> bool:
    logging.info(f"Printing test modeling rule summary - artifacts path: {artifacts_path}")
    # iterate over the artifacts path and find all the test modeling rule result files
    if not (test_modeling_rules_results_files := get_test_results_files(artifacts_path, TEST_MODELING_RULES_REPORT_FILE_NAME)):
        logging.error(f"Could not find any test modeling rule result files in {artifacts_path}")
        return True

    logging.info(f"Found {len(test_modeling_rules_results_files)} test modeling rules files")

    if without_jira:
        logging.info("Printing test modeling rule summary without Jira tickets")
        jira_server = None
    else:
        logging.info("Searching for Jira tickets for test modeling rule with the following settings:\n"
                     f'Jira server url: {JIRA_SERVER_URL}\n'
                     f'Jira verify SSL: {JIRA_VERIFY_SSL}\n'
                     f'Jira project id: {JIRA_PROJECT_ID}\n'
                     f'Jira issue type: {JIRA_ISSUE_TYPE}\n'
                     f'Jira component: {JIRA_COMPONENT}\n')
        jira_server = JIRA(JIRA_SERVER_URL, token_auth=JIRA_API_KEY, options={'verify': JIRA_VERIFY_SSL})
        jira_server_information(jira_server)

    modeling_rules_to_test_suite, jira_tickets_for_modeling_rule, server_versions = (
        calculate_test_modeling_rule_results(test_modeling_rules_results_files, jira_server)
    )

    if modeling_rules_to_test_suite:
        logging.info(f"Found {len(jira_tickets_for_modeling_rule)} Jira tickets out of {len(modeling_rules_to_test_suite)} "
                     "Test modeling rules")

        headers, tabulate_data, xml, total_errors = calculate_results_table(jira_tickets_for_modeling_rule,
                                                                            modeling_rules_to_test_suite,
                                                                            server_versions,
                                                                            TEST_MODELING_RULES_BASE_HEADERS,
                                                                            without_jira=without_jira)

        table = tabulate(tabulate_data, headers, tablefmt="pretty", stralign="left", numalign="center")
        logging.info(f"Test Modeling rule Results:\n{table}")
        return total_errors != 0

    logging.info("Test Modeling rule Results - No test modeling rule results found")
    return False


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
