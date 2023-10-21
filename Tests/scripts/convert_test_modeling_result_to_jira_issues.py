import argparse
import os
import sys
import traceback
from datetime import datetime, timezone

import urllib3
from jira import JIRA
from junitparser import TestSuite, JUnitXml

from Tests.scripts.jira_issues import GITLAB_PROJECT_ID, GITLAB_SERVER_URL, JIRA_SERVER_URL, JIRA_VERIFY_SSL, JIRA_API_KEY, \
    JIRA_PROJECT_ID, JIRA_ISSUE_TYPE, JIRA_COMPONENT, JIRA_ISSUE_UNRESOLVED_TRANSITION_NAME, JIRA_LABELS, \
    jira_server_information
from Tests.scripts.test_modeling_rule_report import create_jira_issue_for_test_modeling_rule, \
    get_test_modeling_rules_results_files
from Tests.scripts.utils import logging_wrapper as logging
from Tests.scripts.utils.log_util import install_logging

urllib3.disable_warnings()  # Disable insecure warnings
JIRA_MAX_DAYS_TO_REOPEN_DEFAULT = 30
JIRA_MAX_DAYS_TO_REOPEN = (os.environ.get("JIRA_MAX_DAYS_TO_REOPEN", JIRA_MAX_DAYS_TO_REOPEN_DEFAULT)
                           or JIRA_MAX_DAYS_TO_REOPEN_DEFAULT)


def options_handler() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Converts Test modeling report to Jira issues')
    parser.add_argument("-a", "--artifacts-path", help='Artifacts path', required=True)
    parser.add_argument('-u', '--url', help='The gitlab server url', default=GITLAB_SERVER_URL)
    parser.add_argument('-gp', '--gitlab-project-id', help='The gitlab project id', default=GITLAB_PROJECT_ID)
    parser.add_argument('-d', '--max-days-to-reopen', default=JIRA_MAX_DAYS_TO_REOPEN, type=int,
                        help='The max days to reopen a closed issue')
    return parser.parse_args()


def main():
    try:
        install_logging('convert_test_modeling_result_to_jira_issues.log', logger=logging)
        now = datetime.now(tz=timezone.utc)
        options = options_handler()
        logging.info(f'Artifacts path: {options.artifacts_path}\n'
                     f'Gitlab server url: {options.url}\n'
                     f'Gitlab project id: {options.gitlab_project_id}\n'
                     f'Jira server url: {JIRA_SERVER_URL}\n'
                     f'Jira verify SSL: {JIRA_VERIFY_SSL}\n'
                     f'Jira project id: {JIRA_PROJECT_ID}\n'
                     f'Jira issue type: {JIRA_ISSUE_TYPE}\n'
                     f'Jira component: {JIRA_COMPONENT}\n'
                     f'Jira labels: {JIRA_LABELS}\n'
                     f'Jira issue unresolved transition name: {JIRA_ISSUE_UNRESOLVED_TRANSITION_NAME}\n'
                     f'Max days to reopen: {options.max_days_to_reopen}\n')

        jira_server = JIRA(JIRA_SERVER_URL, token_auth=JIRA_API_KEY, options={'verify': JIRA_VERIFY_SSL})
        jira_server_information(jira_server)

        if not (result_files_list := get_test_modeling_rules_results_files(options.artifacts_path)):
            logging.critical(f"Could not find any test modeling rules result files in {options.artifacts_path}")
            sys.exit(1)

        logging.info(f"Found {len(result_files_list)} test modeling rules files")

        for result_file in result_files_list:
            xml = JUnitXml.fromfile(result_file.as_posix())
            for test_suite in xml.iterchildren(TestSuite):
                create_jira_issue_for_test_modeling_rule(jira_server, test_suite, options.max_days_to_reopen, now)

        logging.info("Finished creating/updating Jira issues for test modeling rules")

    except Exception as e:
        logging.exception(f'Failed to create jira issues from JUnit results: {e}')
        logging.error(traceback.format_exc())
        sys.exit(1)


if __name__ == '__main__':
    main()
