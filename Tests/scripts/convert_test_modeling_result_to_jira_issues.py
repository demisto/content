import argparse
import os
import sys
import traceback
from datetime import datetime, timezone

import urllib3
from jira.client import JIRA
from junitparser import TestSuite, JUnitXml

from Tests.scripts.jira_issues import GITLAB_PROJECT_ID, GITLAB_SERVER_URL, JIRA_SERVER_URL, JIRA_VERIFY_SSL, JIRA_API_KEY, \
    JIRA_PROJECT_ID, JIRA_ISSUE_TYPE, JIRA_COMPONENT, JIRA_ISSUE_UNRESOLVED_TRANSITION_NAME, JIRA_LABELS, create_jira_issue
from Tests.scripts.utils import logging_wrapper as logging
from Tests.scripts.utils.log_util import install_logging

urllib3.disable_warnings()  # Disable insecure warnings
JIRA_MAX_DAYS_TO_REOPEN_DEFAULT = 30
JIRA_MAX_DAYS_TO_REOPEN = (os.environ.get("JIRA_MAX_DAYS_TO_REOPEN", JIRA_MAX_DAYS_TO_REOPEN_DEFAULT) or
                           JIRA_MAX_DAYS_TO_REOPEN_DEFAULT)


def options_handler() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Converts Test modeling JUnit report to Jira issues')
    parser.add_argument("-jp", "--junit-path", help='JUnit report file path', required=True)
    parser.add_argument('-u', '--url', help='The gitlab server url', default=GITLAB_SERVER_URL)
    parser.add_argument('-gp', '--gitlab-project-id', help='The gitlab project id', default=GITLAB_PROJECT_ID)
    parser.add_argument('-d', '--max-days-to-reopen', default=JIRA_MAX_DAYS_TO_REOPEN, type=int,
                        help='The max days to reopen a closed issue')
    options = parser.parse_args()

    return options


def main():
    try:
        install_logging('convert_test_modeling_result_to_jira_issues.log', logger=logging)
        now = datetime.now(tz=timezone.utc)
        options = options_handler()
        logging.info(f'JUnit path: {options.junit_path}\n'
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

        xml = JUnitXml.fromfile(options.junit_path)
        for test_suite in xml.iterchildren(TestSuite):
            if test_suite.failures or test_suite.errors:
                create_jira_issue(jira_server, test_suite, options, now)
            else:
                logging.debug(f"Skipped creating Jira issue for successful test {test_suite.name}")

        logging.info("Finished creating/updating Jira issues")

    except Exception as e:
        logging.exception(f'Failed to create jira issues from JUnit results: {e}')
        logging.error(traceback.format_exc())
        sys.exit(1)


if __name__ == '__main__':
    main()
