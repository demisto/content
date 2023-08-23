import argparse
import json
import os
import sys
import traceback
from datetime import datetime, timezone, timedelta
from tempfile import NamedTemporaryFile

import urllib3
from jira.client import ResultList, Issue, JIRA
from junitparser import TestSuite, JUnitXml

from Tests.scripts.utils import logging_wrapper as logging
from Tests.scripts.utils.log_util import install_logging

urllib3.disable_warnings()  # Disable insecure warnings

GITLAB_PROJECT_ID = os.getenv('CI_PROJECT_ID') or 2596  # the default is the id of the content repo in code.pan.run
GITLAB_SERVER_URL = os.getenv('CI_SERVER_URL', 'https://code.pan.run')  # disable-secrets-detection
JIRA_SERVER_URL = os.environ["JIRA_SERVER_URL"]
JIRA_VERIFY_SSL = "true" in os.environ.get("JIRA_VERIFY_SSL", "True").lower()
JIRA_API_KEY = os.environ["JIRA_API_KEY"]
JIRA_PROJECT_ID = os.environ["JIRA_PROJECT_ID"]
JIRA_ISSUE_TYPE = os.environ["JIRA_ISSUE_TYPE"]
JIRA_COMPONENT = os.environ["JIRA_COMPONENT"]
JIRA_ISSUE_UNRESOLVED_TRANSITION_NAME = os.environ["JIRA_ISSUE_UNRESOLVED_TRANSITION_NAME"]
JIRA_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%f%z"
JIRA_ADDITIONAL_FIELDS = json.loads(os.environ.get("JIRA_ADDITIONAL_FIELDS", "{}"))
JIRA_LABELS = json.loads(os.environ.get("JIRA_LABELS", "[]"))


def options_handler() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Converts the junit report to a jira issues')
    parser.add_argument("-jp", "--junit-path", help='JUnit report file path', required=True)
    parser.add_argument('-u', '--url', help='The gitlab server url', default=GITLAB_SERVER_URL)
    parser.add_argument('-gp', '--gitlab_project_id', help='The gitlab project id', default=GITLAB_PROJECT_ID)
    parser.add_argument('-d', '--max_days_to_reopen', default=30, type=int,
                        help='The max days to reopen a closed issue')
    options = parser.parse_args()

    return options


def create_jira_issue(jira_server: JIRA,
                      test_suite: TestSuite,
                      options: argparse.Namespace,
                      now: datetime) -> Issue:

    properties = {prop.name: prop.value for prop in test_suite.properties()}
    build_id = properties.get("ci_pipeline_id", "")
    build_url = f"{GITLAB_SERVER_URL}/{GITLAB_PROJECT_ID}/-/pipelines/{build_id}" if build_id else ""
    build_id_hash = f" #{build_id}" if build_id else ""
    build_markdown_link = f"[Nightly{build_id_hash}|{build_url}]" if build_id else f"Nightly{build_id_hash}"
    description = f"""
        *{properties['pack_id']}* - *{properties['file_name']}* failed in {build_markdown_link}

        ||Tests||Result||
        |Total|{test_suite.tests}|
        |Failed|{test_suite.failures}|
        |Errors|{test_suite.errors}|
        |Skipped|{test_suite.skipped}|
        |Successful|{test_suite.tests - test_suite.failures - test_suite.errors - test_suite.skipped}|
        |Duration|{test_suite.time}s|
        """
    summary = f"{properties['pack_id']} - {properties['file_name']} failed nightly"
    jql_query = (f"project = \"{JIRA_PROJECT_ID}\" AND issuetype = \"{JIRA_ISSUE_TYPE}\" "
                 f"AND component = \"{JIRA_COMPONENT}\" AND summary ~ \"{summary}\" ORDER BY created DESC")
    search_issues: ResultList[Issue] = jira_server.search_issues(jql_query, maxResults=1)
    link_to_issue = None
    jira_issue = None
    if use_existing_issue := (len(search_issues) == 1):
        searched_issue = search_issues[0]
        if searched_issue.get_field("resolution"):
            resolution_date = datetime.strptime(searched_issue.get_field("resolutiondate"), JIRA_TIME_FORMAT)
            if use_existing_issue := (resolution_date
                                      and (now - resolution_date)
                                      <= timedelta(days=options.max_days_to_reopen)):  # type: ignore[assignment]

                #  Get the available transitions for the issue
                transitions = jira_server.transitions(searched_issue)

                # Find the transition with the specified ID
                unresolved_transition = None
                for transition in transitions:
                    if transition['name'] == JIRA_ISSUE_UNRESOLVED_TRANSITION_NAME:
                        unresolved_transition = transition
                        break
                if unresolved_transition:
                    jira_server.transition_issue(searched_issue, unresolved_transition['id'])
                    jira_issue = searched_issue
                else:
                    logging.error(f"Failed to find the '{JIRA_ISSUE_UNRESOLVED_TRANSITION_NAME}' "
                                  f"transition for issue {searched_issue.key}")
                    jira_issue = None
                    use_existing_issue = False
                    link_to_issue = searched_issue

            else:
                link_to_issue = searched_issue
        else:
            jira_issue = searched_issue

    if jira_issue is not None:
        jira_server.add_comment(issue=jira_issue, body=description)
    else:
        jira_issue = jira_server.create_issue(project=JIRA_PROJECT_ID,
                                              summary=summary,
                                              description=description,
                                              issuetype={'name': JIRA_ISSUE_TYPE},
                                              components=[{'name': JIRA_COMPONENT}],
                                              labels=['nightly'] + JIRA_LABELS,
                                              **JIRA_ADDITIONAL_FIELDS
                                              )
        # Create a back link to the previous issue, which is resolved.
        if link_to_issue:
            jira_server.create_issue_link(type="Relates", inwardIssue=jira_issue.key,
                                          outwardIssue=link_to_issue.key)

    with NamedTemporaryFile() as attachment_file_name:
        xml = JUnitXml()
        xml.add_testsuite(test_suite)
        xml.write(attachment_file_name.name, pretty=True)
        build_id_dash = f"-{build_id}" if build_id else ""
        junit_file_name = (f"unit-test{build_id_dash}-{properties['start_time']}-{properties['pack_id']}-"
                           f"{properties['file_name']}.xml")
        jira_server.add_attachment(issue=jira_issue.key, attachment=attachment_file_name.name, filename=junit_file_name)

    back_link_to = f" with back link to {link_to_issue.key}" if link_to_issue else ""
    logging.info(f"{'Updated' if use_existing_issue else 'Created'} Jira issue: {jira_issue.key} {back_link_to}"
                 f"for {test_suite.name} with {test_suite.failures} failures and {test_suite.errors} errors")

    return jira_issue


def main():
    try:
        install_logging('convert_test_result_to_jira_issues.log', logger=logging)
        now = datetime.now(tz=timezone.utc)
        options = options_handler()
        logging.info(f'JUnit path: {options.junit_path}')
        logging.info(f'Gitlab server url: {options.url}')
        logging.info(f'Gitlab project id: {options.gitlab_project_id}')
        logging.info(f'Jira server url: {JIRA_SERVER_URL}')
        logging.info(f'Jira verify SSL: {JIRA_VERIFY_SSL}')
        logging.info(f'Jira project id: {JIRA_PROJECT_ID}')
        logging.info(f'Jira issue type: {JIRA_ISSUE_TYPE}')
        logging.info(f'Jira component: {JIRA_COMPONENT}')
        logging.info(f'Jira labels: {JIRA_LABELS}')
        logging.info(f'Jira issue unresolved transition name: {JIRA_ISSUE_UNRESOLVED_TRANSITION_NAME}')
        logging.info(f'Max days to reopen: {options.max_days_to_reopen}')

        jira_server = JIRA(JIRA_SERVER_URL, token_auth=JIRA_API_KEY, options={'verify': JIRA_VERIFY_SSL})

        xml = JUnitXml.fromfile(options.junit_path)
        for test_suite in xml.iterchildren(TestSuite):
            if test_suite.failures or test_suite.errors:
                create_jira_issue(jira_server, test_suite, options, now)
            else:
                logging.info(f"Skipped creating Jira issue for {test_suite.name}")

    except Exception as e:
        logging.exception(f'Failed to create jira issues from JUnit results: {e}')
        logging.error(traceback.format_exc())
        sys.exit(1)


if __name__ == '__main__':
    main()
