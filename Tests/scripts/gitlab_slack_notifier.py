import argparse
import contextlib
import json
import logging
import os
import sys
from datetime import datetime, timedelta
from distutils.util import strtobool
from pathlib import Path
from typing import Any

import requests
from demisto_sdk.commands.coverage_analyze.tools import get_total_coverage
from gitlab.client import Gitlab
from gitlab.v4.objects import ProjectPipelineJob
from junitparser import JUnitXml, TestSuite
from slack_sdk import WebClient
from slack_sdk.web import SlackResponse

from Tests.Marketplace.marketplace_constants import BucketUploadFlow
from Tests.Marketplace.marketplace_services import get_upload_data
from Tests.scripts.common import CONTENT_NIGHTLY, CONTENT_PR, WORKFLOW_TYPES, get_instance_directories, \
    get_properties_for_test_suite, BUCKET_UPLOAD, BUCKET_UPLOAD_BRANCH_SUFFIX, TEST_MODELING_RULES_REPORT_FILE_NAME, \
    get_test_results_files, CONTENT_MERGE, UNIT_TESTS_WORKFLOW_SUBSTRINGS, TEST_PLAYBOOKS_REPORT_FILE_NAME, \
    replace_escape_characters
from Tests.scripts.github_client import GithubPullRequest
from Tests.scripts.test_modeling_rule_report import calculate_test_modeling_rule_results, \
    read_test_modeling_rule_to_jira_mapping, get_summary_for_test_modeling_rule, TEST_MODELING_RULES_TO_JIRA_TICKETS_CONVERTED
from Tests.scripts.test_playbooks_report import read_test_playbook_to_jira_mapping, TEST_PLAYBOOKS_TO_JIRA_TICKETS_CONVERTED
from Tests.scripts.utils.log_util import install_logging

ROOT_ARTIFACTS_FOLDER = Path(os.getenv('ARTIFACTS_FOLDER', './artifacts'))
ARTIFACTS_FOLDER_XSOAR = ROOT_ARTIFACTS_FOLDER / 'xsoar'
ARTIFACTS_FOLDER_XSIAM = ROOT_ARTIFACTS_FOLDER / 'marketplacev2'
ARTIFACTS_FOLDER_XPANSE = ROOT_ARTIFACTS_FOLDER / 'xpanse'
ARTIFACTS_FOLDER_XSOAR_SERVER_TYPE = ARTIFACTS_FOLDER_XSOAR / "server_type_XSOAR"
ARTIFACTS_FOLDER_XSOAR_SAAS_SERVER_TYPE = ARTIFACTS_FOLDER_XSOAR / "server_type_XSOAR SAAS"
ARTIFACTS_FOLDER_XPANSE_SERVER_TYPE = ARTIFACTS_FOLDER_XPANSE / "server_type_XPANSE"
ARTIFACTS_FOLDER_XSIAM_SERVER_TYPE = ARTIFACTS_FOLDER_XSIAM / "server_type_XSIAM"
GITLAB_SERVER_URL = os.getenv('CI_SERVER_URL', 'https://code.pan.run')  # disable-secrets-detection
GITLAB_PROJECT_ID = os.getenv('CI_PROJECT_ID') or 2596  # the default is the id of the content repo in code.pan.run
CONTENT_CHANNEL = 'dmst-build-test'
SLACK_USERNAME = 'Content GitlabCI'
SLACK_WORKSPACE_NAME = os.getenv('SLACK_WORKSPACE_NAME', '')
GITHUB_TOKEN = os.getenv('GITHUB_TOKEN', '')
CI_COMMIT_BRANCH = os.getenv('CI_COMMIT_BRANCH', '')
CI_COMMIT_SHA = os.getenv('CI_COMMIT_SHA', '')
CI_SERVER_HOST = os.getenv('CI_SERVER_HOST', '')
DEFAULT_BRANCH = 'master'
ALL_FAILURES_WERE_CONVERTED_TO_JIRA_TICKETS = ' (All failures were converted to Jira tickets)'


def options_handler() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Parser for slack_notifier args')
    parser.add_argument('-u', '--url', help='The gitlab server url', default=GITLAB_SERVER_URL)
    parser.add_argument('-p', '--pipeline_id', help='The pipeline id to check the status of', required=True)
    parser.add_argument('-s', '--slack_token', help='The token for slack', required=True)
    parser.add_argument('-c', '--ci_token', help='The token for circleci/gitlab', required=True)
    parser.add_argument(
        '-ch', '--slack_channel', help='The slack channel in which to send the notification', default=CONTENT_CHANNEL
    )
    parser.add_argument('-gp', '--gitlab_project_id', help='The gitlab project id', default=GITLAB_PROJECT_ID)
    parser.add_argument(
        '-tw', '--triggering-workflow', help='The type of ci pipeline workflow the notifier is reporting on',
        choices=WORKFLOW_TYPES)
    parser.add_argument('-a', '--allow-failure',
                        help="Allow posting message to fail in case the channel doesn't exist", required=True)
    parser.add_argument('--github-token', required=False, help='A GitHub API token', default=GITHUB_TOKEN)
    parser.add_argument('--current-sha', required=False, help='Current branch commit SHA', default=CI_COMMIT_SHA)
    parser.add_argument('--current-branch', required=False, help='Current branch name', default=CI_COMMIT_BRANCH)
    return parser.parse_args()


def get_artifact_data(artifact_folder: Path, artifact_relative_path: str) -> str | None:
    """
    Retrieves artifact data according to the artifact relative path from 'ARTIFACTS_FOLDER' given.
    Args:
        artifact_folder (Path): Full path of the artifact root folder.
        artifact_relative_path (str): Relative path of an artifact file.

    Returns:
        (Optional[str]): data of the artifact as str if exists, None otherwise.
    """
    file_name = artifact_folder / artifact_relative_path
    try:
        if file_name.exists():
            logging.info(f'Extracting {file_name}')
            return file_name.read_text()
        else:
            logging.info(f'Did not find {file_name} file')
    except Exception:
        logging.exception(f'Error getting {file_name} file')
    return None


def get_test_report_pipeline_url(pipeline_url: str) -> str:
    return f"{pipeline_url}/test_report"


def test_modeling_rules_results(artifact_folder: Path,
                                pipeline_url: str, title: str) -> tuple[list[dict[str, Any]], bool]:

    if not (test_modeling_rules_results_files := get_test_results_files(artifact_folder, TEST_MODELING_RULES_REPORT_FILE_NAME)):
        logging.error(f"Could not find any test modeling rule result files in {artifact_folder}")
        title = f"{title} - Failed to get Test Modeling rules results"
        return [{
            'fallback': title,
            'color': 'warning',
            'title': title,
        }], True

    failed_test_to_jira_mapping = read_test_modeling_rule_to_jira_mapping(artifact_folder)

    modeling_rules_to_test_suite, _, _ = (
        calculate_test_modeling_rule_results(test_modeling_rules_results_files)
    )

    if not modeling_rules_to_test_suite:
        logging.info("Test Modeling rules - No test modeling rule results found for this build")
        title = f"{title} - Test Modeling rules - No test modeling rule results found for this build"
        return [{
            'fallback': title,
            'color': 'good',
            'title': title,
        }], False

    failed_test_suites = []
    total_test_suites = 0
    for test_suites in modeling_rules_to_test_suite.values():
        for test_suite in test_suites.values():
            total_test_suites += 1
            if test_suite.failures or test_suite.errors:
                properties = get_properties_for_test_suite(test_suite)
                if modeling_rule := get_summary_for_test_modeling_rule(properties):
                    failed_test_suites.append(failed_test_data_to_slack_link(modeling_rule,
                                                                             failed_test_to_jira_mapping.get(modeling_rule)))

    if failed_test_suites:
        if (artifact_folder / TEST_MODELING_RULES_TO_JIRA_TICKETS_CONVERTED).exists():
            title_suffix = ALL_FAILURES_WERE_CONVERTED_TO_JIRA_TICKETS
            color = 'warning'
        else:
            title_suffix = ''
            color = 'danger'

        title = (f"{title} - Failed Tests Modeling rules - Passed:{total_test_suites - len(failed_test_suites)}, "
                 f"Failed:{len(failed_test_suites)}")
        return [{
            'fallback': title,
            'color': color,
            'title': title,
            'title_link': get_test_report_pipeline_url(pipeline_url),
            'fields': [
                {
                    "title": f"Failed Tests Modeling rules{title_suffix}",
                    "value": ' ,'.join(failed_test_suites),
                    "short": False
                }
            ]
        }], True

    title = f"{title} - All Test Modeling rules Passed - ({total_test_suites})"
    return [{
        'fallback': title,
        'color': 'good',
        'title': title,
        'title_link': get_test_report_pipeline_url(pipeline_url),
    }], False


def failed_test_data_to_slack_link(failed_test: str, jira_ticket_data: dict[str, str] | None) -> str:
    if jira_ticket_data:
        return slack_link(jira_ticket_data['url'], f"{failed_test} [{jira_ticket_data['key']}]")
    return failed_test


def slack_link(url: str, text: str) -> str:
    return f"<{url}|{text}>"


def test_playbooks_results_to_slack_msg(instance_role: str,
                                        succeeded_tests: set[str],
                                        failed_tests: set[str],
                                        skipped_integrations: set[str],
                                        skipped_tests: set[str],
                                        playbook_to_jira_mapping: dict[str, Any],
                                        test_playbook_tickets_converted: bool,
                                        title: str,
                                        pipeline_url: str) -> tuple[list[dict[str, Any]], bool]:
    if failed_tests:
        title = (f"{title} ({instance_role}) - Test Playbooks - Passed:{len(succeeded_tests)}, Failed:{len(failed_tests)}, "
                 f"Skipped - {len(skipped_tests)}, Skipped Integrations - {len(skipped_integrations)}")
        if test_playbook_tickets_converted:
            title_suffix = ALL_FAILURES_WERE_CONVERTED_TO_JIRA_TICKETS
            color = 'warning'
        else:
            title_suffix = ''
            color = 'danger'
        return [{
            'fallback': title,
            'color': color,
            'title': title,
            'title_link': get_test_report_pipeline_url(pipeline_url),
            "mrkdwn_in": ["fields"],
            'fields': [{
                "title": f"Failed Test Playbooks{title_suffix}",
                "value": ', '.join(
                    failed_test_data_to_slack_link(playbook_id,
                                                   playbook_to_jira_mapping.get(playbook_id)) for playbook_id in failed_tests),
                "short": False
            }]
        }], True
    title = (f"{title} ({instance_role}) - All Tests Playbooks Passed - Passed:{len(succeeded_tests)}, "
             f"Skipped - {len(skipped_tests)}, Skipped Integrations - {len(skipped_integrations)})")
    return [{
        'fallback': title,
        'color': 'good',
        'title': title,
        'title_link': get_test_report_pipeline_url(pipeline_url),
    }], False


def split_results_file(tests_data: str | None) -> list[str]:
    return list(filter(None, tests_data.split('\n'))) if tests_data else []


def get_playbook_tests_data(artifact_folder: Path) -> tuple[set[str], set[str], set[str], set[str]]:
    succeeded_tests = set()
    failed_tests = set()
    skipped_tests = set()
    skipped_integrations = set(split_results_file(get_artifact_data(artifact_folder, 'skipped_integrations.txt')))
    xml = JUnitXml.fromfile(artifact_folder / TEST_PLAYBOOKS_REPORT_FILE_NAME)
    for test_suite in xml.iterchildren(TestSuite):
        properties = get_properties_for_test_suite(test_suite)
        if playbook_id := properties.get("playbook_id"):
            if test_suite.failures or test_suite.errors:
                failed_tests.add(playbook_id)
            elif test_suite.skipped:
                skipped_tests.add(playbook_id)
            else:
                succeeded_tests.add(playbook_id)

    return succeeded_tests, failed_tests, skipped_tests, skipped_integrations


def test_playbooks_results(artifact_folder: Path, pipeline_url: str, title: str) -> tuple[list[dict[str, Any]], bool]:

    test_playbook_to_jira_mapping = read_test_playbook_to_jira_mapping(artifact_folder)
    test_playbook_tickets_converted = (artifact_folder / TEST_PLAYBOOKS_TO_JIRA_TICKETS_CONVERTED).exists()
    has_failed_tests = False
    test_playbook_slack_msg = []
    for instance_role, instance_directory in get_instance_directories(artifact_folder).items():
        succeeded_tests, failed_tests, skipped_tests, skipped_integrations = get_playbook_tests_data(instance_directory)
        instance_slack_msg, instance_has_failed_tests = test_playbooks_results_to_slack_msg(instance_role,
                                                                                            succeeded_tests,
                                                                                            failed_tests,
                                                                                            skipped_integrations,
                                                                                            skipped_tests,
                                                                                            test_playbook_to_jira_mapping,
                                                                                            test_playbook_tickets_converted,
                                                                                            title,
                                                                                            pipeline_url)
        test_playbook_slack_msg += instance_slack_msg
        has_failed_tests |= instance_has_failed_tests

    return test_playbook_slack_msg, has_failed_tests


def unit_tests_results() -> list[dict[str, Any]]:
    if failing_tests_list := split_results_file(get_artifact_data(ROOT_ARTIFACTS_FOLDER, 'failed_lint_report.txt')):
        return [
            {
                "title": f'Failed Unit Tests - ({len(failing_tests_list)})',
                "value": ', '.join(failing_tests_list),
                "short": False,
            }
        ]
    return []


def bucket_upload_results(bucket_artifact_folder: Path,
                          marketplace_name: str,
                          should_include_private_packs: bool) -> list[dict[str, Any]]:
    steps_fields = []
    pack_results_path = bucket_artifact_folder / BucketUploadFlow.PACKS_RESULTS_FILE_FOR_SLACK

    logging.info(f'retrieving upload data from "{pack_results_path}"')
    successful_packs, _, failed_packs, successful_private_packs, _ = get_upload_data(
        pack_results_path.as_posix(), BucketUploadFlow.UPLOAD_PACKS_TO_MARKETPLACE_STORAGE
    )
    if successful_packs:
        steps_fields += [{
            'title': f'Successful {marketplace_name} Packs:',
            'value': ', '.join(sorted({*successful_packs}, key=lambda s: s.lower())),
            'short': False
        }]

    if failed_packs:
        steps_fields += [{
            'title': f'Failed {marketplace_name} Packs:',
            'value': ', '.join(sorted({*failed_packs}, key=lambda s: s.lower())),
            'short': False
        }]

    if successful_private_packs and should_include_private_packs:
        # No need to indicate the marketplace name as private packs only upload to xsoar marketplace.
        steps_fields += [{
            'title': 'Successful Private Packs:',
            'value': ', '.join(sorted({*successful_private_packs}, key=lambda s: s.lower())),
            'short': False
        }]

    return steps_fields


def construct_slack_msg(triggering_workflow: str,
                        pipeline_url: str,
                        pipeline_failed_jobs: list[ProjectPipelineJob],
                        pull_request: GithubPullRequest | None) -> list[dict[str, Any]]:
    # report failing jobs
    content_fields = []

    failed_jobs_names = {job.name: job.web_url for job in pipeline_failed_jobs}
    if failed_jobs_names:
        failed_jobs = [slack_link(url, name) for name, url in sorted(failed_jobs_names.items())]
        content_fields.append({
            "title": f'Failed Jobs - ({len(failed_jobs_names)})',
            "value": '\n'.join(failed_jobs),
            "short": False
        })

    if pull_request:
        content_fields.append({
            "title": "Pull Request",
            "value": slack_link(pull_request.data['html_url'], replace_escape_characters(pull_request.data['title'])),
            "short": False
        })

    # report failing unit-tests
    triggering_workflow_lower = triggering_workflow.lower()
    failed_jobs_or_workflow_title = {job_name.lower() for job_name in failed_jobs_names}
    failed_jobs_or_workflow_title.add(triggering_workflow_lower)

    if any(substr in means_include_unittests_results
           for substr in UNIT_TESTS_WORKFLOW_SUBSTRINGS
           for means_include_unittests_results in failed_jobs_or_workflow_title):
        content_fields += unit_tests_results()

    # report pack updates
    if 'upload' in triggering_workflow_lower:
        content_fields += bucket_upload_results(ARTIFACTS_FOLDER_XSOAR_SERVER_TYPE, "XSOAR", True)
        content_fields += bucket_upload_results(ARTIFACTS_FOLDER_XSOAR_SAAS_SERVER_TYPE, "XSOAR SAAS", True)
        content_fields += bucket_upload_results(ARTIFACTS_FOLDER_XSIAM_SERVER_TYPE, "XSIAM", False)
        content_fields += bucket_upload_results(ARTIFACTS_FOLDER_XPANSE_SERVER_TYPE, "XPANSE", False)

    slack_msg_append = []
    has_failed_tests = False
    # report failing test-playbooks and test modeling rules.
    if triggering_workflow in {CONTENT_NIGHTLY, CONTENT_PR, CONTENT_MERGE}:
        test_playbooks_slack_msg_xsoar, test_playbooks_has_failure_xsoar = test_playbooks_results(ARTIFACTS_FOLDER_XSOAR,
                                                                                                  pipeline_url, title="XSOAR")
        test_playbooks_slack_msg_xsiam, test_playbooks_has_failure_xsiam = test_playbooks_results(ARTIFACTS_FOLDER_XSIAM,
                                                                                                  pipeline_url, title="XSIAM")
        test_modeling_rules_slack_msg_xsiam, test_modeling_rules_has_failure_xsiam = test_modeling_rules_results(
            ARTIFACTS_FOLDER_XSIAM, pipeline_url, title="XSIAM")
        slack_msg_append += test_playbooks_slack_msg_xsoar + test_playbooks_slack_msg_xsiam + test_modeling_rules_slack_msg_xsiam
        has_failed_tests |= (test_playbooks_has_failure_xsoar or test_playbooks_has_failure_xsiam
                             or test_modeling_rules_has_failure_xsiam)
        slack_msg_append += missing_content_packs_test_conf(ARTIFACTS_FOLDER_XSOAR_SERVER_TYPE)
    if triggering_workflow == CONTENT_NIGHTLY:
        # The coverage Slack message is only relevant for nightly and not for PRs.
        slack_msg_append += construct_coverage_slack_msg()

    title = triggering_workflow

    if pull_request:
        pr_number = pull_request.data['number']
        pr_title = replace_escape_characters(pull_request.data['title'])
        title += f' (PR#{pr_number} - {pr_title})'

    # In case we have failed tests we override the color only in case all the pipeline jobs have passed.
    if has_failed_tests:
        title_append = " [Has Failed Tests]"
        color = 'warning'
    else:
        title_append = ""
        color = 'good'

    if pipeline_failed_jobs:
        title += ' - Failure'
        color = 'danger'
    else:
        title += ' - Success'
        # No color is needed in case of success, as it's controlled by the color of the test failures' indicator.

    title += title_append
    title += f' - @{CI_SERVER_HOST}' if CI_SERVER_HOST else ''
    return [{
        'fallback': title,
        'color': color,
        'title': title,
        'title_link': pipeline_url,
        'fields': content_fields
    }] + slack_msg_append


def missing_content_packs_test_conf(artifact_folder: Path) -> list[dict[str, Any]]:
    if missing_packs_list := split_results_file(get_artifact_data(artifact_folder,
                                                                  'missing_content_packs_test_conf.txt')):
        title = f"Notice - Missing packs - ({len(missing_packs_list)})"
        return [{
            'fallback': title,
            'color': 'warning',
            'title': title,
            'fields': [
                {
                    "title": "The following packs exist in content-test-conf, but not in content",
                    "value": ', '.join(missing_packs_list),
                    "short": False
                }
            ]
        }]
    return []


def collect_pipeline_data(gitlab_client: Gitlab,
                          project_id: str,
                          pipeline_id: str) -> tuple[str, list[ProjectPipelineJob]]:
    project = gitlab_client.projects.get(int(project_id))
    pipeline = project.pipelines.get(int(pipeline_id))

    failed_jobs: list[ProjectPipelineJob] = []
    for job in pipeline.jobs.list(iterator=True):
        logging.info(f'status of gitlab job with id {job.id} and name {job.name} is {job.status}')
        if job.status == 'failed':
            logging.info(f'collecting failed job {job.name}')
            logging.info(f'pipeline associated with failed job is {job.pipeline.get("web_url")}')
            failed_jobs.append(job)  # type: ignore[arg-type]

    return pipeline.web_url, failed_jobs


def construct_coverage_slack_msg() -> list[dict[str, Any]]:
    coverage_today = get_total_coverage(filename=(ROOT_ARTIFACTS_FOLDER / "coverage_report" / "coverage-min.json").as_posix())
    coverage_yesterday = get_total_coverage(date=datetime.now() - timedelta(days=1))
    # The artifacts are kept for 30 days, so we can get the coverage for the last month.
    coverage_last_month = get_total_coverage(date=datetime.now() - timedelta(days=30))
    color = 'good' if coverage_today >= coverage_yesterday else 'danger'
    title = (f'Content code coverage: {coverage_today:.3f}% (Yesterday: {coverage_yesterday:.3f}%, '
             f'Last month: {coverage_last_month:.3f}%)')

    return [{
        'fallback': title,
        'color': color,
        'title': title,
    }]


def build_link_to_message(response: SlackResponse) -> str:
    if SLACK_WORKSPACE_NAME and response.status_code == requests.codes.ok:
        data: dict = response.data  # type: ignore[assignment]
        channel_id: str = data['channel']
        message_ts: str = data['ts'].replace('.', '')
        return f"https://{SLACK_WORKSPACE_NAME}.slack.com/archives/{channel_id}/p{message_ts}"
    return ""


def main():
    install_logging('Slack_Notifier.log')
    options = options_handler()
    triggering_workflow = options.triggering_workflow  # ci workflow type that is triggering the slack notifier
    pipeline_id = options.pipeline_id
    project_id = options.gitlab_project_id
    server_url = options.url
    ci_token = options.ci_token
    computed_slack_channel = options.slack_channel
    gitlab_client = Gitlab(server_url, private_token=ci_token)
    slack_token = options.slack_token
    slack_client = WebClient(token=slack_token)

    logging.info(f"Sending Slack message for pipeline {pipeline_id} in project {project_id} on server {server_url} "
                 f"triggering workflow:'{triggering_workflow}' allowing failure:{options.allow_failure} "
                 f"slack channel:{computed_slack_channel}")
    pull_request = None
    if options.current_branch != DEFAULT_BRANCH:
        try:
            branch = options.current_branch
            if triggering_workflow == BUCKET_UPLOAD and BUCKET_UPLOAD_BRANCH_SUFFIX in branch:
                branch = branch[:branch.find(BUCKET_UPLOAD_BRANCH_SUFFIX)]
            logging.info(f"Searching for pull request for origin branch:{options.current_branch} and calculated branch:{branch}")
            pull_request = GithubPullRequest(
                options.github_token,
                branch=branch,
                fail_on_error=True,
                verify=False,
            )
            author = pull_request.data.get('user', {}).get('login')
            if triggering_workflow in {BUCKET_UPLOAD}:
                logging.info(f"Not supporting custom Slack channel for {triggering_workflow} workflow")
            else:
                # This feature is only supported for content nightly and content pr workflows.
                computed_slack_channel = f"{computed_slack_channel}{author}"
            logging.info(f"Sending slack message to channel {computed_slack_channel} for "
                         f"Author:{author} of PR#{pull_request.data.get('number')}")
        except Exception:
            logging.error(f'Failed to get pull request data for branch {options.current_branch}')
    else:
        logging.info("Not a pull request build, skipping PR comment")

    pipeline_url, pipeline_failed_jobs = collect_pipeline_data(gitlab_client, project_id, pipeline_id)
    slack_msg_data = construct_slack_msg(triggering_workflow, pipeline_url, pipeline_failed_jobs, pull_request)

    with contextlib.suppress(Exception):
        output_file = ROOT_ARTIFACTS_FOLDER / 'slack_msg.json'
        logging.info(f'Writing Slack message to {output_file}')
        with open(output_file, 'w') as f:
            f.write(json.dumps(slack_msg_data, indent=4, sort_keys=True, default=str))
        logging.info(f'Successfully wrote Slack message to {output_file}')

    try:
        response = slack_client.chat_postMessage(
            channel=computed_slack_channel, attachments=slack_msg_data, username=SLACK_USERNAME
        )
        link = build_link_to_message(response)
        logging.info(f'Successfully sent Slack message to channel {computed_slack_channel} link: {link}')
    except Exception:
        if strtobool(options.allow_failure):
            logging.warning(f'Failed to send Slack message to channel {computed_slack_channel} not failing build')
        else:
            logging.exception(f'Failed to send Slack message to channel {computed_slack_channel}')
            sys.exit(1)


if __name__ == '__main__':
    main()
