import argparse
import logging
import os
import sys
from datetime import datetime, timedelta
from distutils.util import strtobool
from pathlib import Path
from typing import Any

import gitlab
from demisto_sdk.commands.coverage_analyze.tools import get_total_coverage
from junitparser import TestSuite, JUnitXml
from slack_sdk import WebClient

from Tests.Marketplace.marketplace_constants import BucketUploadFlow
from Tests.Marketplace.marketplace_services import get_upload_data
from Tests.scripts.common import CONTENT_NIGHTLY, CONTENT_PR, TEST_NATIVE_CANDIDATE, WORKFLOW_TYPES
from Tests.scripts.github_client import GithubPullRequest
from Tests.scripts.test_playbooks import get_instance_directories
from Tests.scripts.utils.log_util import install_logging

ROOT_ARTIFACTS_FOLDER = Path(os.getenv('ARTIFACTS_FOLDER', './artifacts'))
ARTIFACTS_FOLDER_XSOAR = Path(os.getenv('ARTIFACTS_FOLDER_XSOAR', './artifacts/xsoar'))
ARTIFACTS_FOLDER_MPV2 = Path(os.getenv('ARTIFACTS_FOLDER_MPV2', './artifacts/marketplacev2'))
ARTIFACTS_FOLDER_MPV2_INSTANCE = Path(os.getenv('ARTIFACTS_FOLDER_INSTANCE', './artifacts/marketplacev2/instance_xsiam'))
ARTIFACTS_FOLDER_XPANSE = Path(os.getenv('ARTIFACTS_FOLDER_XPANSE', './artifacts/xpanse'))
GITLAB_SERVER_URL = os.getenv('CI_SERVER_URL', 'https://code.pan.run')  # disable-secrets-detection
GITLAB_PROJECT_ID = os.getenv('CI_PROJECT_ID') or 2596  # the default is the id of the content repo in code.pan.run
CONTENT_CHANNEL = 'dmst-build-test'
SLACK_USERNAME = 'Content GitlabCI'
GITHUB_TOKEN = os.getenv('GITHUB_TOKEN', '')
CI_COMMIT_BRANCH = os.getenv('CI_COMMIT_BRANCH', '')
CI_COMMIT_SHA = os.getenv('CI_COMMIT_SHA', '')
DEFAULT_BRANCH = 'master'


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
        artifact_folder (str): Full path of the artifact root folder.
        artifact_relative_path (str): Relative path of an artifact file.

    Returns:
        (Optional[str]): data of the artifact as str if exists, None otherwise.
    """
    artifact_data = None
    try:
        file_name = artifact_folder / artifact_relative_path
        if os.path.isfile(file_name):
            logging.info(f'Extracting {artifact_relative_path}')
            with open(file_name) as file_data:
                artifact_data = file_data.read()
        else:
            logging.info(f'Did not find {artifact_relative_path} file')
    except Exception:
        logging.exception(f'Error getting {artifact_relative_path} file')
    return artifact_data


def get_failed_modeling_rule_name_from_test_suite(test_suite: TestSuite) -> str:

    properties = {prop.name: prop.value for prop in test_suite.properties()}

    return f"{properties['modeling_rule_file_name']} ({properties['pack_id']})"


def test_modeling_rules_results(artifact_folder: Path, title: str) -> list[dict[str, Any]]:
    failed_test_modeling_rules = artifact_folder / 'modeling_rules_results.xml'
    if not failed_test_modeling_rules.exists():
        return []
    xml = JUnitXml.fromfile(failed_test_modeling_rules.as_posix())
    content_team_fields = []
    failed_test_suites = []
    total_test_suites = 0
    for test_suite in xml.iterchildren(TestSuite):
        total_test_suites += 1
        if test_suite.failures or test_suite.errors:
            failed_test_suites.append(get_failed_modeling_rule_name_from_test_suite(test_suite))
    if failed_test_suites:
        content_team_fields.append({
            "title": f"{title} - Failed Tests Modeling rules - ({len(failed_test_suites)}/{total_test_suites})",
            "value": ' ,'.join(failed_test_suites),
            "short": False
        })
    else:
        content_team_fields.append({
            "title": f"{title} - All Test Modeling rules Passed - ({total_test_suites})",
            "value": '',
            "short": False
        })

    return content_team_fields


def test_playbooks_results_to_slack_msg(failed_tests: list[str],
                                        skipped_integrations: list[str],
                                        skipped_tests: list[str],
                                        title: str) -> list[dict[str, Any]]:
    content_team_fields = []
    if failed_tests:
        field_failed_tests = {
            "title": f"{title} - Failed Tests - ({len(failed_tests)})",
            "value": ', '.join(failed_tests),
            "short": False
        }
        content_team_fields.append(field_failed_tests)
    if skipped_tests:
        field_skipped_tests = {
            "title": f"{title} - Skipped Tests - ({len(skipped_tests)})",
            "value": '',
            "short": True
        }
        content_team_fields.append(field_skipped_tests)
    if skipped_integrations:
        field_skipped_integrations = {
            "title": f"{title} - Skipped Integrations - ({len(skipped_integrations)})",
            "value": '',
            "short": True
        }
        content_team_fields.append(field_skipped_integrations)
    return content_team_fields


def test_playbooks_results(artifact_folder: Path, title: str) -> list[dict[str, Any]]:

    instance_directories = get_instance_directories(artifact_folder)
    content_team_fields = []
    for instance_directory in instance_directories:
        failed_tests_data = get_artifact_data(instance_directory, 'failed_tests.txt')
        failed_tests = failed_tests_data.split('\n') if failed_tests_data else []

        skipped_tests_data = get_artifact_data(instance_directory, 'skipped_tests.txt')
        skipped_tests = skipped_tests_data.split('\n') if skipped_tests_data else []

        skipped_integrations_data = get_artifact_data(instance_directory, 'skipped_integrations.txt')
        skipped_integrations = skipped_integrations_data.split('\n') if skipped_integrations_data else []

        content_team_fields += test_playbooks_results_to_slack_msg(failed_tests, skipped_integrations, skipped_tests, title)

    if not content_team_fields:
        content_team_fields.append({
            "title": f"{title} - All Tests Playbooks Passed",
            "value": '',
            "short": False
        })

    return content_team_fields


def unit_tests_results() -> list[dict[str, Any]]:
    failing_tests = get_artifact_data(ROOT_ARTIFACTS_FOLDER, 'failed_lint_report.txt')
    slack_results = []
    if failing_tests:
        failing_test_list = failing_tests.split('\n')
        slack_results.append(
            {
                "title": f'Failed Unit Tests - ({len(failing_test_list)})',
                "value": ', '.join(failing_test_list),
                "short": False,
            }
        )
    return slack_results


def bucket_upload_results(bucket_artifact_folder: Path, should_include_private_packs: bool) -> list[dict[str, Any]]:
    steps_fields = []
    pack_results_path = bucket_artifact_folder / BucketUploadFlow.PACKS_RESULTS_FILE_FOR_SLACK
    marketplace_name = os.path.basename(bucket_artifact_folder).upper()

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
                        pipeline_failed_jobs: list,
                        pull_request: GithubPullRequest | None) -> list[dict[str, Any]]:
    # report failing jobs
    content_fields = []
    failed_jobs_names = {job.name for job in pipeline_failed_jobs}
    if failed_jobs_names:
        content_fields.append({
            "title": f'Failed Jobs - ({len(failed_jobs_names)})',
            "value": '\n'.join(failed_jobs_names),
            "short": False
        })

    # report failing unit-tests
    triggering_workflow_lower = triggering_workflow.lower()
    check_unittests_substrings = {'lint', 'unit', 'demisto sdk nightly', TEST_NATIVE_CANDIDATE.lower()}
    failed_jobs_or_workflow_title = {job_name.lower() for job_name in failed_jobs_names}
    failed_jobs_or_workflow_title.add(triggering_workflow_lower)
    for means_include_unittests_results in failed_jobs_or_workflow_title:
        if any(substr in means_include_unittests_results for substr in check_unittests_substrings):
            content_fields += unit_tests_results()
            break

    # report pack updates
    if 'upload' in triggering_workflow_lower:
        content_fields += bucket_upload_results(ARTIFACTS_FOLDER_XSOAR, True)
        content_fields += bucket_upload_results(ARTIFACTS_FOLDER_MPV2, False)
        content_fields += bucket_upload_results(ARTIFACTS_FOLDER_XPANSE, False)

    # report failing test-playbooks and test modeling rules.
    coverage_slack_msg = []
    if triggering_workflow in {CONTENT_NIGHTLY, CONTENT_PR}:
        content_fields += test_playbooks_results(ARTIFACTS_FOLDER_XSOAR, title="XSOAR")
        content_fields += test_playbooks_results(ARTIFACTS_FOLDER_MPV2, title="XSIAM")
        content_fields += test_modeling_rules_results(ARTIFACTS_FOLDER_MPV2, title="XSIAM")
        content_fields += missing_content_packs_test_conf(ARTIFACTS_FOLDER_XSOAR)
        coverage_slack_msg += construct_coverage_slack_msg()

    title = triggering_workflow
    if pull_request:
        pr_number = pull_request.data.get('number')
        pr_title = pull_request.data.get('title')
        title += f' (PR#{pr_number} - {pr_title})'

    if pipeline_failed_jobs:
        title += ' - Failure'
        color = 'danger'
    else:
        title += ' - Success'
        color = 'good'
    slack_msg = [{
        'fallback': title,
        'color': color,
        'title': title,
        'title_link': pipeline_url,
        'fields': content_fields
    }] + coverage_slack_msg
    return slack_msg


def missing_content_packs_test_conf(artifact_folder: Path) -> list[dict[str, Any]]:
    missing_packs = get_artifact_data(artifact_folder, 'missing_content_packs_test_conf.txt')
    content_fields = []
    if missing_packs:
        missing_packs_lst = missing_packs.split('\n')
        content_fields.append({
            "title": f"Notice - Missing packs - ({len(missing_packs_lst)})",
            "value": f"The following packs exist in content-test-conf, but not in content: {', '.join(missing_packs_lst)}",
            "short": False
        })
    return content_fields


def collect_pipeline_data(gitlab_client: gitlab.Gitlab,
                          project_id: str,
                          pipeline_id: str) -> tuple[str, list]:
    project = gitlab_client.projects.get(int(project_id))
    pipeline = project.pipelines.get(int(pipeline_id))
    jobs = pipeline.jobs.list()

    failed_jobs = []
    for job in jobs:
        logging.info(f'status of gitlab job with id {job.id} and name {job.name} is {job.status}')
        if job.status == 'failed':
            logging.info(f'collecting failed job {job.name}')
            logging.info(f'pipeline associated with failed job is {job.pipeline.get("web_url")}')
            failed_jobs.append(job)

    return pipeline.web_url, failed_jobs


def construct_coverage_slack_msg() -> list[dict[str, Any]]:
    coverage_today = get_total_coverage(filename=(ROOT_ARTIFACTS_FOLDER / 'coverage_report/coverage-min.json').as_posix())
    yesterday = datetime.now() - timedelta(days=1)
    coverage_yesterday = get_total_coverage(date=yesterday)
    color = 'good' if coverage_today >= coverage_yesterday else 'danger'
    title = f'content code coverage: {coverage_today:.3f}%'

    return [{
        'fallback': title,
        'color': color,
        'title': title,
    }]


def main():
    install_logging('Slack_Notifier.log')
    options = options_handler()
    server_url = options.url
    slack_token = options.slack_token
    ci_token = options.ci_token
    project_id = options.gitlab_project_id
    pipeline_id = options.pipeline_id
    triggering_workflow = options.triggering_workflow  # ci workflow type that is triggering the slack notifier
    computed_slack_channel = options.slack_channel.lower()
    gitlab_client = gitlab.Gitlab(server_url, private_token=ci_token)
    slack_client = WebClient(token=slack_token)

    if options.current_branch != DEFAULT_BRANCH:
        pull_request = GithubPullRequest(
            options.github_token,
            sha1=options.current_sha,
            branch=options.current_branch,
            fail_on_error=True,
            verify=False,
        )
        author = pull_request.data.get('user', {}).get('login')
        computed_slack_channel = f"{computed_slack_channel}{author}"
        logging.info(f"Sending slack message to channel {computed_slack_channel} for "
                     f"Author:{author} of PR#{pull_request.data.get('number')}")
    else:
        pull_request = None
        logging.info("Not a pull request build, skipping PR comment")

    pipeline_url, pipeline_failed_jobs = collect_pipeline_data(gitlab_client, project_id, pipeline_id)
    slack_msg_data = construct_slack_msg(triggering_workflow, pipeline_url, pipeline_failed_jobs, pull_request)

    try:
        slack_client.chat_postMessage(
            channel=computed_slack_channel, attachments=slack_msg_data, username=SLACK_USERNAME
        )
    except Exception:
        if strtobool(options.allow_failure):
            logging.warning(f'Failed to send slack message to channel {computed_slack_channel}')
        else:
            logging.exception(f'Failed to send slack message to channel {computed_slack_channel}')
            sys.exit(1)


if __name__ == '__main__':
    main()
