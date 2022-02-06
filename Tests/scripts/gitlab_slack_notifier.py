import argparse
from datetime import datetime, timedelta
import logging
import os
from typing import Tuple, Optional
import gitlab
from slack import WebClient as SlackClient

from Tests.Marketplace.marketplace_services import get_upload_data
from Tests.Marketplace.marketplace_constants import BucketUploadFlow
from Tests.scripts.utils.log_util import install_logging
from demisto_sdk.commands.coverage_analyze.tools import get_total_coverage

DEMISTO_GREY_ICON = 'https://3xqz5p387rui1hjtdv1up7lw-wpengine.netdna-ssl.com/wp-content/' \
                    'uploads/2018/07/Demisto-Icon-Dark.png'
ROOT_ARTIFACTS_FOLDER = os.getenv('ARTIFACTS_FOLDER', './artifacts')
ARTIFACTS_FOLDER_XSOAR = os.getenv('ARTIFACTS_FOLDER_XSOAR', './artifacts/xsoar')
ARTIFACTS_FOLDER_MPV2 = os.getenv('ARTIFACTS_FOLDER_MPV2', './artifacts/marketplacev2')
CONTENT_CHANNEL = 'dmst-content-team'
GITLAB_PROJECT_ID = os.getenv('CI_PROJECT_ID') or 2596  # the default is the id of the content repo in code.pan.run
GITLAB_SERVER_URL = os.getenv('CI_SERVER_URL', 'https://code.pan.run')  # disable-secrets-detection
CONTENT_NIGHTLY = 'Content Nightly'
BUCKET_UPLOAD = 'Upload Packs to Marketplace Storage'
SDK_NIGHTLY = 'Demisto SDK Nightly'
PRIVATE_NIGHTLY = 'Private Nightly'
WORKFLOW_TYPES = {CONTENT_NIGHTLY, SDK_NIGHTLY, BUCKET_UPLOAD, PRIVATE_NIGHTLY}


def options_handler():
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
    options = parser.parse_args()

    return options


def get_artifact_data(artifact_folder, artifact_relative_path: str) -> Optional[str]:
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
        file_name = os.path.join(artifact_folder, artifact_relative_path)
        if os.path.isfile(file_name):
            logging.info(f'Extracting {artifact_relative_path}')
            with open(file_name, 'r') as file_data:
                artifact_data = file_data.read()
        else:
            logging.info(f'Did not find {artifact_relative_path} file')
    except Exception:
        logging.exception(f'Error getting {artifact_relative_path} file')
    return artifact_data


def test_playbooks_results(artifact_folder):
    failed_tests_data = get_artifact_data(artifact_folder, 'failed_tests.txt')
    failed_tests = failed_tests_data.split('\n') if failed_tests_data else []

    skipped_tests_data = get_artifact_data(artifact_folder, 'skipped_tests.txt')
    skipped_tests = skipped_tests_data.split('\n') if skipped_tests_data else []

    skipped_integrations_data = get_artifact_data(artifact_folder, 'skipped_tests.txt')
    skipped_integrations = skipped_integrations_data.split('\n') if skipped_integrations_data else []

    content_team_fields = []
    if failed_tests:
        field_failed_tests = {
            "title": "Failed tests - ({})".format(len(failed_tests)),
            "value": '\n'.join(failed_tests),
            "short": False
        }
        content_team_fields.append(field_failed_tests)

    if skipped_tests:
        field_skipped_tests = {
            "title": "Skipped tests - ({})".format(len(skipped_tests)),
            "value": '',
            "short": True
        }
        content_team_fields.append(field_skipped_tests)

    if skipped_integrations:
        field_skipped_integrations = {
            "title": "Skipped integrations - ({})".format(len(skipped_integrations)),
            "value": '',
            "short": True
        }
        content_team_fields.append(field_skipped_integrations)

    return content_team_fields


def unit_tests_results():
    failing_tests = get_artifact_data(ROOT_ARTIFACTS_FOLDER, 'failed_lint_report.txt')
    slack_results = []
    if failing_tests:
        failing_test_list = failing_tests.split('\n')
        slack_results.append({
            "title": f'{"Failed Unit Tests"} - ({len(failing_test_list)})',
            "value": '\n'.join(failing_test_list),
            "short": False
        })
    return slack_results


def bucket_upload_results(bucket_artifact_folder):
    steps_fields = []
    pack_results_path = os.path.join(bucket_artifact_folder, BucketUploadFlow.PACKS_RESULTS_FILE)
    marketplace_name = os.path.basename(bucket_artifact_folder).upper()

    logging.info(f'retrieving upload data from "{pack_results_path}"')
    successful_packs, failed_packs, successful_private_packs, _ = get_upload_data(
        pack_results_path, BucketUploadFlow.UPLOAD_PACKS_TO_MARKETPLACE_STORAGE
    )
    if successful_packs:
        steps_fields += [{
            'title': f'Successful {marketplace_name} Packs:',
            'value': '\n'.join(sorted([pack_name for pack_name in {*successful_packs}], key=lambda s: s.lower())),
            'short': False
        }]

    if failed_packs:
        steps_fields += [{
            'title': f'Failed {marketplace_name} Packs:',
            'value': '\n'.join(sorted([pack_name for pack_name in {*failed_packs}], key=lambda s: s.lower())),
            'short': False
        }]

    if successful_private_packs:
        # No need to indicate the marketplace name as private packs only upload to xsoar marketplace.
        steps_fields += [{
            'title': 'Successful Private Packs:',
            'value': '\n'.join(sorted([pack_name for pack_name in {*successful_private_packs}],
                                      key=lambda s: s.lower())),
            'short': False
        }]

    return steps_fields


def construct_slack_msg(triggering_workflow, pipeline_url, pipeline_failed_jobs) -> list:
    title = triggering_workflow
    if pipeline_failed_jobs:
        title += ' - Failure'
        color = 'danger'
    else:
        title += ' - Success'
        color = 'good'

    # report failing jobs
    content_fields = []
    coverage_slack_msg = None
    failed_jobs_names = {job.name for job in pipeline_failed_jobs}
    if failed_jobs_names:
        content_fields.append({
            "title": f'Failed Jobs - ({len(failed_jobs_names)})',
            "value": '\n'.join(failed_jobs_names),
            "short": False
        })

    # report failing unit-tests
    triggering_workflow_lower = triggering_workflow.lower()
    check_unittests_substrings = {'lint', 'unit', 'demisto sdk nightly'}
    failed_jobs_or_workflow_title = {job_name.lower() for job_name in failed_jobs_names}
    failed_jobs_or_workflow_title.add(triggering_workflow_lower)
    for means_include_unittests_results in failed_jobs_or_workflow_title:
        if any({substr in means_include_unittests_results for substr in check_unittests_substrings}):
            content_fields += unit_tests_results()
            break

    # report pack updates
    if 'upload' in triggering_workflow_lower:
        content_fields += bucket_upload_results(ARTIFACTS_FOLDER_XSOAR)
        content_fields += bucket_upload_results(ARTIFACTS_FOLDER_MPV2)

    # report failing test-playbooks
    if 'content nightly' in triggering_workflow_lower:
        content_fields += test_playbooks_results(ARTIFACTS_FOLDER_XSOAR)
        coverage_slack_msg = construct_coverage_slack_msg()

    slack_msg = [{
        'fallback': title,
        'color': color,
        'title': title,
        'title_link': pipeline_url,
        'fields': content_fields
    }]
    slack_msg.append(coverage_slack_msg) if coverage_slack_msg else None
    return slack_msg


def collect_pipeline_data(gitlab_client, project_id, pipeline_id) -> Tuple[str, list]:
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


def construct_coverage_slack_msg():
    coverage_today = get_total_coverage(filename=os.path.join(ARTIFACTS_FOLDER_XSOAR, 'coverage_report/coverage-min.json'))
    yasterday = datetime.now() - timedelta(days=1)
    coverage_yasterday = get_total_coverage(date=yasterday)
    color = 'good' if coverage_today >= coverage_yasterday else 'danger'
    title = f'content code coverage: {coverage_today}'

    return {
        'fallback': title,
        'color': color,
        'title': title,
    }


def main():
    install_logging('Slack_Notifier.log')
    options = options_handler()
    server_url = options.url
    slack_token = options.slack_token
    ci_token = options.ci_token
    project_id = options.gitlab_project_id
    pipeline_id = options.pipeline_id
    triggering_workflow = options.triggering_workflow  # ci workflow type that is triggering the slack notifier
    slack_channel = options.slack_channel
    gitlab_client = gitlab.Gitlab(server_url, private_token=ci_token)
    pipeline_url, pipeline_failed_jobs = collect_pipeline_data(gitlab_client, project_id, pipeline_id)
    slack_msg_data = construct_slack_msg(triggering_workflow, pipeline_url, pipeline_failed_jobs)
    slack_client = SlackClient(slack_token)
    username = 'Content GitlabCI'
    slack_client.api_call(
        "chat.postMessage",
        json={
            'channel': slack_channel,
            'username': username,
            'as_user': 'False',
            'attachments': slack_msg_data
        }
    )


if __name__ == '__main__':
    main()
