import argparse
import logging
import os
from typing import Tuple

import gitlab
from slack import WebClient as SlackClient

from Tests.Marketplace.marketplace_services import get_upload_data
from Tests.Marketplace.marketplace_constants import BucketUploadFlow
from Tests.scripts.utils.log_util import install_logging
from Tests.scripts.slack_notifier import get_fields, get_artifact_data

DEMISTO_GREY_ICON = 'https://3xqz5p387rui1hjtdv1up7lw-wpengine.netdna-ssl.com/wp-content/' \
                    'uploads/2018/07/Demisto-Icon-Dark.png'
ARTIFACTS_FOLDER = os.getenv('ARTIFACTS_FOLDER', './artifacts')
ENV_RESULTS_PATH = os.getenv('ENV_RESULTS_PATH', os.path.join(ARTIFACTS_FOLDER, 'env_results.json'))
PACK_RESULTS_PATH = os.path.join(ARTIFACTS_FOLDER, BucketUploadFlow.PACKS_RESULTS_FILE)
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
        '-f', '--env_results_path', help='The env results file containing the dns address', default=ENV_RESULTS_PATH
    )
    parser.add_argument('-ca', '--ci_artifacts', help="The path to the ci artifacts directory")
    parser.add_argument(
        '-ch', '--slack_channel', help='The slack channel in which to send the notification', default=CONTENT_CHANNEL
    )
    parser.add_argument('-gp', '--gitlab_project_id', help='The gitlab project id', default=GITLAB_PROJECT_ID)
    parser.add_argument(
        '-tw', '--triggering-workflow', help='The type of ci pipeline workflow the notifier is reporting on',
        choices=WORKFLOW_TYPES)
    options = parser.parse_args()

    return options


def unit_tests_results():
    failing_unit_tests = get_artifact_data('failed_lint_report.txt')
    slack_results = []
    if failing_unit_tests:
        failing_unit_tests = failing_unit_tests.split('\n')  # type: ignore[assignment]
        slack_results.append({
            "title": f'{"Failed Unit Tests"} - ({len(failing_unit_tests)})',
            "value": '\n'.join(failing_unit_tests),
            "short": False
        })
    return slack_results


def test_playbooks_results():
    playbooks_data, _, _ = get_fields()
    return playbooks_data


def bucket_upload_results():
    steps_fields = []
    logging.info(f'retrieving upload data from "{PACK_RESULTS_PATH}"')
    successful_packs, failed_packs, successful_private_packs, _ = get_upload_data(
        PACK_RESULTS_PATH, BucketUploadFlow.UPLOAD_PACKS_TO_MARKETPLACE_STORAGE
    )
    if successful_packs:
        steps_fields += [{
            "title": "Successful Packs:",
            "value": "\n".join(sorted([pack_name for pack_name in {*successful_packs}], key=lambda s: s.lower())),
            "short": False
        }]
    if failed_packs:
        steps_fields += [{
            "title": "Failed Packs:",
            "value": "\n".join(sorted([pack_name for pack_name in {*failed_packs}], key=lambda s: s.lower())),
            "short": False
        }]
    if successful_private_packs:
        steps_fields += [{
            "title": "Successful Private Packs:",
            "value": "\n".join(sorted([pack_name for pack_name in {*successful_private_packs}],
                                      key=lambda s: s.lower())),
            "short": False
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

    content_fields = []
    failed_jobs_names = {job.name for job in pipeline_failed_jobs}
    if failed_jobs_names:
        content_fields.append({
            "title": f'{"Failed Jobs"} - ({len(failed_jobs_names)})',
            "value": '\n'.join(failed_jobs_names),
            "short": False
        })

    triggering_workflow_lower = triggering_workflow.lower()
    check_unittests_substrings = {'lint', 'unit', 'demisto sdk nightly'}
    failed_jobs_or_workflow_title = {job_name.lower() for job_name in failed_jobs_names}
    failed_jobs_or_workflow_title.add(triggering_workflow_lower)
    for means_include_unittests_results in failed_jobs_or_workflow_title:
        if any({substr in means_include_unittests_results for substr in check_unittests_substrings}):
            content_fields += unit_tests_results()
            break
    if 'upload' in triggering_workflow_lower:
        content_fields += bucket_upload_results()
    if 'content nightly' in triggering_workflow_lower:
        content_fields += test_playbooks_results()

    slack_msg = [{
        'fallback': title,
        'color': color,
        'title': title,
        'title_link': pipeline_url,
        'fields': content_fields
    }]
    return slack_msg


def collect_pipeline_data(gitlab_client, project_id, pipeline_id) -> Tuple[str, list]:
    failed_jobs = []
    project = gitlab_client.projects.get(int(project_id))
    pipeline = project.pipelines.get(int(pipeline_id))
    jobs = pipeline.jobs.list()
    for job in jobs:
        logging.info(f'status of gitlab job with id {job.id} and name {job.name} is {job.status}')
        if job.status == 'failed':
            logging.info(f'collecting failed job {job.name}')
            logging.info(f'pipeline associated with failed job is {job.pipeline.get("web_url")}')
            failed_jobs.append(job)
    return pipeline.web_url, failed_jobs


def main():
    install_logging('Slack_Notifier.log')
    options = options_handler()
    server_url = options.url
    slack_token = options.slack_token
    ci_token = options.ci_token
    # env_results_file_name = options.env_results_file_name
    # ci_artifacts_path = options.ci_artifacts
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
