import argparse
import json
import logging
import os
import re
import sys

import requests
import gitlab
from circleci.api import Api as circle_api
from slack import WebClient as SlackClient

from Tests.Marketplace.marketplace_services import get_upload_data
from Tests.Marketplace.marketplace_constants import BucketUploadFlow
from Tests.scripts.utils.log_util import install_logging
from demisto_sdk.commands.common.tools import str2bool, run_command

DEMISTO_GREY_ICON = 'https://3xqz5p387rui1hjtdv1up7lw-wpengine.netdna-ssl.com/wp-content/' \
                    'uploads/2018/07/Demisto-Icon-Dark.png'
ARTIFACTS_FOLDER = os.getenv('ARTIFACTS_FOLDER', './artifacts')
UNITTESTS_TYPE = 'unittests'
TEST_PLAYBOOK_TYPE = 'test_playbooks'
SDK_UNITTESTS_TYPE = 'sdk_unittests'
SDK_FAILED_STEPS_TYPE = 'sdk_failed_steps'
SDK_RUN_AGAINST_FAILED_STEPS_TYPE = 'sdk_run_against_failed_steps'
SDK_BUILD_TITLE = 'SDK Nightly Build'
SDK_XSOAR_BUILD_TITLE = 'Demisto SDK Nightly - Run Against Cortex XSOAR'
CONTENT_CHANNEL = 'dmst-content-team'
DMST_SDK_NIGHTLY_GITLAB_JOBS_PREFIX = 'demisto-sdk-nightly'
SDK_NIGHTLY_CIRCLE_OPTS = {
    SDK_UNITTESTS_TYPE, SDK_FAILED_STEPS_TYPE, SDK_RUN_AGAINST_FAILED_STEPS_TYPE
}


def get_failed_steps_list():
    options = options_handler()
    if options.gitlab_server:
        return get_gitlab_failed_steps(options.ci_token, options.buildNumber, options.gitlab_server,
                                       options.gitlab_project_id)
    return get_circle_failed_steps(options.ci_token, options.buildNumber)


def get_circle_failed_steps(ci_token, build_number):
    failed_steps_list = []
    circle_client = circle_api(ci_token)
    vcs_type = 'github'
    build_report = circle_client.get_build_info(username='demisto', project='content', build_num=build_number,
                                                vcs_type=vcs_type)
    for step in build_report.get('steps', []):
        step_name = step.get('name', '')
        actions = step.get('actions', [])
        for action in actions:
            action_status = action.get('status', '')
            if action_status and action_status == 'failed':
                action_name = action.get('name', '')
                if action_name != step_name:
                    failed_steps_list.append(f'{step_name}: {action_name}')
                else:
                    failed_steps_list.append(f'{step_name}')

    return failed_steps_list


def get_gitlab_failed_steps(ci_token, build_number, server_url, project_id):
    failed_steps_list = []
    gitlab_client = gitlab.Gitlab(server_url, private_token=ci_token)
    project = gitlab_client.projects.get(int(project_id))
    job = project.jobs.get(int(build_number))
    logging.info(f'status of gitlab job with id {job.id} and name {job.name} is {job.status}')
    if job.status == 'failed':
        logging.info(f'collecting failed job {job.name}')
        logging.info(f'pipeline associated with failed job is {job.pipeline.get("web_url")}')
        failed_steps_list.append(f'{job.name}')

    return failed_steps_list


def http_request(url, params_dict=None, verify=True, text=False):
    res = requests.request("GET",
                           url,
                           verify=verify,
                           params=params_dict,
                           )
    res.raise_for_status()

    if text:
        return res.text
    return res.json()


def options_handler():
    parser = argparse.ArgumentParser(description='Parser for slack_notifier args')
    parser.add_argument('-n', '--nightly', type=str2bool, help='is nightly build?', required=True)
    parser.add_argument('-u', '--url', help='The url of the current build', required=True)
    parser.add_argument('-b', '--buildNumber', help='The build number', required=True)
    parser.add_argument('-s', '--slack', help='The token for slack', required=True)
    parser.add_argument('-c', '--ci_token', help='The token for circleci/gitlab', required=True)
    parser.add_argument('-t', '--test_type', help='unittests or test_playbooks or sdk_unittests or sdk_failed_steps'
                                                  'or bucket_upload')
    parser.add_argument('-f', '--env_results_file_name', help='The env results file containing the dns address')
    parser.add_argument('-bu', '--bucket_upload', help='is bucket upload build?', required=True, type=str2bool)
    parser.add_argument('-ca', '--ci_artifacts', help="The path to the ci artifacts directory")
    parser.add_argument('-j', '--job_name', help='The job name that is running the slack notifier')
    parser.add_argument('-ch', '--slack_channel', help='The slack channel in which to send the notification')
    parser.add_argument('-g', '--gitlab_server', help='The gitlab server running the script, if left empty circleci '
                                                      'is assumed.')
    parser.add_argument('-gp', '--gitlab_project_id', help='The gitlab project_id. Only needed if the script is ran '
                                                           'from gitlab.')
    options = parser.parse_args()

    return options


def get_failing_unit_tests_file_data():
    failing_ut_list = None
    try:
        file_name = f'{ARTIFACTS_FOLDER}/failed_lint_report.txt'
        if os.path.isfile(file_name):
            logging.info('Extracting lint_report')
            with open(file_name, 'r') as failed_unittests_file:
                failing_ut = failed_unittests_file.readlines()
                failing_ut_list = [line.strip('\n') for line in failing_ut]
        else:
            logging.info('Did not find failed_lint_report.txt file')
    except Exception:
        logging.exception('Error getting failed_lint_report.txt file')
    return failing_ut_list


def get_entities_fields(entity_title, report_file_name=''):
    if 'lint' in report_file_name:  # lint case
        failed_entities = get_failing_unit_tests_file_data()
    else:
        failed_entities = get_failed_steps_list()
    entity_fields = []
    if failed_entities:
        entity_fields.append({
            "title": f'{entity_title} - ({len(failed_entities)})',
            "value": '\n'.join(failed_entities),
            "short": False
        })
    return entity_fields


def get_attachments_for_unit_test(build_url, is_sdk_build=False):
    unittests_fields = get_entities_fields(entity_title="Failed Unittests", report_file_name="failed_lint_report")
    color = 'good' if not unittests_fields else 'danger'
    if not unittests_fields:
        title = 'Content Nightly Unit Tests - Success' if not is_sdk_build else 'SDK Nightly Unit Tests - Success'
    else:
        title = 'Content Nightly Unit Tests - Failure' if not is_sdk_build else 'SDK Nightly Unit Tests - Failure'
    content_team_attachment = [{
        'fallback': title,
        'color': color,
        'title': title,
        'title_link': build_url,
        'fields': unittests_fields
    }]
    return content_team_attachment


def get_attachments_for_bucket_upload_flow(build_url, job_name, packs_results_file_path=None):
    steps_fields = get_entities_fields(entity_title="Failed Steps")
    color = 'good' if not steps_fields else 'danger'
    title = f'{BucketUploadFlow.BUCKET_UPLOAD_BUILD_TITLE} - Success' if not steps_fields \
        else f'{BucketUploadFlow.BUCKET_UPLOAD_BUILD_TITLE} - Failure'

    if job_name and color == 'danger':
        steps_fields = [{
            "title": f'Job Failed: {job_name}',
            "value": '',
            "short": False
        }] + steps_fields

    if job_name and job_name in BucketUploadFlow.UPLOAD_JOB_NAMES:
        successful_packs, failed_packs, successful_private_packs, _ = get_upload_data(
            packs_results_file_path, BucketUploadFlow.UPLOAD_PACKS_TO_MARKETPLACE_STORAGE
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

    if job_name and job_name not in BucketUploadFlow.UPLOAD_JOB_NAMES and color == 'good':
        logging.info('On bucket upload flow we are not notifying on jobs that are not Upload Packs. exiting...')
        sys.exit(0)

    container_build_url = build_url + '#queue-placeholder/containers/0'
    content_team_attachment = [{
        'fallback': title,
        'color': color,
        'title': title,
        'title_link': container_build_url,
        'fields': steps_fields
    }]
    return content_team_attachment


def get_attachments_for_all_steps(build_url, build_title):
    steps_fields = get_entities_fields(entity_title="Failed Steps")
    color = 'good' if not steps_fields else 'danger'
    title = f'{build_title} - Success' if not steps_fields else f'{build_title} - Failure'

    container_build_url = build_url + '#queue-placeholder/containers/0'
    content_team_attachment = [{
        'fallback': title,
        'color': color,
        'title': title,
        'title_link': container_build_url,
        'fields': steps_fields
    }]
    return content_team_attachment


def get_attachments_for_test_playbooks(build_url, env_results_file_name):
    if not env_results_file_name or not os.path.exists(env_results_file_name):
        logging.critical('When running slack notifier for nightly build, provide env_results_file')
        sys.exit(0)
    with open(env_results_file_name, 'r') as env_results_file_content:
        env_results = json.load(env_results_file_content)

    role = env_results[0]['Role']
    success_file_path = "./Tests/is_build_passed_{}.txt".format(role.replace(' ', ''))

    content_team_fields, content_fields, _ = get_fields()
    is_build_success = os.path.isfile(success_file_path)
    color = 'good' if is_build_success else 'danger'
    title = 'Content Nightly Build - Success' if is_build_success else 'Content Nightly Build - Failure'

    content_team_attachment = [{
        'fallback': title,
        'color': color,
        'title': title,
        'title_link': build_url,
        'fields': content_team_fields
    }]

    content_attachment = [{
        'fallback': title,
        'color': color,
        'title': title,
        'title_link': build_url,
        'fields': content_fields
    }]

    return content_team_attachment, content_attachment


def get_fields():
    failed_tests = []
    if os.path.isfile('./Tests/failed_tests.txt'):
        logging.info('Extracting failed_tests')
        with open('./Tests/failed_tests.txt', 'r') as failed_tests_file:
            failed_tests = failed_tests_file.readlines()
            failed_tests = [line.strip('\n') for line in failed_tests]

    skipped_tests = []
    if os.path.isfile('./Tests/skipped_tests.txt'):
        logging.info('Extracting skipped_tests')
        with open('./Tests/skipped_tests.txt', 'r') as skipped_tests_file:
            skipped_tests = skipped_tests_file.readlines()
            skipped_tests = [line.strip('\n') for line in skipped_tests]

    skipped_integrations = []
    if os.path.isfile('./Tests/skipped_integrations.txt'):
        logging.info('Extracting skipped_integrations')
        with open('./Tests/skipped_integrations.txt', 'r') as skipped_integrations_file:
            skipped_integrations = skipped_integrations_file.readlines()
            skipped_integrations = [line.strip('\n') for line in skipped_integrations]

    content_team_fields = []
    content_fields = []
    if failed_tests:
        field_failed_tests = {
            "title": "Failed tests - ({})".format(len(failed_tests)),
            "value": '\n'.join(failed_tests),
            "short": False
        }
        content_team_fields.append(field_failed_tests)
        content_fields.append(field_failed_tests)

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

    return content_team_fields, content_fields, failed_tests


def slack_notifier(build_url, slack_token, test_type, env_results_file_name=None, packs_results_file=None,
                   job_name="", slack_channel=CONTENT_CHANNEL, gitlab_server=None):
    branches = run_command("git branch")
    branch_name_reg = re.search(r'\* (.*)', branches)
    branch_name = branch_name_reg.group(1)

    if branch_name == 'master' or slack_channel.lower() != CONTENT_CHANNEL:
        logging.info("Extracting build status")
        if test_type == UNITTESTS_TYPE:
            logging.info("Starting Slack notifications about nightly build - unit tests")
            content_team_attachments = get_attachments_for_unit_test(build_url)
        elif test_type == SDK_UNITTESTS_TYPE:
            logging.info("Starting Slack notifications about SDK nightly build - unit tests")
            content_team_attachments = get_attachments_for_unit_test(build_url, is_sdk_build=True)
        elif test_type == 'test_playbooks':
            logging.info("Starting Slack notifications about nightly build - tests playbook")
            content_team_attachments, _ = get_attachments_for_test_playbooks(build_url, env_results_file_name)
        elif test_type == SDK_FAILED_STEPS_TYPE:
            logging.info('Starting Slack notifications about SDK nightly build - test playbook')
            content_team_attachments = get_attachments_for_all_steps(build_url, build_title=SDK_BUILD_TITLE)
        elif test_type == BucketUploadFlow.BUCKET_UPLOAD_TYPE:
            logging.info('Starting Slack notifications about upload to production bucket build')
            content_team_attachments = get_attachments_for_bucket_upload_flow(
                build_url=build_url, job_name=job_name, packs_results_file_path=packs_results_file
            )
        elif test_type == SDK_RUN_AGAINST_FAILED_STEPS_TYPE:
            logging.info("Starting Slack notifications about SDK nightly build - run against an xsoar instance")
            content_team_attachments = get_attachments_for_all_steps(build_url, build_title=SDK_XSOAR_BUILD_TITLE)
        elif job_name and test_type == job_name:
            if job_name.startswith(DMST_SDK_NIGHTLY_GITLAB_JOBS_PREFIX):
                # We run the various circleci sdk nightly builds in a single pipeline in GitLab
                # as different jobs so it requires different handling
                logging.info(f"Starting Slack notifications for {job_name}")
                if 'unittest' in job_name:
                    content_team_attachments = get_attachments_for_unit_test(build_url, is_sdk_build=True)
                    # override the 'title' from the attachment to be the job name
                    content_team_attachments[0]['title'] = content_team_attachments[0]['title'].replace(
                        'SDK Nightly Unit Tests', job_name
                    )
                else:
                    content_team_attachments = get_attachments_for_all_steps(build_url, build_title=job_name)
                    # override the 'fields' from the attachment since any failure will be the same as the job name
                    content_team_attachments[0]['fields'] = []
        else:
            raise NotImplementedError('The test_type parameter must be only \'test_playbooks\' or \'unittests\'')
        logging.info(f'Content team attachments:\n{content_team_attachments}')
        logging.info(f"Sending Slack messages to {slack_channel}")
        slack_client = SlackClient(slack_token)
        username = 'Content GitlabCI' if gitlab_server else 'Content CircleCI'
        slack_client.api_call(
            "chat.postMessage",
            json={'channel': slack_channel,
                  'username': username,
                  'as_user': 'False',
                  'attachments': content_team_attachments}
        )


def main():
    install_logging('Slack_Notifier.log')
    options = options_handler()
    nightly = options.nightly
    url = options.url
    slack = options.slack
    test_type = options.test_type
    env_results_file_name = options.env_results_file_name
    bucket_upload = options.bucket_upload
    ci_artifacts_path = options.ci_artifacts
    job_name = options.job_name
    slack_channel = options.slack_channel or CONTENT_CHANNEL
    gitlab_server = options.gitlab_server
    if nightly:
        slack_notifier(url, slack, test_type, env_results_file_name)
    elif bucket_upload:
        slack_notifier(url, slack, test_type,
                       packs_results_file=os.path.join(
                           ci_artifacts_path, BucketUploadFlow.PACKS_RESULTS_FILE), job_name=job_name,
                       slack_channel=slack_channel, gitlab_server=gitlab_server)
    elif test_type in SDK_NIGHTLY_CIRCLE_OPTS or test_type == job_name:
        slack_notifier(
            url, slack, test_type, job_name=job_name,
            slack_channel=slack_channel, gitlab_server=gitlab_server
        )
    else:
        logging.error("Not nightly build, stopping Slack Notifications about Content build")


if __name__ == '__main__':
    main()
