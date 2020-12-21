import json
import os
import re
import sys
import argparse
import requests
import logging
from circleci.api import Api as circle_api

from slackclient import SlackClient

from Tests.scripts.utils.log_util import install_logging
from demisto_sdk.commands.common.tools import str2bool, run_command
from Tests.Marketplace.marketplace_services import BucketUploadFlow, get_successful_and_failed_packs

DEMISTO_GREY_ICON = 'https://3xqz5p387rui1hjtdv1up7lw-wpengine.netdna-ssl.com/wp-content/' \
                    'uploads/2018/07/Demisto-Icon-Dark.png'
UNITTESTS_TYPE = 'unittests'
TEST_PLAYBOOK_TYPE = 'test_playbooks'
SDK_UNITTESTS_TYPE = 'sdk_unittests'
SDK_FAILED_STEPS_TYPE = 'sdk_faild_steps'
SDK_RUN_AGAINST_FAILED_STEPS_TYPE = 'sdk_run_against_failed_steps'
SDK_BUILD_TITLE = 'SDK Nightly Build'
SDK_XSOAR_BUILD_TITLE = 'Demisto SDK Nightly - Run Against Cortex XSOAR'


def get_faild_steps_list():
    options = options_handler()
    failed_steps_list = []
    circle_client = circle_api(options.circleci)
    vcs_type = 'github'
    build_report = circle_client.get_build_info(username='demisto', project='content', build_num=options.buildNumber,
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
    parser.add_argument('-c', '--circleci', help='The token for circleci', required=True)
    parser.add_argument('-t', '--test_type', help='unittests or test_playbooks or sdk_unittests or sdk_faild_steps'
                                                  'or bucket_upload')
    parser.add_argument('-f', '--env_results_file_name', help='The env results file containing the dns address')
    parser.add_argument('-bu', '--bucket_upload', help='is bucket upload build?', required=True, type=str2bool)
    parser.add_argument('-ca', '--circle_artifacts', help="The path to the circle artifacts directory")
    parser.add_argument('-j', '--job_name', help='The job name that is running the slack notifier')
    options = parser.parse_args()

    return options


def get_failing_unit_tests_file_data():
    try:
        failing_ut_list = None
        file_name = './artifacts/failed_lint_report.txt'
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
        failed_entities = get_faild_steps_list()
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

    if job_name and job_name == BucketUploadFlow.UPLOAD_JOB_NAME:
        successful_packs, failed_packs = get_successful_and_failed_packs(
            packs_results_file_path, BucketUploadFlow.UPLOAD_PACKS_TO_MARKETPLACE_STORAGE
        )
        if successful_packs:
            steps_fields += [{
                "title": "Successful Packs:",
                "value": "\n".join([pack_name for pack_name in {*successful_packs}]),
                "short": False
            }]
        if failed_packs:
            steps_fields += [{
                "title": "Failed Packs:",
                "value": "\n".join([f"{pack_name}: {pack_data.get(BucketUploadFlow.STATUS)}"
                                    for pack_name, pack_data in failed_packs.items()]),
                "short": False
            }]

    if job_name and job_name != 'Upload Packs To Marketplace' and color == 'good':
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
                   job_name=""):
    branches = run_command("git branch")
    branch_name_reg = re.search(r'\* (.*)', branches)
    branch_name = branch_name_reg.group(1)

    if branch_name == 'upload-flow-dev':
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
            content_team_attachments = get_attachments_for_all_steps(build_url, build_title=SDK_XSOAR_BUILD_TITLE)
        else:
            raise NotImplementedError('The test_type parameter must be only \'test_playbooks\' or \'unittests\'')
        logging.info(f'Content team attachments:\n{content_team_attachments}')
        logging.info("Sending Slack messages to #content-team")
        slack_client = SlackClient(slack_token)
        slack_client.api_call(
            "chat.postMessage",
            channel="dmst-bucket-upload",
            username="Content CircleCI",
            as_user="False",
            attachments=content_team_attachments
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
    circle_artifacts_path = options.circle_artifacts
    job_name = options.job_name
    if nightly:
        slack_notifier(url, slack, test_type, env_results_file_name)
    elif bucket_upload:
        slack_notifier(url, slack, test_type,
                       packs_results_file=os.path.join(
                           circle_artifacts_path, BucketUploadFlow.PACKS_RESULTS_FILE), job_name=job_name
                       )
    elif test_type in (SDK_UNITTESTS_TYPE, SDK_FAILED_STEPS_TYPE, SDK_RUN_AGAINST_FAILED_STEPS_TYPE):
        slack_notifier(url, slack, test_type)
    else:
        logging.error("Not nightly build, stopping Slack Notifications about Content build")


if __name__ == '__main__':
    main()
