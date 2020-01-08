import json
import os
import re
import argparse
import requests

from slackclient import SlackClient

from Tests.test_utils import str2bool, run_command, LOG_COLORS, print_color

DEMISTO_GREY_ICON = 'https://3xqz5p387rui1hjtdv1up7lw-wpengine.netdna-ssl.com/wp-content/' \
                    'uploads/2018/07/Demisto-Icon-Dark.png'


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
    parser.add_argument('-f', '--env_results_file_name', help='The env results file containing the dns address',
                        required=True)
    options = parser.parse_args()

    return options


def get_attachments(build_url, env_results_file_name):
    with open(env_results_file_name, 'r') as env_results_file_content:
        env_results = json.load(env_results_file_content)

    # TODO: update this code after switching to parallel tests using multiple server for nightly build
    instance_dns = env_results[0]['InstanceDNS']
    role = env_results[0]['Role']
    build_number = build_url.split('/')[-1]
    success_file_path = "./Tests/is_build_passed_{}.txt".format(role.replace(' ', ''))

    content_team_fields, content_fields, _, failed_unit_tests = get_fields(build_number)
    is_build_success = os.path.isfile(success_file_path) and not failed_unit_tests
    color = 'good' if is_build_success else 'danger'
    title = 'Content Build - Success' if is_build_success else 'Content Build - Failure'

    content_team_attachment = [{
        'fallback': title,
        'color': color,
        'title': title,
        'title_link': build_url,
        "author_name": "Demisto Machine (Click here to open the nightly server)",
        "author_link": "https://{0}".format(instance_dns),
        "author_icon": DEMISTO_GREY_ICON,
        'fields': content_team_fields
    }]

    content_attachment = [{
        'fallback': title,
        'color': color,
        'title': title,
        "author_name": "Demisto AWS Machine",
        "author_link": "https://{0}".format(instance_dns),
        "author_icon": DEMISTO_GREY_ICON,
        'title_link': build_url,
        'fields': content_fields
    }]

    return content_team_attachment, content_attachment


def get_failing_unit_tests(build_number):
    try:
        failing_unit_tests_url = 'https://{0}-60525392-gh.circle-artifacts.com/1/artifacts/failed_unittests.txt'.format(
            build_number)
        res = http_request(failing_unit_tests_url, verify=False, text=True)
        print(res)
        failing_ut_list = res.split('\n')
    except Exception:
        failing_ut_list = None
    return failing_ut_list


def get_fields(build_number):
    failed_tests = []
    if os.path.isfile('./Tests/failed_tests.txt'):
        print('Extracting failed_tests')
        with open('./Tests/failed_tests.txt', 'r') as failed_tests_file:
            failed_tests = failed_tests_file.readlines()
            failed_tests = [line.strip('\n') for line in failed_tests]

    skipped_tests = []
    if os.path.isfile('./Tests/skipped_tests.txt'):
        print('Extracting skipped_tests')
        with open('./Tests/skipped_tests.txt', 'r') as skipped_tests_file:
            skipped_tests = skipped_tests_file.readlines()
            skipped_tests = [line.strip('\n') for line in skipped_tests]

    skipped_integrations = []
    if os.path.isfile('./Tests/skipped_integrations.txt'):
        print('Extracting skipped_integrations')
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

    failed_unittests = get_failing_unit_tests(build_number)
    if failed_unittests:
        field_failed_unittests = {
            "title": "Failed unittests - ({})".format(len(failed_unittests)),
            "value": '\n'.join(failed_unittests),
            "short": False
        }
        content_team_fields.append(field_failed_unittests)
        content_fields.append(field_failed_unittests)

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

    return content_team_fields, content_fields, failed_tests, failed_unittests


def slack_notifier(build_url, slack_token, env_results_file_name):
    branches = run_command("git branch")
    branch_name_reg = re.search(r'\* (.*)', branches)
    branch_name = branch_name_reg.group(1)

    if branch_name == 'unittest-slack-notifier':
        print_color("Starting Slack notifications about nightly build", LOG_COLORS.GREEN)
        print("Extracting build status")
        content_team_attachments, _ = get_attachments(build_url, env_results_file_name)

        print("Sending Slack messages to #content-team")
        slack_client = SlackClient(slack_token)
        slack_client.api_call(
            "chat.postMessage",
            channel="WHCL130LE",
            username="Content CircleCI",
            as_user="False",
            attachments=content_team_attachments
        )


def main():
    options = options_handler()
    # if options.nightly:
    slack_notifier(options.url, options.slack, options.env_results_file_name)
    # else:
    #     print_color("Not nightly build, stopping Slack Notifications about Content build", LOG_COLORS.RED)


if __name__ == '__main__':
    main()
