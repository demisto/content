import json
import os
import re
import argparse
import requests

from slackclient import SlackClient

from Tests.test_utils import str2bool, run_command, LOG_COLORS, print_color

DEMISTO_GREY_ICON = 'https://3xqz5p387rui1hjtdv1up7lw-wpengine.netdna-ssl.com/wp-content/uploads/2018/07/Demisto-Icon-Dark.png'


def http_request(url, params_dict=None):
    try:
        res = requests.request("GET",
                               url,
                               verify=True,
                               params=params_dict,
                               )
        res.raise_for_status()

        return res.json()

    except Exception as e:
        raise e


def options_handler():
    parser = argparse.ArgumentParser(description='Parser for slack_notifier args')
    parser.add_argument('-n', '--nightly', type=str2bool, help='is nightly build?', required=True)
    parser.add_argument('-u', '--url', help='The url of the current build', required=True)
    parser.add_argument('-b', '--buildNumber', help='The build number', required=True)
    parser.add_argument('-s', '--slack', help='The token for slack', required=True)
    parser.add_argument('-c', '--circleci', help='The token for circleci', required=True)
    parser.add_argument('-f', '--env_results_file_name', help='The env results file containing the dns address', required=True)
    options = parser.parse_args()

    return options


def get_attachments(build_url, env_results_file_name):
    content_team_fields, content_fields, failed_tests, failed_unittests = get_fields()
    color = 'good' if not failed_tests else 'danger'
    title = 'Content Build - Success' if not (failed_tests or failed_unittests) else 'Content Build - Failure'

    with open(env_results_file_name, 'r') as env_results_file_content:
        env_results = json.load(env_results_file_content)
        instance_dns = env_results[0]['InstanceDNS']

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


def get_fields():
    print('Extracting failed_tests')
    with open('./Tests/failed_tests.txt', 'r') as failed_tests_file:
        failed_tests = failed_tests_file.readlines()
        failed_tests = [line.strip('\n') for line in failed_tests]

    print('Extracting failed_unittests')
    with open('./Tests/failed_unittests.txt', 'r') as failed_unittests_file:
        failed_unittests = failed_unittests_file.readlines()
        failed_unittests = [line.strip('\n') for line in failed_unittests]

    print('Extracting skipped_tests')
    with open('./Tests/skipped_tests.txt', 'r') as skipped_tests_file:
        skipped_tests = skipped_tests_file.readlines()
        skipped_tests = [line.strip('\n') for line in skipped_tests]

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
    branch_name_reg = re.search("\* (.*)", branches)
    branch_name = branch_name_reg.group(1)

    if branch_name == 'unittest-slack-notification':
        print_color("Starting Slack notifications about nightly build", LOG_COLORS.GREEN)
        print("Extracting build status")
        content_team_attachments, content_attachments = get_attachments(build_url, env_results_file_name)

        print("Sending Slack messages to #content-team")
        sc = SlackClient(slack_token)
        sc.api_call(
            "chat.postMessage",
            channel="WHB66N4VA",
            username="Content CircleCI",
            as_user="False",
            attachments=content_team_attachments
        )


if __name__ == "__main__":
    options = options_handler()
    # if options.nightly:
    slack_notifier(options.url, options.slack, options.env_results_file_name)
    # else:
    #     print_color("Not nightly build, stopping Slack Notifications about Content build", LOG_COLORS.RED)

    os.remove('./Tests/failed_tests.txt')
    os.remove('./Tests/failed_unittests.txt')
    os.remove('./Tests/skipped_tests.txt')
    os.remove('./Tests/skipped_integrations.txt')
