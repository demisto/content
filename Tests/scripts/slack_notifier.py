import os
import re
import sys
import json
import base64
import argparse
import requests
from subprocess import Popen, PIPE

from slackclient import SlackClient


class LOG_COLORS:
    NATIVE = '\033[m'
    RED = '\033[01;31m'
    GREEN = '\033[01;32m'


def print_error(error_str):
    print_color(error_str, LOG_COLORS.RED)


# print srt in the given color
def print_color(msg, color):
    print(str(color) + str(msg) + LOG_COLORS.NATIVE)


def http_request(url, params_dict=None):
    try:
        res = requests.request("GET",
                               url,
                               verify=True,
                               params=params_dict,
                               )
        res.raise_for_status()

        return res.json()

    except Exception, e:
        raise e


def run_git_command(command):
    p = Popen(command.split(), stdout=PIPE, stderr=PIPE)
    p.wait()
    if p.returncode != 0:
        print_error("Failed to run git command " + command)
        sys.exit(1)
    return p.stdout.read()


def str2bool(v):
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')


def options_handler():
    parser = argparse.ArgumentParser(description='Parser for slack_notifier args')
    parser.add_argument('-n', '--nightly', type=str2bool, help='is nightly build?', required=True)
    parser.add_argument('-u', '--url', help='The url of the current build', required=True)
    parser.add_argument('-b', '--buildNumber', help='The build number', required=True)
    parser.add_argument('-s', '--slack', help='The token for slack', required=True)
    parser.add_argument('-c', '--circleci', help='The token for circleci', required=True)
    options = parser.parse_args()

    return options


def extract_build_status(build_number, circleci_token):
    url = "https://circleci.com/api/v1.1/project/github/demisto/content/{0}?circle-token={1}".format(build_number, circleci_token)
    res = http_request(url)

    status = 'success'
    steps = res.get('steps', [])
    for step in steps:
        action = step.get('actions', [{}])[0]
        if action.get('status', 'failed') == 'failed':
            status = 'failed'

    return status


def get_attachments(build_url, build_st):
    color = 'good' if build_st is 'success' else 'danger'
    title = 'Content Build - Success' if build_st is 'success' else 'Content Build - Failure'
    fields = get_fields()

    attachment = [{
        'fallback': title,
        'color': color,
        'title': title,
        'title_link': build_url,
        'fields': fields
    }]

    return attachment


def get_fields():
    print('Extracting failed_tests')
    with open('./Tests/failed_tests.txt', 'r') as failed_tests_file:
        failed_tests = failed_tests_file.readlines()
        failed_tests = [line.strip('\n') for line in failed_tests]

    print('Extracting skipped_tests')
    with open('./Tests/skipped_tests.txt', 'r') as skipped_tests_file:
        skipped_tests = skipped_tests_file.readlines()
        skipped_tests = [line.strip('\n') for line in skipped_tests]

    print('Extracting skipped_integrations')
    with open('./Tests/skipped_integrations.txt', 'r') as skipped_integrations_file:
        skipped_integrations = skipped_integrations_file.readlines()
        skipped_integrations = [line.strip('\n') for line in skipped_integrations]

    fields = []

    if failed_tests:
        field_failed_tests = {
            "title": "Failed tests",
            "value": '\n'.join(failed_tests),
            "short": False
        }
        fields.append(field_failed_tests)

    if skipped_tests:
        field_skipped_tests = {
            "title": "Skipped tests",
            "value": '\n'.join(skipped_tests),
            "short": True
        }
        fields.append(field_skipped_tests)

    if skipped_integrations:
        field_skipped_integrations = {
            "title": "Skipped integrations",
            "value": '\n'.join(skipped_integrations),
            "short": True
        }
        fields.append(field_skipped_integrations)

    return fields


def slack_notifier(build_url, build_number, slack_token, circleci_token):
    branches = run_git_command("git branch")
    branch_name_reg = re.search("\* (.*)", branches)
    branch_name = branch_name_reg.group(1)

    if branch_name == 'master':
        print_color("Starting Slack notifications about nightly build", LOG_COLORS.GREEN)
        print("Extracting build status")
        build_st = extract_build_status(build_number, circleci_token)
        attachments = get_attachments(build_url, build_st)

        sc = SlackClient(slack_token)
        sc.api_call(
            "chat.postMessage",
            channel="content-team",
            username="Content CircleCI",
            as_user="False",
            attachments=attachments
        )

        sc.api_call(
            "chat.postMessage",
            channel="content",
            username="Content CircleCI",
            as_user="False",
            attachments=attachments
        )


if __name__ == "__main__":
    options = options_handler()
    if options.nightly:
        slack_notifier(options.url, options.buildNumber, options.slack, options.circleci)
    else:
        print_color("Not nightly build, stopping Slack Notifications about Content build", LOG_COLORS.RED)

    os.remove('./Tests/failed_tests.txt')
    os.remove('./Tests/skipped_tests.txt')
    os.remove('./Tests/skipped_integrations.txt')
