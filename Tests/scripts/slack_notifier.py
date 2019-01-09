import os
import re
import sys
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


def get_attachments(build_url):
    content_team_fields, content_fields, failed_tests = get_fields()
    color = 'good' if not failed_tests else 'danger'
    title = 'Content Build - Success' if not failed_tests else 'Content Build - Failure'

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

    content_team_fields = []
    content_fields = []

    if failed_tests:
        field_failed_tests = {
            "title": "Failed tests",
            "value": '\n'.join(failed_tests),
            "short": False
        }
        content_team_fields.append(field_failed_tests)
        content_fields.append(field_failed_tests)

    if skipped_tests:
        field_skipped_tests = {
            "title": "Skipped tests",
            "value": '\n'.join(skipped_tests),
            "short": True
        }
        content_team_fields.append(field_skipped_tests)

    if skipped_integrations:
        field_skipped_integrations = {
            "title": "Skipped integrations",
            "value": '\n'.join(skipped_integrations),
            "short": True
        }
        content_team_fields.append(field_skipped_integrations)

    return content_team_fields, content_fields, failed_tests


def slack_notifier(build_url, build_number, slack_token, circleci_token):
    branches = run_git_command("git branch")
    branch_name_reg = re.search("\* (.*)", branches)
    branch_name = branch_name_reg.group(1)

    if branch_name == 'master':
        print_color("Starting Slack notifications about nightly build", LOG_COLORS.GREEN)
        print("Extracting build status")
        content_team_attachments, content_attachments = get_attachments(build_url)

        print("Sending Slack messages to #content and #content-team")
        sc = SlackClient(slack_token)
        sc.api_call(
            "chat.postMessage",
            channel="content-team",
            username="Content CircleCI",
            as_user="False",
            attachments=content_team_attachments
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
