#!/usr/bin/env bash

echo "Start Slack notifier"

python ./Tests/slack_notifier.py -n $IS_NIGHTLY -l $CIRCLE_BUILD_URL
import re
import sys
import argparse
from subprocess import Popen, PIPE

from slackclient import SlackClient

TOKEN = "xoxp-3435591503-412013996354-447855140609-ad8718a9a223692d0c92a6365a115d37"


class LOG_COLORS:
    NATIVE = '\033[m'
    RED = '\033[01;31m'
    GREEN = '\033[01;32m'


def print_error(error_str):
    print_color(error_str, LOG_COLORS.RED)


# print srt in the given color
def print_color(msg, color):
    print(str(color) + str(msg) + LOG_COLORS.NATIVE)


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
    parser = argparse.ArgumentParser(description='Utility for batch action on incidents')
    parser.add_argument('-n', '--nightly', type=str2bool, help='Run nightly tests')
    options = parser.parse_args()

    return options


def slack_notifier():
    branches = run_git_command("git branch")
    branch_name_reg = re.search("\* (.*)", branches)
    branch_name = branch_name_reg.group(1)

    if branch_name == 'master':
        sc = SlackClient(TOKEN)
        sc.api_call(
            "chat.postMessage",
            channel="test_slack",
            username="circleci",
            text="hellosadfasdfa",
            as_user="False"
        )


if __name__ == "__main__":
    options = options_handler()
    if options.nightly:
        slack_notifier()


$CIRCLE_BUILD_URL
