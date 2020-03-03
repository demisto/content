"""Wait for server to be ready for tests"""
import sys
import json
import ast
import argparse
import time
import re
from time import sleep
import datetime
import requests

from demisto_client.demisto_api.rest import ApiException
import demisto_client.demisto_api
from typing import List, AnyStr
import urllib3.util

from Tests.test_utils import run_command, print_warning, print_error, print_color, LOG_COLORS

# Disable insecure warnings
urllib3.disable_warnings()

MAX_TRIES = 30
PRINT_INTERVAL_IN_SECONDS = 30
SETUP_TIMEOUT = 45 * 60
SLEEP_TIME = 45


def is_release_branch():
    """Check if we are working on a release branch."""
    diff_string_config_yml = run_command("git diff origin/master .circleci/config.yml")
    if re.search(r'[+-][ ]+CONTENT_VERSION: ".*', diff_string_config_yml):
        return True

    return False


def get_apikey_and_contentversion():
    parser = argparse.ArgumentParser(description='Utility for batch action on incidents')
    parser.add_argument('-c', '--confPath', help='The path for the secret conf file', required=True)
    parser.add_argument('-v', '--contentVersion', help='Content version to install', required=True)
    parser.add_argument("--non-ami", help="Do NOT run with AMI setting", action='store_true')
    options = parser.parse_args()
    conf_path = options.confPath

    with open(conf_path, 'r') as conf_file:
        conf = json.load(conf_file)

    return conf['temp_apikey'], options.contentVersion


def is_correct_content_installed(ips, content_version, api_key):
    # type: (AnyStr, List[List], AnyStr) -> bool
    """ Checks if specific content version is installed on server list

    Args:
        ips: list with lists of [instance_name, instance_ip]
        content_version: content version that should be installed
        api_key: the demisto api key to create an api client with.

    Returns:
        True: if all tests passed, False if one failure
    """

    for ami_instance_name, ami_instance_ip in ips:
        host = "https://{}".format(ami_instance_ip)

        client = demisto_client.configure(base_url=host, api_key=api_key, verify_ssl=False)
        resp_json = None
        try:
            try:
                resp = demisto_client.generic_request_func(self=client, path='/content/installed/',
                                                           method='POST', accept='application/json',
                                                           content_type='application/json')
                try:
                    resp_json = ast.literal_eval(resp[0])
                except ValueError as err:
                    print_error(
                        'failed to parse response from demisto. response is {}.\nError:\n{}'.format(resp[0], err))
                    return False
            except ApiException as err:
                print(err)

            if not isinstance(resp_json, dict):
                raise ValueError('Response from server is not a Dict, got [{}].\n'
                                 'Text: {}'.format(type(resp_json), resp_json))
            release = resp_json.get("release")
            notes = resp_json.get("releaseNotes")
            installed = resp_json.get("installed")
            if not (release and content_version in release and notes and installed):
                if is_release_branch():
                    print_warning('On a release branch - ignoring content mismatch.')
                else:
                    print_error("Failed install content on instance [{}]\nfound content version [{}], expected [{}]"
                                "".format(ami_instance_name, release, content_version))
                    return False
            else:
                print_color("Instance [{instance_name}] content verified with version [{content_version}]".format(
                    instance_name=ami_instance_name, content_version=release),
                    LOG_COLORS.GREEN
                )
        except ValueError as exception:
            err_msg = "Failed to verify content version on server [{}]\n" \
                      "Error: [{}]\n".format(ami_instance_name, str(exception))
            if resp_json is not None:
                err_msg += "Server response: {}".format(resp_json)
            print_error(err_msg)
            return False
    return True


def exit_if_timed_out(loop_start_time, current_time):
    time_since_started = current_time - loop_start_time
    if time_since_started > SETUP_TIMEOUT:
        print_error("Timed out while trying to set up instances.")
        sys.exit(1)


def main():
    api_key, content_version = get_apikey_and_contentversion()
    ready_ami_list = []
    with open('./Tests/instance_ips.txt', 'r') as instance_file:
        instance_ips = instance_file.readlines()
        instance_ips = [line.strip('\n').split(":") for line in instance_ips]

    loop_start_time = time.time()
    last_update_time = loop_start_time
    instance_ips_not_created = [ami_instance_ip for ami_instance_name, ami_instance_ip in instance_ips]

    while len(instance_ips_not_created) > 0:
        current_time = time.time()
        exit_if_timed_out(loop_start_time, current_time)

        for ami_instance_name, ami_instance_ip in instance_ips:
            if ami_instance_ip in instance_ips_not_created:
                host = "https://{}".format(ami_instance_ip)
                path = '/health'
                method = 'GET'
                res = requests.request(method=method, url=(host + path), verify=False)
                if res.status_code == 200:
                    print("[{}] {} is ready to use".format(datetime.datetime.now(), ami_instance_name))
                    # ready_ami_list.append(ami_instance_name)
                    instance_ips_not_created.remove(ami_instance_ip)
                elif current_time - last_update_time > PRINT_INTERVAL_IN_SECONDS:  # printing the message every 30 seconds
                    print("{} at ip {} is not ready yet - waiting for it to start".format(ami_instance_name,
                                                                                          ami_instance_ip))

        if current_time - last_update_time > PRINT_INTERVAL_IN_SECONDS:
            # The interval has passed, which means we printed a status update.
            last_update_time = current_time
        if len(instance_ips) > len(ready_ami_list):
            sleep(1)

    # if not is_correct_content_installed(instance_ips, content_version, api_key=api_key):
    #     sys.exit(1)


if __name__ == "__main__":
    main()
