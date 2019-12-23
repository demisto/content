"""Wait for server to be ready for tests"""
import sys
import json
import ast
import argparse
import time
from time import sleep
import datetime
import requests

from demisto_client.demisto_api.rest import ApiException
import demisto_client.demisto_api
from typing import List, AnyStr
import urllib3.util

from Tests.test_utils import print_error, print_color, LOG_COLORS

# Disable insecure warnings
urllib3.disable_warnings()

MAX_TRIES = 30
SLEEP_TIME = 45


def get_username_password():
    parser = argparse.ArgumentParser(description='Utility for batch action on incidents')
    parser.add_argument('-c', '--confPath', help='The path for the secret conf file', required=True)
    parser.add_argument('-v', '--contentVersion', help='Content version to install', required=True)
    parser.add_argument("--non-ami", help="Do NOT run with AMI setting", action='store_true')
    options = parser.parse_args()
    conf_path = options.confPath

    with open(conf_path, 'r') as conf_file:
        conf = json.load(conf_file)

    if options.non_ami:
        return conf['username'], conf['username'], options.contentVersion

    return conf['username'], conf['userPassword'], options.contentVersion


def is_correct_content_installed(ips, content_version, username, password):
    # type: (AnyStr, List[List], AnyStr) -> bool
    """ Checks if specific content version is installed on server list

    Args:
        username: Username of the service account
        password: Password of the service account
        ips: list with lists of [instance_name, instance_ip]
        content_version: content version that should be installed

    Returns:
        True: if all tests passed, False if one failure
    """

    for ami_instance_name, ami_instance_ip in ips:
        host = "https://{}".format(ami_instance_ip)

        client = demisto_client.configure(base_url=host, username=username, password=password, verify_ssl=False)
        try:
            resp_json = None
            try:
                resp = demisto_client.generic_request_func(self=client, path='/content/installed/',
                                                           method='POST', accept='application/json',
                                                           content_type='application/json')
                resp_json = ast.literal_eval(resp[0])
            except ApiException as err:
                print(err)
            if not isinstance(resp_json, dict):
                raise ValueError('Response from server is not a Dict, got [{}].\n'
                                 'Text: {}'.format(type(resp_json), resp_json))
            release = resp_json.get("release")
            notes = resp_json.get("releaseNotes")
            installed = resp_json.get("installed")
            if not (release and content_version in release and notes and installed):
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
    print_color("Content was installed successfully on all of the instances! :)", LOG_COLORS.GREEN)
    return True


def exit_if_timed_out(loop_start_time, current_time):
    time_since_started = current_time - loop_start_time
    half_hour_in_seconds = 30 * 60
    if time_since_started > half_hour_in_seconds:
        print_error("Timed out while trying to set up instances.")
        sys.exit(1)


def get_instance_types_count(instance_ips):
    instance_types_count = {}
    for ami_instance_name, ami_instance_ip in instance_ips:
        if ami_instance_name in instance_types_count:
            instance_types_count[ami_instance_name] += 1
        else:
            instance_types_count[ami_instance_name] = 1
    return instance_types_count


def main():
    username, password, content_version = get_username_password()
    ready_ami_list = []
    with open('./Tests/instance_ips.txt', 'r') as instance_file:
        instance_ips = instance_file.readlines()
        instance_ips = [line.strip('\n').split(":") for line in instance_ips]

    instance_types_to_create = get_instance_types_count(instance_ips)
    loop_start_time = time.perf_counter()
    last_update_time = loop_start_time

    while len(ready_ami_list) < len(instance_ips):
        current_time = time.perf_counter()
        exit_if_timed_out(loop_start_time, current_time)

        for ami_instance_name, ami_instance_ip in instance_ips:
            if instance_types_to_create[ami_instance_name] > 0:
                host = "https://{}".format(ami_instance_ip)
                path = '/health'
                method = 'GET'
                res = requests.request(method=method, url=(host + path), verify=False)
                if res.status_code == 200:
                    print("[{}] {} is ready to use".format(datetime.datetime.now(), ami_instance_name))
                    ready_ami_list.append(ami_instance_name)
                elif current_time - last_update_time > 30:  # printing the message every 30 seconds
                    print("{} is not ready yet - waiting for it to start".format(ami_instance_name))
                    last_update_time = current_time

        if len(instance_ips) > len(ready_ami_list):
            sleep(1)

    if not is_correct_content_installed(instance_ips, content_version, username=username, password=password):
        sys.exit(1)


if __name__ == "__main__":
    main()
