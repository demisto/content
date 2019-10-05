"""Wait for server to be ready for tests"""
import sys
import json
import argparse
from time import sleep
import datetime

import demisto
from typing import List, AnyStr

from Tests.test_utils import print_error, print_color, LOG_COLORS

MAX_TRIES = 20
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


def is_correct_content_installed(username, password, ips, content_version):
    # type: (AnyStr, AnyStr, List[List], AnyStr) -> bool
    """ Checks if specific content version is installed on server list

    Args:
        username: for server connection
        password: for server connection
        ips: list with lists of [instance_name, instance_ip]
        content_version: content version that should be installed

    Returns:
        True: if all tests passed, False if one failure
    """
    method = "post"
    suffix = "/content/installed/"
    for ami_instance_name, ami_instance_ip in ips:
        d = demisto.DemistoClient(None, "https://{}".format(ami_instance_ip), username, password)
        d.Login()
        resp = d.req(method, suffix, None)
        resp_json = None
        try:
            resp_json = resp.json()
            if not isinstance(resp_json, dict):
                raise ValueError('Response from server is not a Dict, got [{}].\n'
                                 'Text: {}'.format(type(resp_json), resp.text))
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


def main():
    username, password, content_version = get_username_password()

    ready_ami_list = []
    with open('./Tests/instance_ips.txt', 'r') as instance_file:
        instance_ips = instance_file.readlines()
        instance_ips = [line.strip('\n').split(":") for line in instance_ips]

    for i in range(MAX_TRIES * SLEEP_TIME):
        if len(instance_ips) > len(ready_ami_list):
            for ami_instance_name, ami_instance_ip in instance_ips:
                if ami_instance_name not in ready_ami_list:
                    c = demisto.DemistoClient(None, "https://{}".format(ami_instance_ip), username, password)
                    res = c.Login()
                    if res.status_code == 200:
                        print "[{}] {} is ready to use".format(datetime.datetime.now(), ami_instance_name)
                        ready_ami_list.append(ami_instance_name)
                    elif i % 30 == 0:  # printing the message every 30 seconds
                        print "{} is not ready yet - waiting for it to start".format(ami_instance_name)

            if len(instance_ips) > len(ready_ami_list):
                sleep(1)

        else:
            break

    if len(ready_ami_list) != len(instance_ips):
        print_error("The server is not ready :(")
        sys.exit(1)

    if not is_correct_content_installed(username, password, instance_ips, content_version):
        sys.exit(1)


if __name__ == "__main__":
    main()
