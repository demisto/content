"""Wait for server to be ready for tests"""
import sys
import json
import string
import random
import ast
import argparse
from time import sleep
import datetime
import requests
from requests import Session

import demisto_client.demisto_api
from demisto_client.demisto_api.rest import ApiException
from typing import List, AnyStr
import urllib3.util

# Disable insecure warnings
urllib3.disable_warnings()

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


def get_xsrf_token(ips):
    for ami_instance_name, ami_instance_ip in ips:
        host = "https://{}".format(ami_instance_ip)
        session = Session()
        r = session.get(host, verify=False)


def is_correct_content_installed(ips, content_version, username, password):
    # type: (AnyStr, List[List], AnyStr) -> bool
    """ Checks if specific content version is installed on server list

    Args:
        api_key: For server connection
        ips: list with lists of [instance_name, instance_ip]
        content_version: content version that should be installed

    Returns:
        True: if all tests passed, False if one failure
    """

    print("EXPECTED CONTENT VERSION IS: ")
    print(repr(content_version))

    for ami_instance_name, ami_instance_ip in ips:
        host = "https://{}".format(ami_instance_ip)
        session = Session()
        r = session.get(host, verify=False)
        print(r.content)
        xsrf = r.cookies["XSRF-TOKEN"]
        print(xsrf)
        h = {"Accept": "application/json",
             "Content-type": "application/json",
             "X-XSRF-TOKEN": xsrf}
        body = json.dumps({"user": username, "password": password})
        print(username+"......"+password)
        first_time_login = session.request("POST", host+"/login", headers=h, verify=False, data=body)
        print(str(first_time_login.content))
        sleep(15)
        demisto_api_key = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(32))
        apikey_json = {
            'name': 'test_apikey',
            'apikey': demisto_api_key
        }
        resp = session.request("POST", host + "/apikeys", headers=h, verify=False,
                               data=json.dumps(apikey_json))
        print(str(resp))
        api_key = demisto_api_key
        client = demisto_client.configure(base_url=host, api_key=api_key, verify_ssl=False)
        # # just signing in for the session
        # body = {"user": username, "password": password}
        # demisto_client.generic_request_func(self=client, path='/login',
        #                                     method='POST', accept='application/json',
        #                                     content_type='application/json', body=body)
        # client.get_all_reports()
        try:
            resp = demisto_client.generic_request_func(self=client, path='/content/installed/',
                                                            method='POST', accept='application/json', content_type='application/json')
            print("This is the raw response\n\n\n")
            print(resp)
            resp_json = ast.literal_eval(resp[0])
            print("This is the response with literals stripped\n\n\n")
            print(resp_json)
            resp_json = json.loads(resp_json)
            print("This is the response dumped as JSON\n\n\n")
            print(resp_json)
            print("\n\n\nOBJECT TYPE: "+str(type(resp_json)))

            if not isinstance(dict(resp_json), dict):
                raise ValueError('Response from server is not a Dict, got [{}].\n'
                                 'Text: {}'.format(type(resp_json), resp_json))
            release = resp_json.get("release")
            print("Release is: "+str(release))
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

    print(username+"......"+password)

    ready_ami_list = []
    with open('./Tests/instance_ips.txt', 'r') as instance_file:
        instance_ips = instance_file.readlines()
        instance_ips = [line.strip('\n').split(":") for line in instance_ips]

    for i in range(MAX_TRIES * SLEEP_TIME):
        if len(instance_ips) > len(ready_ami_list):
            for ami_instance_name, ami_instance_ip in instance_ips:
                if ami_instance_name not in ready_ami_list:
                    host = "https://{}".format(ami_instance_ip)
                    path = '/health'
                    method = 'GET'
                    res = requests.request(method=method, url=(host+path), verify=False)
                    # res = demisto_client.generic_request_func(self=client, path=path, method=method)
                    # print(res)
                    if res.status_code == 200:
                        print("[{}] {} is ready to use".format(datetime.datetime.now(), ami_instance_name))
                        ready_ami_list.append(ami_instance_name)
                    elif i % 30 == 0:  # printing the message every 30 seconds
                        print("{} is not ready yet - waiting for it to start".format(ami_instance_name))

            if len(instance_ips) > len(ready_ami_list):
                sleep(1)

        else:
            break

    if len(ready_ami_list) != len(instance_ips):
        print_error("The server is not ready :(")
        sys.exit(1)

    if not is_correct_content_installed(instance_ips, content_version, username=username, password=password):
        sys.exit(1)


if __name__ == "__main__":
    main()
