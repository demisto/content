import argparse
import ast
import json
import sys
from datetime import time

import demisto_client
import urllib3

from Tests.scripts.wait_until_server_ready import is_release_branch
from Tests.test_utils import print_error, print_warning, print_color, LOG_COLORS
from demisto_client.demisto_api.rest import ApiException

# Disable insecure warnings
urllib3.disable_warnings()


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


def main():
    api_key, content_version = get_apikey_and_contentversion()
    with open('./Tests/instance_ips.txt', 'r') as instance_file:
        instance_ips = instance_file.readlines()
        instance_ips = [line.strip('\n').split(":") for line in instance_ips]

    if not is_correct_content_installed(instance_ips, content_version, api_key=api_key):
        sys.exit(1)


if __name__ == "__main__":
    main()
