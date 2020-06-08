"""Wait for server to be ready for tests"""
import sys
import time
import re
from time import sleep
import datetime
import requests
import urllib3.util

from demisto_sdk.commands.common.tools import run_command, print_error, print_warning

# Disable insecure warnings
urllib3.disable_warnings()

MAX_TRIES = 30
PRINT_INTERVAL_IN_SECONDS = 30
SETUP_TIMEOUT = 60 * 60
SLEEP_TIME = 45


def is_release_branch():
    """Check if we are working on a release branch."""
    diff_string_config_yml = run_command("git diff origin/master .circleci/config.yml")
    if re.search(r'[+-][ ]+CONTENT_VERSION: ".*', diff_string_config_yml):
        return True

    return False


def exit_if_timed_out(loop_start_time, current_time):
    time_since_started = current_time - loop_start_time
    if time_since_started > SETUP_TIMEOUT:
        print_error("Timed out while trying to set up instances.")
        sys.exit(1)


def main():
    ready_ami_list = []
    failure = False
    with open('./Tests/instance_ips.txt', 'r') as instance_file:
        instance_ips = instance_file.readlines()
        instance_ips = [line.strip('\n').split(":") for line in instance_ips]

    loop_start_time = time.time()
    last_update_time = loop_start_time
    instance_ips_to_poll = [ami_instance_ip for ami_instance_name, ami_instance_ip in instance_ips]

    print(f'[{datetime.datetime.now()}] Starting wait loop')
    while instance_ips_to_poll:
        current_time = time.time()
        exit_if_timed_out(loop_start_time, current_time)

        for ami_instance_name, ami_instance_ip in instance_ips:
            if ami_instance_ip in instance_ips_to_poll:
                host = "https://{}".format(ami_instance_ip)
                path = '/health'
                method = 'GET'
                try:
                    res = requests.request(method=method, url=(host + path), verify=False)
                except (requests.exceptions.RequestException, requests.exceptions.HTTPError) as exp:
                    # print_error(f'{ami_instance_name} encountered an error: {str(exp)}\n'
                    #             f'Spot instance was dropped by amazon, if raised often - report to team leader.')
                    print_error(f'{ami_instance_name} encountered an error: {str(exp)}')
                    if SETUP_TIMEOUT != 60 * 10:  # noqa: F823
                        print_warning('Setting SETUP_TIMEOUT to 10 minutes.')
                        SETUP_TIMEOUT = 60 * 10
                    # instance_ips_to_poll.remove(ami_instance_ip)
                    failure = True
                    continue
                except Exception as exp:
                    print_warning(f'{ami_instance_name} encountered an error: {str(exp)}\n'
                                  f'Will retry this step later.')
                    continue
                if res.status_code == 200:
                    if SETUP_TIMEOUT != 60 * 60:
                        print(f'Resetting SETUP_TIMEOUT to an hour.')
                        SETUP_TIMEOUT = 60 * 60
                    print(f'[{datetime.datetime.now()}] {ami_instance_name} is ready to use')
                    # ready_ami_list.append(ami_instance_name)
                    instance_ips_to_poll.remove(ami_instance_ip)
                # printing the message every 30 seconds
                elif current_time - last_update_time > PRINT_INTERVAL_IN_SECONDS:
                    print(f'{ami_instance_name} at ip {ami_instance_ip} is not ready yet - waiting for it to start')

        if current_time - last_update_time > PRINT_INTERVAL_IN_SECONDS:
            # The interval has passed, which means we printed a status update.
            last_update_time = current_time
        if len(instance_ips) > len(ready_ami_list):
            sleep(1)

    if failure:
        print_error('One or more instance were dropped by amazon, if raised often - report to team leader.')
        sys.exit(1)


if __name__ == "__main__":
    main()
