"""Wait for server to be ready for tests"""
import json
import os
import sys
import time
import re
from subprocess import check_output
from time import sleep
import requests
import urllib3.util

from demisto_sdk.commands.common.tools import run_command, print_error, print_warning

# Disable insecure warnings
urllib3.disable_warnings()

MAX_TRIES = 30
PRINT_INTERVAL_IN_SECONDS = 30
SETUP_TIMEOUT = 60 * 60
SLEEP_TIME = 45
SSH_USER = 'ec2-user'


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


def docker_login(ip: str) -> None:
    """
    Login-in to docker on the server to avoid docker rate limit quota violation
    Args:
        ip: The ip of the server that should be logged in
    """
    docker_username = os.environ.get('DOCKERHUB_USER')
    docker_password = os.environ.get('DOCKERHUB_PASSWORD')
    try:
        check_output(
            f'ssh {SSH_USER}@{ip} '
            f'sudo mkdir -p /home/demisto '
            f'&& sudo chown demisto /home/demisto '
            f'&& cd /home/demisto && sudo -u demisto docker '
            f'login --username {docker_username} --password-stdin'.split(),
            input=docker_password.encode())
    except Exception as err:
        print_error(f'Could not login to docker on server {ip}, {err}')


def main():
    global SETUP_TIMEOUT
    instance_name_to_wait_on = sys.argv[1]
    ready_ami_list = []
    with open('./env_results.json', 'r') as json_file:
        env_results = json.load(json_file)
        instance_ips = [(env.get('Role'), env.get('InstanceDNS'), env.get('TunnelPort')) for env in env_results]

    loop_start_time = time.time()
    last_update_time = loop_start_time
    instance_ips_to_poll = [ami_instance_ip for ami_instance_name, ami_instance_ip, _ in instance_ips if
                            ami_instance_name == instance_name_to_wait_on]

    print('Starting wait loop')
    try:
        while instance_ips_to_poll:
            current_time = time.time()
            exit_if_timed_out(loop_start_time, current_time)

            for ami_instance_name, ami_instance_ip, tunnel_port in instance_ips:
                if ami_instance_ip in instance_ips_to_poll:
                    url = f"https://localhost:{tunnel_port}/health"
                    method = 'GET'
                    try:
                        res = requests.request(method=method, url=url, verify=False)
                    except (requests.exceptions.RequestException, requests.exceptions.HTTPError) as exp:
                        print_error(f'{ami_instance_name} encountered an error: {str(exp)}\n')
                        if SETUP_TIMEOUT != 60 * 10:
                            print_warning('Setting SETUP_TIMEOUT to 10 minutes.')
                            SETUP_TIMEOUT = 60 * 10
                        continue
                    except Exception:
                        print_error(f'{ami_instance_name} encountered an error, Will retry this step later')
                        continue
                    if res.status_code == 200:
                        if SETUP_TIMEOUT != 60 * 60:
                            print('Resetting SETUP_TIMEOUT to an hour.')
                            SETUP_TIMEOUT = 60 * 60
                        print(f'{ami_instance_name} is ready to use')
                        instance_ips_to_poll.remove(ami_instance_ip)
                    # printing the message every 30 seconds
                    elif current_time - last_update_time > PRINT_INTERVAL_IN_SECONDS:
                        print(
                            f'{ami_instance_name} at ip {ami_instance_ip} is not ready yet - waiting for it to start')

            if current_time - last_update_time > PRINT_INTERVAL_IN_SECONDS:
                # The interval has passed, which means we printed a status update.
                last_update_time = current_time
            if len(instance_ips) > len(ready_ami_list):
                sleep(1)
    finally:
        instance_ips_to_download_log_files = [ami_instance_ip for ami_instance_name, ami_instance_ip, _ in instance_ips if
                                              ami_instance_name == instance_name_to_wait_on]
        for ip in instance_ips_to_download_log_files:
            docker_login(ip)


if __name__ == "__main__":
    main()
