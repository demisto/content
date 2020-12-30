"""Wait for server to be ready for tests"""
import json
import logging
import os
import re
import sys
import time
from subprocess import check_output
from time import sleep

import requests
import urllib3.util

from Tests.scripts.utils.log_util import install_logging
from demisto_sdk.commands.common.tools import run_command

# Disable insecure warnings
urllib3.disable_warnings()

ARTIFACTS_PATH = os.environ.get('CIRCLE_ARTIFACTS')
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
        logging.critical("Timed out while trying to set up instances.")
        sys.exit(1)


def download_cloud_init_logs_from_server(ip: str) -> None:
    """
    Since setup instance is now done by the server itself in the *user-data* script, the logs of the setup are stored
    in the server itself.
    This method downloads those logs to artifacts path for debugging purposes
    Args:
        ip: The ip from which we should download the cloud-init log file
    """
    cloud_init_log_path = '/var/log/cloud-init-output.log'
    try:
        # downloading cloud-init logs to artifacts
        check_output(['scp',
                      '-o', ' StrictHostKeyChecking=no',
                      f'ec2-user@{ip}:{cloud_init_log_path}',
                      f'{ARTIFACTS_PATH}/{ip}-cloud_init.log'])
    except Exception:
        logging.exception(f'Could not download cloud-init file from server {ip}.')


def docker_login(ip: str) -> None:
    """
    Login-in to docker on the server to avoid docker rate limit quota violation
    Args:
        ip: The ip of the server that should be logged in
    """
    docker_username = os.environ.get('DOCKERHUB_USER')
    docker_password = os.environ.get('DOCKERHUB_PASSWORD')
    try:
        check_output(f'ssh -o StrictHostKeyChecking=no ec2-user@{ip} '
                     f'sudo docker login --username {docker_username} --password-stdin'.split(),
                     input=docker_password.encode())
    except Exception:
        logging.exception(f'Could not login to docker on server {ip}')


def main():
    install_logging('Wait_Until_Server_Ready.log')
    global SETUP_TIMEOUT
    instance_name_to_wait_on = sys.argv[1]
    ready_ami_list = []
    with open('./env_results.json', 'r') as json_file:
        env_results = json.load(json_file)
        instance_ips = [(env.get('Role'), env.get('InstanceDNS')) for env in env_results]

    loop_start_time = time.time()
    last_update_time = loop_start_time
    instance_ips_to_poll = [ami_instance_ip for ami_instance_name, ami_instance_ip in instance_ips if
                            ami_instance_name == instance_name_to_wait_on]

    logging.info('Starting wait loop')
    try:
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
                        logging.error(f'{ami_instance_name} encountered an error: {str(exp)}\n')
                        if SETUP_TIMEOUT != 60 * 10:
                            logging.warning('Setting SETUP_TIMEOUT to 10 minutes.')
                            SETUP_TIMEOUT = 60 * 10
                        continue
                    except Exception:
                        logging.exception(f'{ami_instance_name} encountered an error, Will retry this step later')
                        continue
                    if res.status_code == 200:
                        if SETUP_TIMEOUT != 60 * 60:
                            logging.info('Resetting SETUP_TIMEOUT to an hour.')
                            SETUP_TIMEOUT = 60 * 60
                        logging.info(f'{ami_instance_name} is ready to use')
                        instance_ips_to_poll.remove(ami_instance_ip)
                    # printing the message every 30 seconds
                    elif current_time - last_update_time > PRINT_INTERVAL_IN_SECONDS:
                        logging.info(
                            f'{ami_instance_name} at ip {ami_instance_ip} is not ready yet - waiting for it to start')

            if current_time - last_update_time > PRINT_INTERVAL_IN_SECONDS:
                # The interval has passed, which means we printed a status update.
                last_update_time = current_time
            if len(instance_ips) > len(ready_ami_list):
                sleep(1)
    finally:
        instance_ips_to_download_log_files = [ami_instance_ip for ami_instance_name, ami_instance_ip in instance_ips if
                                              ami_instance_name == instance_name_to_wait_on]
        for ip in instance_ips_to_download_log_files:
            download_cloud_init_logs_from_server(ip)
            docker_login(ip)


if __name__ == "__main__":
    main()
