"""Wait for server to be ready for tests"""
import json
import logging
import os
import sys
import time
from subprocess import CalledProcessError, check_output
from time import sleep
from argparse import ArgumentParser

import requests
import urllib3.util
from demisto_sdk.commands.common.tools import str2bool

from Tests.scripts.utils.log_util import install_logging
from demisto_sdk.commands.test_content.constants import SSH_USER

# Disable insecure warnings
urllib3.disable_warnings()

ARTIFACTS_FOLDER = os.getenv('ARTIFACTS_FOLDER', './artifacts')
MAX_TRIES = 30
PRINT_INTERVAL_IN_SECONDS = 30
SETUP_TIMEOUT = 60 * 60
SLEEP_TIME = 45
NIGHTLY_BUILD_TTL = 12 * 60  # 12 hours


def exit_if_timed_out(loop_start_time, current_time):
    time_since_started = current_time - loop_start_time
    if time_since_started > SETUP_TIMEOUT:
        logging.critical("Timed out while trying to set up instances.")
        sys.exit(1)


def docker_login(ip: str) -> None:
    """
    Login-in to docker on the server to avoid docker rate limit quota violation
    Args:
        ip: The ip of the server that should be logged in
    """
    docker_username = os.environ.get('DOCKER_READ_ONLY_USER')
    docker_password = os.environ.get('DOCKER_READ_ONLY_PASSWORD') or ''
    container_engine_type = 'docker'
    try:
        check_output(
            f'ssh {SSH_USER}@{ip} cd /home/demisto && sudo -u demisto {container_engine_type} '
            f'login --username {docker_username} --password-stdin'.split(),
            input=docker_password.encode())
    except CalledProcessError as e:
        logging.exception(f'Could not login to {container_engine_type} on server {ip}:\n{e.stderr=}\n{e.output=}\n'
                          f'{e.returncode=}\n{e.cmd=}.')


def set_server_ttl(ip: str, ttl: int):
    try:
        shutdown_command = f'sudo shutdown +{ttl}' if ttl else 'sudo shutdown'
        logging.info(f"Setting TTL for server:{ip} with command:'{shutdown_command}'")
        check_output(f"ssh {SSH_USER}@{ip} {shutdown_command}".split())
    except CalledProcessError as e:
        logging.exception(f"Failed while calling shutdown on server {ip}:\n{e.stderr=}\n{e.output=}\n{e.returncode=}\n{e.cmd=}.")


def main():
    install_logging('Wait_Until_Server_Ready.log')
    global SETUP_TIMEOUT
    parser = ArgumentParser()
    parser.add_argument('-n', '--nightly', type=str2bool, help='Is nightly')
    parser.add_argument('--instance-role', help='The instance role', required=True)
    args = parser.parse_args()

    ready_ami_list: list = []
    env_results_path = os.path.join(ARTIFACTS_FOLDER, 'env_results.json')
    with open(env_results_path) as json_file:
        env_results = json.load(json_file)
        instance_ips = [(env.get('Role'), env.get('InstanceDNS')) for env in env_results]

    loop_start_time = time.time()
    last_update_time = loop_start_time
    instance_ips_to_poll = [ami_instance_ip for ami_instance_name, ami_instance_ip in instance_ips if
                            ami_instance_name == args.instance_role]

    logging.info('Starting wait loop')
    try:
        while instance_ips_to_poll:
            current_time = time.time()
            exit_if_timed_out(loop_start_time, current_time)

            for ami_instance_name, ami_instance_ip in instance_ips:
                if ami_instance_ip in instance_ips_to_poll:
                    url = f"https://{ami_instance_ip}/health"
                    try:
                        res = requests.request(method="GET", url=url, verify=False)
                    except (requests.exceptions.RequestException, requests.exceptions.HTTPError) as exp:
                        logging.error(f'{ami_instance_name} encountered an error: {str(exp)}\n')
                        if 60 * 10 != SETUP_TIMEOUT:
                            logging.warning('Setting SETUP_TIMEOUT to 10 minutes.')
                            SETUP_TIMEOUT = 60 * 10
                        continue
                    except Exception:
                        logging.exception(f'{ami_instance_name} encountered an error, Will retry this step later')
                        continue
                    if res.status_code == 200:
                        if 60 * 60 != SETUP_TIMEOUT:
                            logging.info('Resetting SETUP_TIMEOUT to an hour.')
                            SETUP_TIMEOUT = 60 * 60
                        logging.info(f'Role:{ami_instance_name} server ip:{ami_instance_ip} is ready to use')
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
                                              ami_instance_name == args.instance_role]
        for ip in instance_ips_to_download_log_files:
            docker_login(ip)
            if args.nightly:
                set_server_ttl(ip, ttl=NIGHTLY_BUILD_TTL)


if __name__ == "__main__":
    main()
