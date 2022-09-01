"""Wait for server to be ready for tests"""
import json
import logging
import os
import sys
import time
from subprocess import check_output
from time import sleep

import requests
import urllib3.util

from Tests.scripts.utils.log_util import install_logging
# Disable insecure warnings
from demisto_sdk.commands.test_content.constants import SSH_USER
from demisto_sdk.commands.test_content.tools import is_redhat_instance

urllib3.disable_warnings()

ARTIFACTS_FOLDER = os.getenv('ARTIFACTS_FOLDER', './artifacts')
MAX_TRIES = 30
PRINT_INTERVAL_IN_SECONDS = 30
SETUP_TIMEOUT = 60 * 60
SLEEP_TIME = 45


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
        check_output(f'scp {SSH_USER}@{ip}:{cloud_init_log_path} '
                     f'{ARTIFACTS_FOLDER}/{ip}-cloud_init.log'.split())
    except Exception:
        logging.exception(f'Could not download cloud-init file from server {ip}.')


def docker_login(ip: str) -> None:
    """
    Login-in to docker on the server to avoid docker rate limit quota violation
    Args:
        ip: The ip of the server that should be logged in
    """
    docker_username = os.environ.get('DOCKER_READ_ONLY_USER')
    docker_password = os.environ.get('DOCKER_READ_ONLY_PASSWORD') or ''
    container_engine_type = 'podman' if is_redhat_instance(ip) else 'docker'
    try:
        check_output(
            f'ssh {SSH_USER}@{ip} cd /home/demisto && sudo -u demisto {container_engine_type} '
            f'login --username {docker_username} --password-stdin'.split(),
            input=docker_password.encode())
    except Exception:
        logging.exception(f'Could not login to {container_engine_type} on server {ip}')


def main():
    install_logging('Wait_Until_Server_Ready.log')
    global SETUP_TIMEOUT
    instance_name_to_wait_on = sys.argv[1]

    ready_ami_list: list = []
    env_results_path = os.path.join(ARTIFACTS_FOLDER, 'env_results.json')
    with open(env_results_path, 'r') as json_file:
        env_results = json.load(json_file)
        instance_ips = [(env.get('Role'), env.get('InstanceDNS'), env.get('TunnelPort')) for env in env_results]

    loop_start_time = time.time()
    last_update_time = loop_start_time
    instance_ips_to_poll = [ami_instance_ip for ami_instance_name, ami_instance_ip, _ in instance_ips if
                            ami_instance_name == instance_name_to_wait_on]

    logging.info('Starting wait loop')
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
        instance_ips_to_download_log_files = [ami_instance_ip for ami_instance_name, ami_instance_ip, _ in instance_ips if
                                              ami_instance_name == instance_name_to_wait_on]
        for ip in instance_ips_to_download_log_files:
            download_cloud_init_logs_from_server(ip)
            docker_login(ip)


if __name__ == "__main__":
    main()
