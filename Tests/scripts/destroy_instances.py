import argparse
import json
import logging
import os
from pathlib import Path
import subprocess
from demisto_sdk.commands.test_content.constants import SSH_USER
from Tests.scripts.utils.log_util import install_logging

# Disable insecure warnings
import urllib3

urllib3.disable_warnings()


def options_handler():
    parser = argparse.ArgumentParser(description='Utility for destroying integration test instances')
    parser.add_argument('--artifacts-dir', help='Path to the artifacts directory', required=True)
    parser.add_argument('--instance-role', help='The instance role', required=True)
    parser.add_argument('--env-file', help='The env_results.json file')
    return parser.parse_args()


def chmod_logs(server_ip: str):
    try:
        logging.debug(f'Changing permissions of folder /var/log/demisto on server {server_ip}')
        subprocess.check_output(f'ssh {SSH_USER}@{server_ip} "sudo chmod -R 755 /var/log/demisto"', shell=True)  # noqa: S602

    except subprocess.CalledProcessError:
        logging.exception(f'Failed changing permissions of folder /var/log/demisto on server {server_ip}')


def download_logs(server_ip: str, artifacts_dir: str, role: str):
    scp_string = f"scp {SSH_USER}@{server_ip}:/var/log/demisto/server.log " \
                 f"{artifacts_dir}/server_{role}_{server_ip}.log || echo 'WARN: Failed downloading server.log'"
    try:
        logging.debug(f'Downloading server logs from server {server_ip}')
        subprocess.check_output(scp_string, shell=True)  # noqa: S602

    except subprocess.CalledProcessError:
        logging.exception(f'Failed downloading server logs from server {server_ip}')


def shutdown(server_ip: str, ttl: int | None = None):
    try:
        logging.info(f'Destroying instance with IP - {server_ip}')
        shutdown_command = f'sudo shutdown +{ttl}' if ttl else 'sudo shutdown'
        subprocess.check_output(f'ssh {SSH_USER}@{server_ip} "{shutdown_command}"', shell=True)  # noqa: S602

    except subprocess.CalledProcessError:
        logging.exception(f'Failed to shutdown server {server_ip}')


def main():
    install_logging('Destroy_instances.log')
    options = options_handler()
    time_to_live = os.getenv('TIME_TO_LIVE')
    tests_path = Path('./Tests')

    with open(options.env_file) as json_file:
        env_results = json.load(json_file)

    for env in filter(lambda x: x["Role"] == options.instance_role, env_results):
        readable_role = env["Role"]
        role = readable_role.replace(' ', '')
        server_ip = env["InstanceDNS"]

        logging.info(f'Downloading server log from {readable_role}')
        chmod_logs(server_ip)
        download_logs(server_ip, options.artifacts_dir, role)

        if time_to_live:
            logging.info(f'Time to live was set to {time_to_live} minutes')
            shutdown(server_ip, int(time_to_live))
        elif (tests_path / f'is_build_passed_{role}.txt').exists() and \
                (tests_path / f'is_post_update_passed_{role}.txt').exists():
            shutdown(server_ip)
        else:
            logging.warning(f'Tests for some integration failed on {readable_role}, keeping instance alive')


if __name__ == "__main__":
    main()
