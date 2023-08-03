import argparse
import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path

import humanize
import urllib3
from demisto_sdk.commands.test_content.constants import SSH_USER
from paramiko import SSHClient, SSHException
from scp import SCPClient, SCPException

from Tests.scripts.utils.log_util import install_logging

urllib3.disable_warnings()  # Disable insecure warnings

DEFAULT_TTL = "300"
SERVER_LOG_DIRECTORY = "/var/log/demisto"
SERVER_LOG_FILE_PATH = f"{SERVER_LOG_DIRECTORY}/server.log"


def options_handler():
    parser = argparse.ArgumentParser(description='Utility for destroying integration test instances')
    parser.add_argument('--artifacts-dir', help='Path to the artifacts directory', required=True)
    parser.add_argument('--instance-role', help='The instance role', required=True)
    parser.add_argument('--env-file', help='The env_results.json file')
    return parser.parse_args()


def chmod_logs(ssh: SSHClient, server_ip: str) -> bool:
    try:
        logging.info(f'Changing permissions of folder {SERVER_LOG_DIRECTORY} on server {server_ip}')
        _, stdout, stderr = ssh.exec_command(f"sudo chmod -R 755 {SERVER_LOG_DIRECTORY}")
        # Wait for the command to exit.
        exit_code = stdout.channel.recv_exit_status()
        stderr_lines = stderr.readlines()
        logging.info(f"Running chmod finished - stdout:{stdout.readlines()}, stderr:{stderr_lines}, exit code:{exit_code}")

        return not stderr_lines and exit_code == 0
    except SSHException:
        logging.exception(f'Failed changing permissions of folder {SERVER_LOG_DIRECTORY} on server {server_ip}')
    return False


def shutdown(ssh: SSHClient, server_ip: str, ttl: int | None = None) -> bool:
    try:
        shutdown_command = f'sudo shutdown +{ttl}' if ttl else 'sudo shutdown'
        logging.info(f"Destroying instance with IP - {server_ip} with command:'{shutdown_command}'")
        _, stdout, stderr = ssh.exec_command(shutdown_command)
        # Wait for the command to exit.
        exit_code = stdout.channel.recv_exit_status()
        stderr_lines = stderr.readlines()
        logging.info(f"Running shutdown finished - stdout:{stdout.readlines()}, stderr:{stderr_lines},"
                     f" exit code:{exit_code}")

        return not stderr_lines and exit_code == 0
    except SSHException:
        logging.exception(f'Failed changing permissions of folder {SERVER_LOG_DIRECTORY} on server {server_ip}')
    return False


def download_logs(ssh: SSHClient, server_ip: str, artifacts_dir: str, role: str) -> bool:

    def progress(filename: bytes, size: int, sent: int, peer_name: tuple[str, int]):
        logging.info(f"Downloading from:{peer_name[0]}:{peer_name[1]} {filename!r} "
                     f"progress: {float(sent) / float(size) * 100:.2f}% "
                     f"({humanize.naturalsize(sent, binary=True, gnu=True)}/{humanize.naturalsize(size, binary=True, gnu=True)})")

    try:
        download_path = (Path(artifacts_dir) / f"server_{role}_{server_ip}.log").as_posix()
        logging.info(f'Downloading server logs from server {server_ip} from:{SERVER_LOG_FILE_PATH} to {download_path}')
        with SCPClient(ssh.get_transport(), progress4=progress) as scp:
            scp.get(SERVER_LOG_FILE_PATH, download_path)
        return True
    except SCPException:
        logging.exception(f'Failed downloading server logs from server {server_ip}')
    return False


def main():
    install_logging('Destroy_instances.log')
    options = options_handler()
    time_to_live = int(os.getenv('TIME_TO_LIVE') or DEFAULT_TTL)
    tests_path = Path('./Tests')
    start_time = datetime.utcnow()
    logging.info(f"Starting destroy instances - environment from {options.env_file}, TTL:{time_to_live} seconds, "
                 f"Tests Path:{tests_path.absolute()}")

    with open(options.env_file) as json_file:
        env_results = json.load(json_file)

    servers_list = list(filter(lambda x: x["Role"] == options.instance_role, env_results))
    logging.info(f"Found {len(servers_list)} server from the environment file to destroy")
    success = True
    for i, env in enumerate(servers_list, 1):
        readable_role = env["Role"]
        role = readable_role.replace(' ', '')
        server_ip = env["InstanceDNS"]
        logging.info(f'{i}/{len(servers_list)} - Downloading server log from {readable_role}, ip:{server_ip} and destroying it')

        with SSHClient() as ssh:
            try:
                ssh.load_system_host_keys()
                ssh.connect(server_ip, username=SSH_USER)
                success &= chmod_logs(ssh, server_ip)
                success &= download_logs(ssh, server_ip, options.artifacts_dir, role)

                if time_to_live:
                    logging.info(f'Time to live was set to {time_to_live} minutes for server:{server_ip}')
                    success &= shutdown(ssh, server_ip, time_to_live)
                elif (tests_path / f'is_build_passed_{role}.txt').exists() and \
                        (tests_path / f'is_post_update_passed_{role}.txt').exists():
                    success &= shutdown(ssh, server_ip)
                else:
                    logging.warning(f'Tests for some integration failed on {readable_role}, keeping instance alive')
            except SSHException:
                logging.exception(f"Unable to SSH to server:{server_ip}")
                success = False

    logging.info(f"Finished destroying instances - success:{success} took:{datetime.utcnow() - start_time}")
    if not success:
        sys.exit(1)


if __name__ == "__main__":
    main()
