import json
import logging
import os
import sys
from argparse import Namespace, ArgumentParser
from datetime import datetime, timedelta
from pathlib import Path
from collections.abc import Callable

import humanize
import urllib3
from demisto_sdk.commands.test_content.constants import SSH_USER
from paramiko import SSHClient, SSHException
from scp import SCPClient, SCPException
from tqdm import tqdm

from Tests.scripts.utils.log_util import install_logging

urllib3.disable_warnings()  # Disable insecure warnings

DEFAULT_TTL = "300"
SERVER_LOG_DIRECTORY = "/var/log/demisto"
SERVER_LOG_FILE_PATH = f"{SERVER_LOG_DIRECTORY}/server.log"


def options_handler() -> Namespace:
    parser = ArgumentParser(description='Utility for destroying integration test instances')
    parser.add_argument('--artifacts-dir', help='Path to the artifacts directory', required=True)
    parser.add_argument('--instance-role', help='The instance role', required=True)
    parser.add_argument('--env-file', help='The env_results.json file')
    return parser.parse_args()


def execute_ssh_command(ssh: SSHClient, shutdown_command: str) -> tuple[int, str, str]:
    _, stdout, stderr = ssh.exec_command(shutdown_command)
    # Wait for the command to exit.
    exit_code = stdout.channel.recv_exit_status()
    stdout_lines_output = '\n'.join(stdout.readlines())
    stderr_lines_output = '\n'.join(stderr.readlines())
    return exit_code, stderr_lines_output, stdout_lines_output


def chmod_logs(ssh: SSHClient, server_ip: str) -> bool:
    try:
        logging.info(f'Changing permissions of folder {SERVER_LOG_DIRECTORY} on server {server_ip}')
        exit_code, stderr_lines_output, stdout_lines_output = execute_ssh_command(ssh,
                                                                                  f"sudo chmod -R 755 {SERVER_LOG_DIRECTORY}")
        logging.info(f"Running chmod finished.\nstdout:\n{stdout_lines_output}\nstderr:\n{stderr_lines_output}\n"
                     f"exit code:{exit_code}")

        return not stderr_lines_output and exit_code == 0
    except SSHException:
        logging.exception(f'Failed changing permissions of folder {SERVER_LOG_DIRECTORY} on server {server_ip}')
    return False


def shutdown(ssh: SSHClient, server_ip: str, ttl: int | None = None) -> bool:
    try:
        shutdown_command = f'sudo shutdown +{ttl}' if ttl else 'sudo shutdown'
        logging.info(f"Destroying instance with IP {server_ip}, with command: '{shutdown_command}'")
        exit_code, stderr_lines_output, stdout_lines_output = execute_ssh_command(ssh, shutdown_command)
        # not checking stderr, as shutdown command on success writes it's output to it, so we can only verify the exit code.
        logging.info(f"Running shutdown finished.\nstdout:\n{stdout_lines_output}\nstderr:\n{stderr_lines_output}\n"
                     f"exit code: {exit_code}")

        return exit_code == 0
    except SSHException:
        logging.exception(f'Failed shutting down server {server_ip}')
    return False


def tqdm_progress4_update(tqdm_progress: tqdm) -> Callable[[bytes, int, int, tuple[str, int]], None]:
    # This is a hack to make the variable mutable inside the closure.
    last_bytes = [0]
    last_time = [datetime.utcnow()]

    def update_to(filename: bytes, size: int, sent: int, peer_name: tuple[str, int]):
        tqdm_progress.total = size
        tqdm_progress.desc = f"Downloading {filename!r} ..."
        tqdm_progress.update(sent - last_bytes[0])
        last_bytes[0] = sent
        if datetime.utcnow() - last_time[0] > timedelta(seconds=1) or sent == size:
            last_time[0] = datetime.utcnow()
            logging.info(f"Downloading from {peer_name[0]}:{peer_name[1]} {filename!r} "
                         f"progress: {float(sent) / float(size) * 100:.2f}% "
                         f"({humanize.naturalsize(sent, binary=True, gnu=True)}/"
                         f"{humanize.naturalsize(size, binary=True, gnu=True)})")

    return update_to


def download_logs(ssh: SSHClient, server_ip: str, artifacts_dir: str, role: str) -> bool:
    try:
        download_path = (Path(artifacts_dir) / f"server_{role}_{server_ip}.log").as_posix()
        logging.info(f'Downloading server logs from server {server_ip} from:{SERVER_LOG_FILE_PATH} to {download_path}')
        with (tqdm(unit='B', unit_scale=True, unit_divisor=1024, desc='Downloading server logs', mininterval=1.0, leave=True,
                   colour='green') as tqdm_progress,
              SCPClient(ssh.get_transport(), progress4=tqdm_progress4_update(tqdm_progress)) as scp):
            scp.get(SERVER_LOG_FILE_PATH, download_path)
        return True
    except SCPException:
        logging.exception(f'Failed downloading server logs from server {server_ip}')
    return False


def destroy_server(artifacts_dir: str, readable_role: str, role: str, server_ip: str, time_to_live: int) -> bool:
    success = True
    with SSHClient() as ssh:
        try:
            ssh.load_system_host_keys()
            ssh.connect(server_ip, username=SSH_USER)
            success &= chmod_logs(ssh, server_ip)
            success &= download_logs(ssh, server_ip, artifacts_dir, role)

            if (Path(artifacts_dir) / f'is_build_passed_{role}.txt').exists() and \
                    (Path(artifacts_dir) / f'is_post_update_passed_{role}.txt').exists():
                success &= shutdown(ssh, server_ip)
                logging.warning(f'Tests passed on {readable_role}, shutting down instance.')
            elif time_to_live:
                logging.info(f'Time to live was set to {time_to_live} minutes for server {server_ip}')
                success &= shutdown(ssh, server_ip, time_to_live)
            else:
                logging.warning(f'Tests for some integration failed on {readable_role}, keeping instance alive, '
                                f'until server default TTL')
        except SSHException:
            logging.exception(f"Unable to SSH to server {server_ip}")
            success = False
    return success


def main():
    install_logging('Destroy_instances.log')
    options = options_handler()
    time_to_live = int(os.getenv('TIME_TO_LIVE') or DEFAULT_TTL)
    start_time = datetime.utcnow()
    logging.info(f"Starting destroy instances - environment from {options.env_file}, TTL: {time_to_live} minutes, "
                 f"Artifacts dir: {options.artifacts_dir}")

    with open(options.env_file) as json_file:
        env_results = json.load(json_file)

    servers_list = list(filter(lambda x: x["Role"] == options.instance_role, env_results))
    logging.info(f"Found {len(servers_list)} server(s) from the environment file {options.env_file} to destroy")
    success = True
    for i, env in enumerate(servers_list, 1):
        readable_role = env["Role"]
        role = readable_role.replace(' ', '')
        server_ip = env["InstanceDNS"]
        logging.info(f'{i}/{len(servers_list)} {server_ip} - Downloading server log from {readable_role}, and destroying it')

        success &= destroy_server(options.artifacts_dir, readable_role, role, server_ip, time_to_live)

    duration = humanize.naturaldelta(datetime.utcnow() - start_time, minimum_unit="milliseconds")
    logging.info(f"Finished destroying instances - success:{success} took:{duration}")
    if not success:
        logging.error('Exiting with error, see reasons above.')
        sys.exit(1)


if __name__ == "__main__":
    main()
