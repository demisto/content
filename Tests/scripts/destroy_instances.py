import sys
import os
import json
import subprocess
import logging
import Tests.scripts.awsinstancetool.aws_functions as aws_functions
from Tests.scripts.utils.log_util import install_logging


def main():
    install_logging('Destroy_instances.log')
    circle_aritfact = sys.argv[1]
    env_file = sys.argv[2]
    instance_role = sys.argv[3]
    time_to_live = sys.argv[4]
    with open(env_file, 'r') as json_file:
        env_results = json.load(json_file)

    filtered_results = [env_result for env_result in env_results if env_result["Role"] == instance_role]
    for env in filtered_results:
        logging.info(f'Downloading server log from {env.get("Role", "Unknown role")}')
        ssh_string = 'ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {}@{} ' \
                     '"sudo chmod -R 755 /var/log/demisto"'
        scp_string = 'scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ' \
                     '{}@{}:/var/log/demisto/server.log {} || echo "WARN: Failed downloading server.log"'

        try:
            logging.debug(f'Changing permissions of folder /var/log/demisto on server {env["InstanceDNS"]}')
            subprocess.check_output(
                ssh_string.format(env["SSHuser"], env["InstanceDNS"]), shell=True)

        except subprocess.CalledProcessError:
            logging.exception(f'Failed changing permissions of folder /var/log/demisto on server {env["InstanceDNS"]}')

        try:
            logging.debug(f'Downloading server logs from server {env["InstanceDNS"]}')
            server_ip = env["InstanceDNS"].split('.')[0]
            subprocess.check_output(
                scp_string.format(
                    env["SSHuser"],
                    env["InstanceDNS"],
                    "{}/server_{}_{}.log".format(circle_aritfact, env["Role"].replace(' ', ''), server_ip)),
                shell=True)

        except subprocess.CalledProcessError:
            logging.exception(f'Failed downloading server logs from server {env["InstanceDNS"]}')

        if time_to_live:
            logging.info(f'Skipping - Time to live was set to {time_to_live} minutes')
            continue
        if os.path.isfile("./Tests/is_build_passed_{}.txt".format(env["Role"].replace(' ', ''))):
            logging.info(f'Destroying instance with role - {env.get("Role", "Unknown role")} and IP - '
                         f'{env["InstanceDNS"]}')
            rminstance = aws_functions.destroy_instance(env["Region"], env["InstanceID"])
            if aws_functions.isError(rminstance):
                logging.error(rminstance['Message'])
        else:
            logging.warning(f'Tests failed on {env.get("Role", "Unknown role")}, keeping instance alive')


if __name__ == "__main__":
    main()
