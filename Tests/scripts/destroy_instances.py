import json
import logging
import os
import shutil
import sys

import Tests.scripts.awsinstancetool.aws_functions as aws_functions  # pylint: disable=E0611,E0401

from Tests.scripts.utils.log_util import install_logging
import demisto_client


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
        try:
            logging.debug(f'Downloading server logs from server {env["InstanceDNS"]}')
            dmst_client = demisto_client.configure(base_url=f'https://localhost:{env["TunnelPort"]}', verify_ssl=False)
            tmp_file_path, _, _ = dmst_client.generic_request('/log/bundle', 'GET', response_type='file')

            server_ip = env["InstanceDNS"].split('.')[0]
            logs_dst = f"{circle_aritfact}/server_{env['Role'].replace(' ', '')}_{server_ip}_logs.tar.gz"
            copy_dst = shutil.copy(tmp_file_path, logs_dst)
            logging.info(f'Server logs saved in: {copy_dst}')

        except Exception:
            logging.exception(f'Failed downloading server logs from server {env["InstanceDNS"]}')

        if time_to_live:
            logging.info(f'Skipping - Time to live was set to {time_to_live} minutes')
            continue
        if os.path.isfile("./Tests/is_build_passed_{}.txt".format(env["Role"].replace(' ', ''))) and \
                os.path.isfile("./Tests/is_post_update_passed_{}.txt".format(env["Role"].replace(' ', ''))):
            logging.info(f'Destroying instance with role - {env.get("Role", "Unknown role")} and IP - '
                         f'{env["InstanceDNS"]}')
            rminstance = aws_functions.destroy_instance(env["Region"], env["InstanceID"])
            if aws_functions.isError(rminstance):
                logging.error(rminstance['Message'])
        else:
            logging.warning(f'Tests for some integration failed on {env.get("Role", "Unknown role")}'
                            f', keeping instance alive')


if __name__ == "__main__":
    main()
