import sys
import os
import json
import subprocess
from demisto_sdk.commands.common.tools import print_warning, print_error
import Tests.scripts.awsinstancetool.aws_functions as aws_functions


def main():
    circle_aritfact = sys.argv[1]
    env_file = sys.argv[2]
    instance_role = sys.argv[3]
    with open(env_file, 'r') as json_file:
        env_results = json.load(json_file)

    filtered_results = [env_result for env_result in env_results if env_result["Role"] == instance_role]
    for env in filtered_results:
        print(f'Downloading server log from {env.get("Role", "Unknown role")}')
        ssh_string = 'ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {}@{} ' \
                     '"sudo chmod -R 755 /var/log/demisto"'
        scp_string = 'scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ' \
                     '{}@{}:/var/log/demisto/server.log {} || echo "WARN: Failed downloading server.log"'

        try:
            subprocess.check_output(
                ssh_string.format(env["SSHuser"], env["InstanceDNS"]), shell=True)

        except subprocess.CalledProcessError as exc:
            print(exc.output)

        try:
            subprocess.check_output(
                scp_string.format(
                    env["SSHuser"],
                    env["InstanceDNS"],
                    "{}/server_{}.log".format(circle_aritfact, env["Role"].replace(' ', ''))),
                shell=True)

        except subprocess.CalledProcessError as exc:
            print(exc.output)

        if os.path.isfile("./Tests/is_build_passed_{}.txt".format(env["Role"].replace(' ', ''))):
            print(f'Destroying instance {env.get("Role", "Unknown role")}')
            rminstance = aws_functions.destroy_instance(env["Region"], env["InstanceID"])
            if aws_functions.isError(rminstance):
                print_error(rminstance)
        else:
            print_warning(f'Tests failed on {env.get("Role", "Unknown role")}, keeping instance alive')


if __name__ == "__main__":
    main()
