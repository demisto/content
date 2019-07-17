import sys
import os
import subprocess
from Tests.scripts.awsinstancetool import aws_functions
# from threading import Thread

from Tests.test_utils import run_command, run_threads_list


def main():
    circle_aritfact = sys.argv[1]

    with open('./env_results.json', 'r') as json_file:
        env_results = json.load(json_file)

    for env in env_results:
        if os.path.isfile("./Tests/is_build_failed_{}.txt".format(env["Role"].replace(' ', ''))):
            subprocess.check_output("ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {}@${} \"sudo chmod -R 755 /var/log/demisto\"".format(env["SSHuser"],env["InstanceDNS"]), shell=True)
            subprocess.check_output("scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {}@{}:/var/log/demisto/server.log {} || echo \"WARN: Failed downloading server.log\"".format(env["SSHuser"],env["InstanceDNS"],circle_aritfact +
            "/server_{}.log".format(env["Role"].replace(' ', ''))) ,shell=True)
            rminstance = aws_functions.destroy_instance(env["Region"],env["InstanceID"])
            if aws_functions.isError(rminstance):
                print (ValueError(rminstance))


    # with open('./Tests/instance_ips.txt', 'r') as instance_file:
    #     instance_ips = instance_file.readlines()
    #     instance_ips = [line.strip('\n').split(":") for line in instance_ips if line.strip() != '']
    #
    # with open('./Tests/instance_ids.txt', 'r') as instance_file:
    #     instance_ids = instance_file.readlines()
    #     instance_ids = [line.strip('\n').split(":") for line in instance_ids if line.strip() != '']
    # threads_list = []
    # for ami_instance_name, ami_instance_ip in instance_ips:
    #     for ami_instance_name_second, ami_instance_id in instance_ids:
    #         if ami_instance_name == ami_instance_name_second:
    #             if os.path.isfile("./Tests/is_build_failed_{}.txt".format(ami_instance_name.replace(' ', ''))):
    #                 rminstance = aws_fuctions.destroy_instance("us-west-2",ami_instance_id)
    #                 if aws_fuctions.isError(rminstance):
    #                     print (rminstance)
                # t = Thread(target=run_command,
                #            args=("./Tests/scripts/destroy_instances.sh {} {} {} ./Tests/is_build_failed_{}.txt".format(
                #                circle_aritfact,
                #                ami_instance_id,
                #                ami_instance_ip,
                #                ami_instance_name.replace(' ', '')),
                #            ), kwargs={'is_silenced': False})
                # threads_list.append(t)
    # run_threads_list(threads_list)


if __name__ == "__main__":
    main()
