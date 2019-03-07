"""Run content installation on the AMI instances"""
import sys
from time import sleep
from subprocess import Popen


class LOG_COLORS:
    NATIVE = '\033[m'
    RED = '\033[01;31m'
    GREEN = '\033[01;32m'
    YELLOW = '\033[0;33m'


# print srt in the given color
def print_color(str, color):
    print(color + str + LOG_COLORS.NATIVE)


def print_error(error_str):
    print_color(error_str, LOG_COLORS.RED)


def run_bash_command(command, is_shell=False):
    p = Popen(command.split(), shell=is_shell)
    output, err = p.communicate()
    if err:
        print_error("Failed to run git command " + command)
        print_error(err)
        sys.exit(1)

    return output


def main():
    instance_ips = []
    with open('./Tests/instance_ids.txt', 'r') as instance_file:
        ami_instances = instance_file.readlines()
        ami_instances = [line.strip('\n').split(":") for line in ami_instances if line.strip('\n').split(":") != ['']]

    id_to_ip = {}
    for ami_instance_name, ami_instance_id in ami_instances:
        print "Validating ami instance: {}".format(ami_instance_name)
        run_bash_command("./Tests/scripts/get_instance_ip.sh {}".format(ami_instance_id))
        # get_instance_ip.sh script is writing the ip to instance_ips.txt because we couldn't get the ip
        # from the output of the aws script
        with open('./Tests/instance_ips.txt', 'r') as instance_file:
            instance_ip = instance_file.read()
            instance_ip = instance_ip.strip()

        print("The IP of the instance is {}\n".format(instance_ip))
        id_to_ip[ami_instance_id] = instance_ip

    print("Waiting 90 Seconds for SSH to start\n")
    sleep(90)

    for ami_instance_name, ami_instance_id in ami_instances:
        run_bash_command("./Tests/scripts/copy_content_data.sh {}".format(id_to_ip[ami_instance_id]))
        # copy_content_data.sh also starts the server
        instance_ips.append("{}:{}".format(ami_instance_name, id_to_ip[ami_instance_id]))

    with open('./Tests/instance_ips.txt', 'w') as instance_file:
        instance_file.write('\n'.join(instance_ips))

    sys.exit(0)


if __name__ == "__main__":
    main()
