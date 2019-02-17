import sys
from subprocess import Popen


class LOG_COLORS:
    NATIVE = '\033[m'
    RED = '\033[01;31m'
    GREEN = '\033[01;32m'
    YELLOW = '\033[0;33m'


# print srt in the given color
def print_color(string, color):
    print(color + string + LOG_COLORS.NATIVE)


def print_error(error_str):
    print_color(error_str, LOG_COLORS.RED)


def run_bash_command(command, is_shell=False):
    p = Popen(command.split(), shell=is_shell)
    output, err = p.communicate()
    if err:
        print_error("Failed to run git command " + command)
        sys.exit(1)

    return output


def main():
    with open('./Tests/instance_ips.txt', 'r') as instance_file:
        instance_ips = instance_file.readlines()
        instance_ips = [line.strip().split(":") for line in instance_ips]

    with open('./Tests/instance_ids.txt', 'r') as instance_file:
        instance_ids = instance_file.readlines()
        instance_ids = [line.strip().split(":") for line in instance_ids]

    for ami_instance_name, ami_instance_ip in instance_ips:
        for ami_instance_name_second, ami_instance_id in instance_ids:
            if ami_instance_name == ami_instance_name_second:
                run_bash_command("./Tests/scripts/destroy_instances.sh $CIRCLE_ARTIFACTS {} {}".format(ami_instance_id,
                                                                                                       ami_instance_ip))


if __name__ == "__main__":
    main()
