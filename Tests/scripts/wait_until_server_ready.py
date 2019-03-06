"""Wait for server to be ready for tests"""
import sys
import argparse
from time import sleep
from subprocess import Popen, PIPE

import demisto


MAX_TRIES = 20
SLEEP_TIME = 45


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


def run_bash_command(command):
    p = Popen(command.split(), stdout=PIPE, stderr=PIPE)
    output, err = p.communicate()
    if err:
        print_error("Failed to run git command " + command)
        sys.exit(1)

    return output


def options_handler():
    parser = argparse.ArgumentParser(description='Utility for batch action on incidents')
    parser.add_argument('-u', '--user', help='The username for the login', required=True)
    parser.add_argument('-p', '--password', help='The password for the login', required=True)

    options = parser.parse_args()
    return options


def main():
    options = options_handler()
    username = options.user
    password = options.password

    ready_ami_list = []
    with open('./Tests/instance_ips.txt', 'r') as instance_file:
        instance_ips = instance_file.readlines()
        instance_ips = [line.strip('\n').split(":") for line in instance_ips]

    print instance_ips
    for _ in range(MAX_TRIES * SLEEP_TIME):
        if len(instance_ips) > len(ready_ami_list):
            for ami_instance_name, ami_instance_ip in instance_ips:
                if ami_instance_name not in ready_ami_list:
                    c = demisto.DemistoClient(None, "https://{}".format(ami_instance_ip), username, password)
                    res = c.Login()
                    if res.status_code == 200:
                        print "{} is ready for use".format(ami_instance_name)
                        ready_ami_list.append(ami_instance_name)
                    else:
                        print "{} is not ready yet - wait another 45 seconds".format(ami_instance_name)

            if len(instance_ips) > len(ready_ami_list):
                sleep(1)

        else:
            break

    if len(ready_ami_list) != len(instance_ips):
        print_error("The server is not ready :(")
        sys.exit(1)


if __name__ == "__main__":
    main()
