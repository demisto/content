"""Wait for server to be ready for tests"""
import sys
from time import sleep
from subprocess import Popen, PIPE

HTTP_CODE = "{http_code}"
HTTP_CODE_REQUEST = "curl --write-out %{} --silent --output /dev/null {}/user -k -m 15"

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


def main():
    ready_ami_list = []
    with open('./Tests/instance_ips.txt', 'r') as instance_file:
        instance_ips = instance_file.readlines()
        instance_ips = [line.strip('\n').split(":") for line in instance_ips]

    print instance_ips
    for _ in range(MAX_TRIES * SLEEP_TIME):
        if len(instance_ips) > len(ready_ami_list):
            for ami_instance_name, ami_instance_ip in instance_ips:
                if ami_instance_name not in ready_ami_list:
                    http_code = run_bash_command(HTTP_CODE_REQUEST.format(HTTP_CODE, ami_instance_ip))
                    print "this is the bash command {}".format(http_code)
                    if http_code != "433" and http_code != "000":
                        print "{} is ready for use".format(ami_instance_name)
                        ready_ami_list.append(ami_instance_name)
                    else:
                        print "{} is not ready yet - wait another 45 seconds".format(ami_instance_name)

            if len(instance_ips) > len(ready_ami_list):
                sleep(1)

        else:
            break

    sleep(10)
    if len(ready_ami_list) != len(instance_ips):
        print_error("The server is not ready :(")
        sys.exit(1)


if __name__ == "__main__":
    main()
