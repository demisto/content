"""Wait for server to be ready for tests"""
import sys
from time import sleep
from ..test_utils import run_bash_command, print_error

HTTP_CODE = "{http_code}"
HTTP_CODE_REQUEST = "curl --write-out %{} --silent --output /dev/null {}/user -k"

MAX_TRIES = 20
SLEEP_TIME = 45


def main():
    ready_ami_list = []
    with open('./Tests/instance_ips.txt', 'r') as instance_file:
        instance_ips = instance_file.readlines()
        instance_ips = [line.strip('\n').split(":") for line in instance_ips]

    for _ in range(MAX_TRIES):
        if len(instance_ips) > len(ready_ami_list):
            for ami_instance_name, ami_instance_ip in instance_ips:
                if ami_instance_name not in ready_ami_list:
                    print "{} is not yet ready - wait another 45 seconds".format(ami_instance_name)
                    http_code = run_bash_command(HTTP_CODE_REQUEST.format(HTTP_CODE, ami_instance_ip))
                    if http_code != 433:
                        ready_ami_list.append(ami_instance_name)

            sleep(SLEEP_TIME)

        else:
            break

    if len(ready_ami_list) != len(instance_ips):
        print_error("The server is not ready :(")
        sys.exit(1)


if __name__ == "__main__":
    main()
