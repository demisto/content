"""Wait for server to be ready for tests"""
import sys
import json
import argparse
from time import sleep
import datetime

import demisto

from Tests.test_utils import print_error


MAX_TRIES = 20
SLEEP_TIME = 45


def get_username_password():
    parser = argparse.ArgumentParser(description='Utility for batch action on incidents')
    parser.add_argument('-c', '--confPath', help='The path for the secret conf file', required=True)

    options = parser.parse_args()
    conf_path = options.confPath

    with open(conf_path, 'r') as conf_file:
        conf = json.load(conf_file)

    return conf['username'], conf['userPassword']


def main():
    username, password = get_username_password()

    ready_ami_list = []
    with open('./Tests/instance_ips.txt', 'r') as instance_file:
        instance_ips = instance_file.readlines()
        instance_ips = [line.strip('\n').split(":") for line in instance_ips]

    for i in range(MAX_TRIES * SLEEP_TIME):
        if len(instance_ips) > len(ready_ami_list):
            for ami_instance_name, ami_instance_ip in instance_ips:
                if ami_instance_name not in ready_ami_list:
                    c = demisto.DemistoClient(None, "https://{}".format(ami_instance_ip), username, password)
                    res = c.Login()
                    if res.status_code == 200:
                        print "[{}] {} is ready for use".format(datetime.datetime.now(), ami_instance_name)
                        ready_ami_list.append(ami_instance_name)
                    elif i % 30 == 0:  # printing the message every 30 seconds
                        print "{} is not ready yet - waiting for it to start".format(ami_instance_name)

            if len(instance_ips) > len(ready_ami_list):
                sleep(1)

        else:
            break

    if len(ready_ami_list) != len(instance_ips):
        print_error("The server is not ready :(")
        sys.exit(1)


if __name__ == "__main__":
    main()
