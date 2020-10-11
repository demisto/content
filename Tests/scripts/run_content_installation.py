"""Run content installation on the AMI instances"""
from time import sleep
from threading import Thread
from demisto_sdk.commands.common.tools import run_command, run_threads_list
import json


def main():
    with open('./env_results.json', 'r') as json_file:
        env_results = json.load(json_file)

    id_to_ip = [env["InstanceDNS"] for env in env_results]

    print("Waiting 60 Seconds for SSH to start\n")
    sleep(60)
    threads_list = []
    for instance_ip in id_to_ip:
        t = Thread(target=run_command,
                   args=("./Tests/scripts/copy_content_data.sh {}".format(instance_ip), ),
                   kwargs={'is_silenced': False})
        threads_list.append(t)

    run_threads_list(threads_list)


if __name__ == "__main__":
    main()
