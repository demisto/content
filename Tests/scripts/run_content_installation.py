"""Run content installation on the AMI instances"""
from time import sleep
from threading import Thread
from Tests.test_utils import run_command, run_threads_list
import json


def main():
    instance_ips = []
    instance_ids = []

    id_to_ip = {}
    with open('./env_results.json', 'r') as json_file:
        env_results = json.load(json_file)

    for env in env_results:
        id_to_ip.update({env["InstanceID"]: env["InstanceDNS"]})
        instance_ips.append(env["Role"] + ":" + env["InstanceDNS"])
        instance_ids.append(env["Role"] + ":" + env["InstanceID"])
        with open('./Tests/images_data.txt', 'a') as instance_file:
            instance_file.write('{} Image info is: {} {} {}\n'.format(env["Role"], env["AmiId"], env["AmiName"],
                                                                      env["AmiCreation"]))

    with open('./Tests/instance_ids.txt', 'w') as instance_file:
        instance_file.write('\n'.join(instance_ids))

    print("Waiting 90 Seconds for SSH to start\n")
    sleep(90)
    threads_list = []
    for instance_ip in id_to_ip.values():
        t = Thread(target=run_command,
                   args=("./Tests/scripts/copy_content_data.sh {}".format(instance_ip), ),
                   kwargs={'is_silenced': False})
        threads_list.append(t)

    run_threads_list(threads_list)
    with open('./Tests/instance_ips.txt', 'w') as instance_file:
        instance_file.write('\n'.join(instance_ips))


if __name__ == "__main__":
    main()
