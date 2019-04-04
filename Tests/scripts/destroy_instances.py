import sys
from threading import Thread

from Tests.test_utils import run_command, run_threads_list


def main():
    circle_aritfact = sys.argv[1]
    with open('./Tests/instance_ips.txt', 'r') as instance_file:
        instance_ips = instance_file.readlines()
        instance_ips = [line.strip('\n').split(":") for line in instance_ips if line.strip() != '']

    with open('./Tests/instance_ids.txt', 'r') as instance_file:
        instance_ids = instance_file.readlines()
        instance_ids = [line.strip('\n').split(":") for line in instance_ids if line.strip() != '']
    threads_list = []
    for ami_instance_name, ami_instance_ip in instance_ips:
        for ami_instance_name_second, ami_instance_id in instance_ids:
            if ami_instance_name == ami_instance_name_second:
                t = Thread(target=run_command,
                           args=("./Tests/scripts/destroy_instances.sh {} {} {} ./Tests/is_build_failed_{}.txt".format(
                               circle_aritfact,
                               ami_instance_id,
                               ami_instance_ip,
                               ami_instance_name.replace(' ', '')),
                           ), kwargs={'is_silenced': False})
                threads_list.append(t)
    run_threads_list(threads_list)


if __name__ == "__main__":
    main()
