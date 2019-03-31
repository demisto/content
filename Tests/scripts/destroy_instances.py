import sys

from Tests.test_utils import run_command


def main():
    circle_aritfact = sys.argv[1]
    with open('./Tests/instance_ips.txt', 'r') as instance_file:
        instance_ips = instance_file.readlines()
        instance_ips = [line.strip('\n').split(":") for line in instance_ips if line.strip() != '']

    with open('./Tests/instance_ids.txt', 'r') as instance_file:
        instance_ids = instance_file.readlines()
        instance_ids = [line.strip('\n').split(":") for line in instance_ids if line.strip() != '']

    for ami_instance_name, ami_instance_ip in instance_ips:
        for ami_instance_name_second, ami_instance_id in instance_ids:
            if ami_instance_name == ami_instance_name_second:
                run_command(
                    "./Tests/scripts/destroy_instances.sh {} {} {} ./Tests/is_build_failed_{}.txt".format(
                        circle_aritfact,
                        ami_instance_id,
                        ami_instance_ip,
                        ami_instance_name.replace(' ', '')
                    ), is_silenced=False)


if __name__ == "__main__":
    main()
