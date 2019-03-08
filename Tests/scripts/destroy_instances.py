from Tests.test_utils import run_command


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
                run_command("./Tests/scripts/destroy_instances.sh $CIRCLE_ARTIFACTS {} {}".format(ami_instance_id,
                                                                                                  ami_instance_ip))


if __name__ == "__main__":
    main()
