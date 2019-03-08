"""Run content installation on the AMI instances"""
from time import sleep

from Tests.test_utils import run_command


def main():
    instance_ips = []
    with open('./Tests/instance_ids.txt', 'r') as instance_file:
        ami_instances = instance_file.readlines()
        ami_instances = [line.strip('\n').split(":") for line in ami_instances if line.strip('\n').split(":") != ['']]

    id_to_ip = {}
    for ami_instance_name, ami_instance_id in ami_instances:
        print "Validating ami instance: {}".format(ami_instance_name)
        run_command("./Tests/scripts/get_instance_ip.sh {}".format(ami_instance_id))
        # get_instance_ip.sh script is writing the ip to instance_ips.txt because we couldn't get the ip
        # from the output of the aws script
        with open('./Tests/instance_ips.txt', 'r') as instance_file:
            instance_ip = instance_file.read()
            instance_ip = instance_ip.strip()

        print("The IP of the instance is {}\n".format(instance_ip))
        id_to_ip[ami_instance_id] = instance_ip

    print("Waiting 90 Seconds for SSH to start\n")
    sleep(90)

    for ami_instance_name, ami_instance_id in ami_instances:
        run_command("./Tests/scripts/copy_content_data.sh {}".format(id_to_ip[ami_instance_id]))
        # copy_content_data.sh also starts the server
        instance_ips.append("{}:{}".format(ami_instance_name, id_to_ip[ami_instance_id]))

    with open('./Tests/instance_ips.txt', 'w') as instance_file:
        instance_file.write('\n'.join(instance_ips))


if __name__ == "__main__":
    main()
