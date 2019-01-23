"""Run content installation on the AMI instances"""
from ..test_utils import run_bash_command


def main():
    instance_ips = []
    with open('./Tests/instance_ids.txt', 'r') as instance_file:
        ami_instances = instance_file.readlines()
        ami_instances = [line.strip('\n').split(":") for line in ami_instances]

    for ami_instance_name, ami_instance_id in ami_instances:
        print "running content installation for ami instance: {}".format(ami_instance_name)
        _ = run_bash_command("./Tests/scripts/run_installer_on_instance.sh {}".format(ami_instance_id))
        instance_ips.append("{}:{}".format(ami_instance_name, run_bash_command("echo ${PUBLIC_IP}")))

    with open('./Tests/instance_ips.txt', 'w') as instance_file:
        instance_file.write('\n'.join(instance_ips))


if __name__ == "__main__":
    main()
