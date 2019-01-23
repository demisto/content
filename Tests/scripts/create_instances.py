import argparse
from ..test_utils import run_bash_command, str2bool

SERVER_GA = "Demisto-Circle-CI-Content-GA*"
SERVER_MASTER = "Demisto-Circle-CI-Content-Master*"
SERVER_ONE_BEFORE_GA = "Demisto-Circle-CI-Content-OneBefore-GA*"
SERVER_TWO_BEFORE_GA = "Demisto-Circle-CI-Content-TwoBefore-GA*"

AMI_LIST = [SERVER_GA, SERVER_MASTER, SERVER_ONE_BEFORE_GA, SERVER_TWO_BEFORE_GA]

AMI_NAME_TO_READABLE = {
    SERVER_GA: "Demisto GA",
    SERVER_MASTER: "Server Master",
    SERVER_ONE_BEFORE_GA: "Demisto one before GA",
    SERVER_TWO_BEFORE_GA: "Demisto two before GA"
}


def is_nightly_build():
    parser = argparse.ArgumentParser(description='Utility creating an instance for Content build')
    parser.add_argument('-n', '--nightly', type=str2bool, help='Run nightly build')
    options = parser.parse_args()
    return options.nightly


def create_instance(ami_name):
    print "Creating instance from the AMI image for {}".format(AMI_NAME_TO_READABLE[ami_name])
    _ = run_bash_command("AMI_NAME='{}'".format(ami_name))
    _ = run_bash_command("./Tests/scripts/create_instance.sh instance.json")
    instance_id = run_bash_command("echo ${INSTANCE_ID}")
    return instance_id


def main():
    instance_ids = []
    if is_nightly_build():
        instance_ids.append(create_instance(SERVER_GA))

    else:
        for ami_name in AMI_LIST:
            instance_ids.append("{}:{}".format(AMI_NAME_TO_READABLE[ami_name], create_instance(ami_name)))

    with open('./Tests/instance_ids.txt', 'w') as instance_file:
        instance_file.write('\n'.join(instance_ids))


if __name__ == "__main__":
    main()
