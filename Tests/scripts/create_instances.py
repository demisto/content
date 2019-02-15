import sys
import argparse
from subprocess import Popen, PIPE

SERVER_GA = "Demisto-Circle-CI-Content-GA*"
SERVER_MASTER = "Demisto-Circle-CI-Content-Master*"
SERVER_ONE_BEFORE_GA = "Demisto-Circle-CI-Content-OneBefore-GA*"
SERVER_TWO_BEFORE_GA = "Demisto-Circle-CI-Content-TwoBefore-GA*"

AMI_LIST = [SERVER_GA, SERVER_MASTER, SERVER_ONE_BEFORE_GA, SERVER_TWO_BEFORE_GA]

AMI_NAME_TO_READABLE = {
    SERVER_GA: "Demisto GA",
    SERVER_MASTER: "Server Master",
    SERVER_ONE_BEFORE_GA: "Demisto one before GA",
    SERVER_TWO_BEFORE_GA: "Demisto two before GA"}


class LOG_COLORS:
    NATIVE = '\033[m'
    RED = '\033[01;31m'
    GREEN = '\033[01;32m'
    YELLOW = '\033[0;33m'


# print srt in the given color
def print_color(string, color):
    print(color + string + LOG_COLORS.NATIVE)


def print_error(error_str):
    print_color(error_str, LOG_COLORS.RED)


def str2bool(v):
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')


def run_bash_command(command, is_shell=False):
    p = Popen(command.split(), stdout=PIPE, stderr=PIPE, shell=is_shell)
    output, err = p.communicate()
    if err:
        print_error("Failed to run git command " + command)
        sys.exit(1)

    return output


def is_nightly_build():
    parser = argparse.ArgumentParser(description='Utility creating an instance for Content build')
    parser.add_argument('-n', '--nightly', type=str2bool, help='Run nightly build')
    options = parser.parse_args()
    return options.nightly


def create_instance(ami_name):
    print "Creating instance from the AMI image for {}".format(AMI_NAME_TO_READABLE[ami_name])
    run_bash_command("./Tests/scripts/create_instance.sh instance.json {}".format(ami_name))  # noqa
    instance_id = run_bash_command("echo $INSTANCE_ID")
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
