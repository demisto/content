import argparse

from demisto_sdk.commands.common.tools import str2bool, run_command
from demisto_sdk.commands.common.constants import FILTER_CONF, RUN_ALL_TESTS_FORMAT


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


def options_handler():
    parser = argparse.ArgumentParser(description='Utility creating an instance for Content build')
    parser.add_argument('-n', '--nightly', type=str2bool, help='Run nightly build')
    parser.add_argument('-b', '--branch', help='Branch Name')
    options = parser.parse_args()
    return options.nightly, options.branch


def create_instance(ami_name):
    print("Creating instance from the AMI image for {}".format(AMI_NAME_TO_READABLE[ami_name]))
    run_command("./Tests/scripts/create_instance.sh instance.json {}".format(ami_name), False)  # noqa
    with open('./Tests/instance_ids.txt', 'r') as instance_file:
        instance_id = instance_file.read()
    with open('image_id.txt', 'r') as image_id_file:
        image_data = image_id_file.read()
        print('Image data is {}'.format(image_data))
        with open("./Tests/images_data.txt", "a") as image_data_file:
            image_data_file.write(
                '{name} Image info is: {data}\n'.format(name=AMI_NAME_TO_READABLE[ami_name], data=image_data))
    return instance_id


def is_run_all():
    with open(FILTER_CONF, 'r') as filter_file:
        filtered_tests = filter_file.readlines()
        filtered_tests = [line.strip('\n') for line in filtered_tests]
        run_all = True if RUN_ALL_TESTS_FORMAT in filtered_tests else False

    return run_all


def main():
    instance_ids = []
    is_nightly_build, branch_name = options_handler()
    run_all = is_run_all()
    if is_nightly_build or branch_name == 'master' or run_all:
        instance_ids.append("{}:{}".format(AMI_NAME_TO_READABLE[SERVER_GA], create_instance(SERVER_GA)))

    else:
        for ami_name in AMI_LIST:
            instance_ids.append("{}:{}".format(AMI_NAME_TO_READABLE[ami_name], create_instance(ami_name)))

    with open('./Tests/instance_ids.txt', 'w') as instance_file:
        instance_file.write('\n'.join(instance_ids))


if __name__ == "__main__":
    main()
