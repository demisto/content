import re
import os
import sys
import json
import argparse
from subprocess import Popen, PIPE
from distutils.version import LooseVersion
import yaml
import requests
from Tests.scripts.constants import CHECKED_TYPES_REGEXES, PACKAGE_SUPPORTING_DIRECTORIES, CONTENT_GITHUB_LINK, \
    PACKAGE_YML_FILE_REGEX, UNRELEASE_HEADER, RELEASE_NOTES_REGEX, PACKS_DIR_REGEX, PACKS_DIR

# disable insecure warnings
requests.packages.urllib3.disable_warnings()


class LOG_COLORS:
    NATIVE = '\033[m'
    RED = '\033[01;31m'
    GREEN = '\033[01;32m'
    YELLOW = '\033[0;33m'


# print srt in the given color
def print_color(obj, color):
    print(u'{}{}{}'.format(color, obj, LOG_COLORS.NATIVE))


def print_error(error_str):
    print_color(error_str, LOG_COLORS.RED)


def print_warning(warning_str):
    print_color(warning_str, LOG_COLORS.YELLOW)


def run_command(command, is_silenced=True, exit_on_error=True):
    """Run a bash command in the shell.

    Args:
        command (string): The string of the command you want to execute.
        is_silenced (bool): Whether to print command output.
        exit_on_error (bool): Whether to exit on command error.

    Returns:
        string. The output of the command you are trying to execute.
    """
    if is_silenced:
        p = Popen(command.split(), stdout=PIPE, stderr=PIPE, universal_newlines=True)
    else:
        p = Popen(command.split())

    output, err = p.communicate()
    if err:
        if exit_on_error:
            print_error('Failed to run command {}\nerror details:\n{}'.format(command, err))
            sys.exit(1)
        else:
            raise RuntimeError('Failed to run command {}\nerror details:\n{}'.format(command, err))

    return output


def get_remote_file(full_file_path, tag='master'):
    # 'origin/' prefix is used to compared with remote branches but it is not a part of the github url.
    tag = tag.lstrip('origin/')

    # The replace in the end is for Windows support
    github_path = os.path.join(CONTENT_GITHUB_LINK, tag, full_file_path).replace('\\', '/')
    try:
        res = requests.get(github_path, verify=False)
        res.raise_for_status()
    except Exception as exc:
        print_warning('Could not find the old entity file under "{}".\n'
                      'please make sure that you did not break backward compatibility. '
                      'Reason: {}'.format(github_path, exc))
        return {}

    if full_file_path.endswith('json'):
        details = json.loads(res.content)
    else:
        details = yaml.safe_load(res.content)

    return details


def filter_packagify_changes(modified_files, added_files, removed_files, tag='master'):
    """
    Mark scripts/integrations that were removed and added as modifiied.

    :param modified_files: list of modified files in branch
    :param added_files: list of new files in branch
    :param removed_files: list of removed files in branch
    :param tag: tag of compared revision

    :return: tuple of updated lists: (modified_files, updated_added_files, removed_files)
    """
    # map IDs to removed files
    packagify_diff = {}  # type: dict
    for file_path in removed_files:
        if file_path.split("/")[0] in PACKAGE_SUPPORTING_DIRECTORIES:
            details = get_remote_file(file_path, tag)
            if details:
                uniq_identifier = '_'.join([
                    details['name'],
                    details.get('fromversion', '0.0.0'),
                    details.get('toversion', '99.99.99')
                ])
                packagify_diff[uniq_identifier] = file_path

    updated_added_files = set()
    for file_path in added_files:
        if file_path.split("/")[0] in PACKAGE_SUPPORTING_DIRECTORIES:
            with open(file_path) as f:
                details = yaml.safe_load(f.read())

            uniq_identifier = '_'.join([
                details['name'],
                details.get('fromversion', '0.0.0'),
                details.get('toversion', '99.99.99')
            ])
            if uniq_identifier in packagify_diff:
                # if name appears as added and removed, this is packagify process - treat as modified.
                removed_files.remove(packagify_diff[uniq_identifier])
                modified_files.add((packagify_diff[uniq_identifier], file_path))
                continue

        updated_added_files.add(file_path)

    # remove files that are marked as both "added" and "modified"
    for file_path in modified_files:
        if isinstance(file_path, tuple):
            updated_added_files -= {file_path[1]}
        else:
            updated_added_files -= {file_path}

    return modified_files, updated_added_files, removed_files


def get_last_release_version():
    """
    Get latest release tag (xx.xx.xx)

    :return: tag
    """
    tags = run_command('git tag').split('\n')
    tags = [tag for tag in tags if re.match(r'\d+\.\d+\.\d+', tag) is not None]
    tags.sort(key=LooseVersion, reverse=True)

    return tags[0]


def get_file(method, file_path, type_of_file):
    data_dictionary = None
    with open(os.path.expanduser(file_path), "r") as f:
        if file_path.endswith(type_of_file):
            try:
                data_dictionary = method(f)
            except Exception as e:
                print_error(
                    "{} has a structure issue of file type{}. Error was: {}".format(file_path, type_of_file, str(e)))
                return {}
    if type(data_dictionary) is dict:
        return data_dictionary
    return {}


def get_yaml(file_path):
    return get_file(yaml.safe_load, file_path, ('yml', 'yaml'))


def get_json(file_path):
    return get_file(json.load, file_path, 'json')


def get_script_or_integration_id(file_path):
    data_dictionary = get_yaml(file_path)

    if data_dictionary:
        commonfields = data_dictionary.get('commonfields', {})
        return commonfields.get('id', ['-', ])


def collect_ids(file_path):
    """Collect id mentioned in file_path"""
    data_dictionary = get_yaml(file_path)

    if data_dictionary:
        return data_dictionary.get('id', '-')


def get_from_version(file_path):
    data_dictionary = get_yaml(file_path)

    if data_dictionary:
        from_version = data_dictionary.get('fromversion', '0.0.0')
        if from_version == "":
            return "0.0.0"

        if not re.match(r"^\d{1,2}\.\d{1,2}\.\d{1,2}$", from_version):
            raise ValueError("{} fromversion is invalid \"{}\". "
                             "Should be of format: \"x.x.x\". for example: \"4.5.0\"".format(file_path, from_version))

        return from_version

    return '0.0.0'


def get_to_version(file_path):
    data_dictionary = get_yaml(file_path)

    if data_dictionary:
        to_version = data_dictionary.get('toversion', '99.99.99')
        if not re.match(r"^\d{1,2}\.\d{1,2}\.\d{1,2}$", to_version):
            raise ValueError("{} toversion is invalid \"{}\". "
                             "Should be of format: \"x.x.x\". for example: \"4.5.0\"".format(file_path, to_version))

        return to_version

    return '99.99.99'


def str2bool(v):
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True

    if v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False

    raise argparse.ArgumentTypeError('Boolean value expected.')


def get_release_notes_file_path(file_path):
    dir_name = os.path.dirname(file_path)

    if re.match(PACKAGE_YML_FILE_REGEX, file_path):
        return os.path.join(dir_name, 'CHANGELOG.md')

    # outside of packages, change log file will include the original file name.
    file_name = os.path.basename(file_path)
    return os.path.join(dir_name, os.path.splitext(file_name)[0] + '_CHANGELOG.md')


def get_latest_release_notes_text(rn_path):
    if not os.path.isfile(rn_path):
        # releaseNotes were not provided
        return None

    with open(rn_path) as f:
        rn = f.read()

    if not rn:
        # empty releaseNotes is not supported
        return None

    new_rn = re.findall(RELEASE_NOTES_REGEX, rn)
    if new_rn:
        # get release notes up to release header
        new_rn = new_rn[0].rstrip()
    else:
        new_rn = rn.replace(UNRELEASE_HEADER, '')

    return new_rn if new_rn else None


def checked_type(file_path, compared_regexes=None):
    compared_regexes = compared_regexes or CHECKED_TYPES_REGEXES
    if any(re.match(regex, file_path, re.IGNORECASE) for regex in compared_regexes):
        return True
    return False


def server_version_compare(v1, v2):
    """compare Demisto versions

    Args:
        v1 (string): string representing Demisto version (first comparable)
        v2 (string): string representing Demisto version (second comparable)


    Returns:
        int.
        0 for equal versions.
        positive if v1 later version than v2.
        negative if v2 later version than v1.
    """

    v1 = re.sub('[\'\"]', '', v1)
    v2 = re.sub('[\'\"]', '', v2)

    if v1 == "" or v2 == "":
        return 0

    v1_nums = [int(d) for d in v1.split(".")]
    v2_nums = [int(d) for d in v2.split(".")]

    for i in range(min(len(v1_nums), len(v2_nums))):
        if v1_nums[i] != v2_nums[i]:
            return v1_nums[i] - v2_nums[i]

    # versions are equal to the i th number

    # versions are equal
    return 0


def run_threads_list(threads_list):
    """
    Start a list of threads and wait for completion (join)

    Arguments:
        threads_list (list of threads) -- list of threads to start and wait for join
    """
    # run each command in a separate thread
    for t in threads_list:
        t.start()
    # wait for the commands to complete
    for t in threads_list:
        t.join()


def get_dockerimage45(script_object):
    """Get the docker image used up to 4.5 (including).

    Arguments:
        script_object {dict} -- [script object containing the dockerimage configuration]
    """
    if 'dockerimage45' in script_object:
        return script_object['dockerimage45']
    return script_object.get('dockerimage', '')


def is_file_path_in_pack(file_path):
    return bool(re.findall(PACKS_DIR_REGEX, file_path))


def get_pack_name(file_path):
    match = re.search(r'^(?:./)?{}/([^/]+)/'.format(PACKS_DIR), file_path)
    return match.group(1) if match else None


def pack_name_to_path(pack_name):
    return os.path.join(PACKS_DIR, pack_name)


class Docker:
    """ Client for running docker commands on remote machine using ssh connection.

    """
    PYTHON_INTEGRATION_TYPE = 'python'
    JAVASCRIPT_INTEGRATION_TYPE = 'javascript'
    DEFAULT_PYTHON2_IMAGE = 'demisto/python'
    DEFAULT_PYTHON3_IMAGE = 'demisto/python3'
    COMMAND_FORMAT = '{{json .}}'
    MEMORY_USAGE = 'MemUsage'
    PIDS_USAGE = 'PIDs'
    CONTAINER_NAME = 'Name'
    DEFAULT_CONTAINER_MEMORY_USAGE = 75
    DEFAULT_CONTAINER_PIDS_USAGE = 3
    REMOTE_MACHINE_USER = 'ec2-user'
    SSH_OPTIONS = 'ssh -o StrictHostKeyChecking=no'

    @classmethod
    def _build_stats_cmd(cls, server_ip, docker_images):
        """ Builds docker stats and grep command string.

        Example of returned value:
        ssh -o StrictHostKeyChecking=no ec2-user@server_ip
        'sudo docker stats --no-stream --no-trunc --format "{{json .}}" | grep -Ei "demistopython33.7.2.214--"'
        Grep is based on docker images names regex.

            Args:
                server_ip (str): Remote machine ip to connect using ssh.
                docker_images (set): Set of docker images.

            Returns:
                str: String command to run later as subprocess.

        """
        # docker stats command with json output
        docker_command = 'sudo docker stats --no-stream --no-trunc --format "{}"'.format(cls.COMMAND_FORMAT)
        # replacing : and / in docker images names in order to grep the stats by container name
        docker_images_regex = ['{}--'.format(re.sub('[:/]', '', docker_image)) for docker_image in docker_images]
        pipe = ' | '
        grep_command = 'grep -Ei "{}"'.format('|'.join(docker_images_regex))
        remote_command = docker_command + pipe + grep_command
        remote_server = '{}@{}'.format(cls.REMOTE_MACHINE_USER, server_ip)
        ssh_prefix = '{} {}'.format(cls.SSH_OPTIONS, remote_server)
        # escaping the remote command with single quotes
        cmd = "{} '{}'".format(ssh_prefix, remote_command)

        return cmd

    @classmethod
    def _build_kill_cmd(cls, server_ip, container_name):
        """ Constructs docker kll command string to run on remote machine.

            Args:
                server_ip (str): Remote machine ip to connect using ssh.
                container_name (str): Docker container name to kill.

            Returns:
                str: String of docker kill command on remote machine.
        """
        remote_command = 'sudo docker kill {}'.format(container_name)
        remote_server = '{}@{}'.format(cls.REMOTE_MACHINE_USER, server_ip)
        ssh_prefix = '{} {}'.format(cls.SSH_OPTIONS, remote_server)
        cmd = "{} '{}'".format(ssh_prefix, remote_command)

        return cmd

    @classmethod
    def _parse_stats_result(cls, stats_lines):
        """Parses the docker statics str and converts to Mib.

            Args:
                stats_lines (str): String that contains docker stats.
            Returns:
                list: List of dictionaries with parsed docker container statistics.

        """
        stats_result = []
        try:
            containers_stats = [json.loads(c) for c in stats_lines.splitlines()]

            for container_stat in containers_stats:
                memory_usage_stats = container_stat.get(cls.MEMORY_USAGE, '').split('/')[0].lower()

                if 'kib' in memory_usage_stats:
                    mib_usage = float(memory_usage_stats.replace('kib', '').strip()) / 1024
                elif 'gib' in memory_usage_stats:
                    mib_usage = float(memory_usage_stats.replace('kib', '').strip()) * 1024
                else:
                    mib_usage = float(memory_usage_stats.replace('mib', '').strip())

                pids_number = int(container_stat.get(cls.PIDS_USAGE))
                container_name = container_stat.get(cls.CONTAINER_NAME)
                stats_result.append({'memory_usage': mib_usage, 'pids': pids_number, 'container_name': container_name})
        except Exception as e:
            print_warning("Failed in parsing docker stats result, returned empty list. Additional info: {}".format(e))
        finally:
            return stats_result

    @classmethod
    def get_integration_image(cls, integration_config):
        """ Returns docker image of integration that was configured using rest api call via demisto_client

            Args:
                integration_config (dict): Integration config that included script section.
            Returns:
                list: List that includes integration docker image name. If no docker image was found,
                      default python2 and python3 images are returned.

        """
        integration_script = integration_config.get('configuration', {}).get('integrationScript', {}) or {}
        integration_type = integration_script.get('type')
        docker_image = integration_script.get('dockerImage')

        if integration_type == cls.JAVASCRIPT_INTEGRATION_TYPE:
            return None
        elif integration_type == cls.PYTHON_INTEGRATION_TYPE and docker_image:
            return [docker_image]
        else:
            return [cls.DEFAULT_PYTHON2_IMAGE, cls.DEFAULT_PYTHON3_IMAGE]

    @classmethod
    def docker_stats(cls, server_ip, docker_images):
        """ Executes docker stats command and greps all containers with prefix of docker images names.

            Args:
                server_ip (str): Remote machine ip to connect using ssh.
                docker_images (set): Set of docker images to check their resource usage.

            Returns:
                list: List of dictionaries with parsed container memory statistics.
        """
        cmd = cls._build_stats_cmd(server_ip, docker_images)
        process = Popen(cmd, stdout=PIPE, stderr=PIPE, shell=True, universal_newlines=True)
        stdout, stderr = process.communicate()

        if stderr:
            print_warning("Failed running docker stats command. Additional information: {}".format(stderr))
            return []

        return cls._parse_stats_result(stdout)

    @classmethod
    def kill_container(cls, server_ip, container_name):
        """ Executes docker kill command on remote machine using ssh.

            Args:
                server_ip (str): The remote server ip address.
                container_name (str): The container name to kill

        """
        cmd = cls._build_kill_cmd(server_ip, container_name)

        process = Popen(cmd, stdout=PIPE, stderr=PIPE, shell=True, universal_newlines=True)
        stdout, stderr = process.communicate()

        if stderr:
            print_warning("Failed killing container: {}\nAdditional information: {}".format(container_name, stderr))

    @classmethod
    def check_resource_usage(cls, server_url, docker_images, memory_threshold, pids_threshold):
        """
        Executes docker stats command on remote machine and returns error message in case of exceeding threshold.

        Args:
            server_url (str): Target machine full url.
            docker_images (set): Set of docker images to check their resource usage.
            memory_threshold (int): Memory threshold of specific docker container, in Mib.
            pids_threshold (int): PIDs threshold of specific docker container, in Mib.

        Returns:
            str: The error message. Empty in case that resource check passed.

        """
        server_ip = server_url.lstrip("https://")
        containers_stats = cls.docker_stats(server_ip, docker_images)
        error_message = ""

        for container_stat in containers_stats:
            failed_memory_test = False
            container_name = container_stat['container_name']
            memory_usage = container_stat['memory_usage']
            pids_usage = container_stat['pids']

            if memory_usage > memory_threshold:
                error_message += ('Failed docker resource test. Docker container {} exceeded the memory threshold, '
                                  'configured: {} MiB and actual memory usage is {} MiB.\n'
                                  .format(container_name, memory_threshold, memory_usage))
                failed_memory_test = True
            if pids_usage > pids_threshold:
                error_message += ('Failed docker resource test. Docker container {} exceeded the pids threshold, '
                                  'configured: {} and actual pid number is {}.\n'.
                                  format(container_name, pids_threshold, pids_usage))
                failed_memory_test = True

            if failed_memory_test:
                # killing current container in case of memory resource test failure
                cls.kill_container(server_ip, container_name)

        return error_message
