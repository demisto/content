import re
import os
import sys
import yaml
import json
import requests
import argparse
from subprocess import Popen, PIPE
from distutils.version import LooseVersion

from Tests.scripts.constants import CHECKED_TYPES_REGEXES, PACKAGE_SUPPORTING_DIRECTORIES, CONTENT_GITHUB_LINK, \
    PACKAGE_YML_FILE_REGEX, UNRELEASE_HEADER, RELEASE_NOTES_REGEX

# disable insecure warnings
requests.packages.urllib3.disable_warnings()


class LOG_COLORS:
    NATIVE = '\033[m'
    RED = '\033[01;31m'
    GREEN = '\033[01;32m'
    YELLOW = '\033[0;33m'


# print srt in the given color
def print_color(str, color):
    print(color + str + LOG_COLORS.NATIVE)


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
                uniq_identifier = '_'.join([details['name'],
                                           details.get('fromversion', '0.0.0'),
                                           details.get('toversion', '99.99.99')])
                packagify_diff[uniq_identifier] = file_path

    updated_added_files = set()
    for file_path in added_files:
        if file_path.split("/")[0] in PACKAGE_SUPPORTING_DIRECTORIES:
            with open(file_path) as f:
                details = yaml.safe_load(f.read())

            uniq_identifier = '_'.join([details['name'],
                                        details.get('fromversion', '0.0.0'),
                                        details.get('toversion', '99.99.99')])
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


def get_yaml(file_path):
    data_dictionary = None
    with open(os.path.expanduser(file_path), "r") as f:
        if file_path.endswith(".yaml") or file_path.endswith('.yml'):
            try:
                data_dictionary = yaml.safe_load(f)
            except Exception as e:
                print_error(file_path + " has yml structure issue. Error was: " + str(e))
                return []

    if type(data_dictionary) is dict:
        return data_dictionary
    else:
        return {}


def get_json(file_path):
    data_dictionary = None
    with open(os.path.expanduser(file_path), "r") as f:
        if file_path.endswith(".json"):
            try:
                data_dictionary = json.load(f)
            except Exception as e:
                print_error(file_path + " has json structure issue. Error was: " + str(e))
                return []

    if type(data_dictionary) is dict:
        return data_dictionary
    else:
        return {}


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


def get_to_version(file_path):
    data_dictionary = get_yaml(file_path)

    if data_dictionary:
        to_version = data_dictionary.get('toversion', '99.99.99')
        if not re.match(r"^\d{1,2}\.\d{1,2}\.\d{1,2}$", to_version):
            raise ValueError("{} toversion is invalid \"{}\". "
                             "Should be of format: \"x.x.x\". for example: \"4.5.0\"".format(file_path, to_version))

        return to_version


def str2bool(v):
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')


def get_release_notes_file_path(file_path):
    dir_name = os.path.dirname(file_path)

    if re.match(PACKAGE_YML_FILE_REGEX, file_path):
        return os.path.join(dir_name, 'CHANGELOG.md')
    else:
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


def checked_type(file_path, compared_regexes=CHECKED_TYPES_REGEXES):
    for regex in compared_regexes:
        if re.match(regex, file_path, re.IGNORECASE):
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
