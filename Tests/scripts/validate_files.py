"""
This script is used to validate the files in Content repository. Specifically for each file:
1) Proper prefix
2) Proper suffix
3) Valid yml/json schema
4) Having ReleaseNotes if applicable.

It can be run to check only committed changes (if the first argument is 'true') or all the files in the repo.
Note - if it is run for all the files in the repo it won't check releaseNotes, use `release_notes.py`
for that task.
"""
import os
import re
import sys
import glob
import logging
import argparse
import subprocess

from Tests.scripts.constants import *
from Tests.scripts.hook_validations.id import IDSetValidator
from Tests.scripts.hook_validations.secrets import get_secrets
from Tests.scripts.hook_validations.image import ImageValidator
from Tests.scripts.hook_validations.description import DescriptionValidator
from Tests.scripts.update_id_set import get_script_package_data
from Tests.scripts.hook_validations.script import ScriptValidator
from Tests.scripts.hook_validations.conf_json import ConfJsonValidator
from Tests.scripts.hook_validations.structure import StructureValidator
from Tests.scripts.hook_validations.integration import IntegrationValidator
from Tests.test_utils import checked_type, run_command, print_error, collect_ids, print_color, str2bool, LOG_COLORS, \
    get_yaml, filter_packagify_changes


class FilesValidator(object):
    """FilesValidator is a class that's designed to validate all the changed files on your branch, and all files in case
    you are on master, this class will be used on your local env as the validation hook(pre-commit), and on CircleCi
    to make sure you did not bypass the hooks as a safety precaution.

    Attributes:
        _is_valid (bool): saves the status of the whole validation(instead of mingling it between all the functions).
        is_circle (bool): whether we are running on circle or local env.
        conf_json_validator (ConfJsonValidator): object for validating the conf.json file.
        id_set_validator (IDSetValidator): object for validating the id_set.json file(Created in Circle only).
    """

    def __init__(self, is_circle=False):
        self._is_valid = True
        self.is_circle = is_circle

        self.conf_json_validator = ConfJsonValidator()
        self.id_set_validator = IDSetValidator(is_circle)

    @staticmethod
    def is_py_script_or_integration(file_path):
        file_yml = get_yaml(file_path)
        if re.match(INTEGRATION_REGEX, file_path, re.IGNORECASE):
            if file_yml.get('script', {}).get('type', 'javascript') != 'python':
                return False

            return True

        elif re.match(SCRIPT_REGEX, file_path, re.IGNORECASE):
            if file_yml.get('type', 'javascript') != 'python':
                return False

            return True

        return False

    @staticmethod
    def get_modified_files(files_string, tag='master'):
        """Get lists of the modified files in your branch according to the files string.

        Args:
            files_string (string): String that was calculated by git using `git diff` command.
            tag (string): String of git tag used to update modified files

        Returns:
            (modified_files_list, added_files_list, deleted_files). Tuple of sets.
        """
        all_files = files_string.split('\n')
        deleted_files = set([])
        added_files_list = set([])
        modified_files_list = set([])
        old_format_files = set([])
        for f in all_files:
            file_data = f.split()
            if not file_data:
                continue

            file_status = file_data[0]
            file_path = file_data[1]

            if file_status.lower().startswith('r'):
                file_status = 'r'
                file_path = file_data[2]

            if checked_type(file_path, CODE_FILES_REGEX) and file_status.lower() != 'd' \
                    and not file_path.endswith('_test.py'):
                # naming convention - code file and yml file in packages must have same name.
                file_path = os.path.splitext(file_path)[0] + '.yml'
            elif file_path.endswith('.js') or file_path.endswith('.py'):
                continue

            if file_status.lower() in ['m', 'a', 'r'] and checked_type(file_path, OLD_YML_FORMAT_FILE) and \
                    FilesValidator.is_py_script_or_integration(file_path):
                old_format_files.add(file_path)
            elif file_status.lower() == 'm' and checked_type(file_path) and not file_path.startswith('.'):
                modified_files_list.add(file_path)
            elif file_status.lower() == 'a' and checked_type(file_path) and not file_path.startswith('.'):
                added_files_list.add(file_path)
            elif file_status.lower() == 'd' and checked_type(file_path) and not file_path.startswith('.'):
                deleted_files.add(file_path)
            elif file_status.lower().startswith('r') and checked_type(file_path):
                modified_files_list.add((file_data[1], file_data[2]))
            elif checked_type(file_path, [SCHEMA_REGEX]):
                modified_files_list.add(file_path)
            elif file_status.lower() not in KNOWN_FILE_STATUSES:
                print_error(file_path + " file status is an unknown known one, "
                                        "please check. File status was: " + file_status)

        modified_files_list, added_files_list, deleted_files = filter_packagify_changes(
            modified_files_list,
            added_files_list,
            deleted_files,
            tag)

        return modified_files_list, added_files_list, deleted_files, old_format_files

    def get_modified_and_added_files(self, branch_name, is_circle, tag='master'):
        """Get lists of the modified and added files in your branch according to the git diff output.

        Args:
            branch_name (string): The name of the branch we are working on.
            is_circle (bool): Whether we are running on circle or local env.
            tag (string): String of git tag used to update modified files

        Returns:
            (modified_files, added_files). Tuple of sets.
        """
        all_changed_files_string = run_command(
            "git diff --name-status origin/{tag}...refs/heads/{branch}".format(tag=tag, branch=branch_name))
        modified_files, added_files, _, old_format_files = self.get_modified_files(all_changed_files_string)

        if not is_circle:
            files_string = run_command("git diff --name-status --no-merges HEAD")

            non_committed_modified_files, non_committed_added_files, non_committed_deleted_files, \
            non_committed_old_format_files = self.get_modified_files(files_string)
            all_changed_files_string = run_command("git diff --name-status origin/{}".format(tag))
            modified_files_from_tag, added_files_from_tag, _, _ = \
                self.get_modified_files(all_changed_files_string)

            old_format_files = old_format_files.union(non_committed_old_format_files)
            for mod_file in modified_files_from_tag:
                if mod_file in non_committed_modified_files:
                    modified_files.add(mod_file)

            for add_file in added_files_from_tag:
                if add_file in non_committed_added_files:
                    added_files.add(add_file)

            modified_files = modified_files - set(non_committed_deleted_files)
            added_files = added_files - set(non_committed_modified_files) - set(non_committed_deleted_files)

            # new_added_files = set([])
            # for added_file in added_files:
            #     if added_file in non_committed_added_files:
            #         new_added_files.add(added_file)

            # added_files = new_added_files

        return modified_files, added_files, old_format_files

    @staticmethod
    def get_previous_release_branch(release_branch_name):
        """Get previous release branch

        Args:
            release_branch_name (string): Release branch to compare to

        Returns:
            (string). Release version prior to release_branch_name
        """
        try:
            year, month, ver = release_branch_name.split('.')
            if ver == '0':
                month = int(month) - 1
                if month < 1:
                    month = 12
                    year = int(year) - 1
                prev_ver_prefix = 'origin/{year}.{month}.*'.format(year=year, month=month)
                git_prev_versions = run_command("git branch -a --list {}".format(prev_ver_prefix)).decode(
                    'utf8').strip().split('\n')
                git_prev_versions.sort()
                # No branches were found
                if not git_prev_versions:
                    return ''
                # Deal with branches of type 'year.month.ver*' whereas * is not empty
                i = -1
                prev_ver = git_prev_versions[i]
                # TODO: Discuss this solution, and try to think of a better one
                while len(git_prev_versions[i]) != len(git_prev_versions[0]):
                    prev_ver = git_prev_versions[i]
                    i -= 1
                return prev_ver
            ver = int(ver) - 1
            return '{year}.{month}.{ver}'.format(year=year, month=month, ver=ver)
        except ValueError:
            # Wrong input
            return ''

    def validate_modified_files(self, modified_files, is_backward_check=True):
        """Validate the modified files from your branch.

        In case we encounter an invalid file we set the self._is_valid param to False.

        Args:
            modified_files (set): A set of the modified files in the current branch.
            is_backward_check (bool): When set to True will run backward compatibility checks
        """
        for file_path in modified_files:
            old_file_path = None
            if isinstance(file_path, tuple):
                old_file_path, file_path = file_path

            print("Validating {}".format(file_path))
            structure_validator = StructureValidator(file_path, is_added_file=not (False or is_backward_check),
                                                     is_renamed=True if old_file_path else False)
            if not structure_validator.is_file_valid():
                self._is_valid = False

            if not self.id_set_validator.is_file_valid_in_set(file_path):
                self._is_valid = False

            elif re.match(INTEGRATION_REGEX, file_path, re.IGNORECASE) or \
                    re.match(INTEGRATION_YML_REGEX, file_path, re.IGNORECASE):

                image_validator = ImageValidator(file_path)
                if not image_validator.is_valid():
                    self._is_valid = False

                description_validator = DescriptionValidator(file_path)
                if not description_validator.is_valid():
                    self._is_valid = False

                integration_validator = IntegrationValidator(file_path, old_file_path=old_file_path)
                if is_backward_check and not integration_validator.is_backward_compatible():
                    self._is_valid = False
                if not integration_validator.is_valid_integration():
                    self._is_valid = False

            elif re.match(SCRIPT_REGEX, file_path, re.IGNORECASE):
                script_validator = ScriptValidator(file_path, old_file_path=old_file_path)
                if is_backward_check and not script_validator.is_backward_compatible():
                    self._is_valid = False
                if not script_validator.is_valid_script():
                    self._is_valid = False

            elif re.match(SCRIPT_YML_REGEX, file_path, re.IGNORECASE) or \
                    re.match(SCRIPT_PY_REGEX, file_path, re.IGNORECASE) or \
                    re.match(SCRIPT_JS_REGEX, file_path, re.IGNORECASE):

                yml_path, _ = get_script_package_data(os.path.dirname(file_path))
                script_validator = ScriptValidator(yml_path, old_file_path=old_file_path)
                if is_backward_check and not script_validator.is_backward_compatible():
                    self._is_valid = False

            elif re.match(IMAGE_REGEX, file_path, re.IGNORECASE):
                image_validator = ImageValidator(file_path)
                if not image_validator.is_valid():
                    self._is_valid = False

    def validate_added_files(self, added_files):
        """Validate the added files from your branch.

        In case we encounter an invalid file we set the self._is_valid param to False.

        Args:
            added_files (set): A set of the modified files in the current branch.
        """
        for file_path in added_files:
            print("Validating {}".format(file_path))

            structure_validator = StructureValidator(file_path, is_added_file=True)
            if not structure_validator.is_file_valid():
                self._is_valid = False

            if not self.id_set_validator.is_file_valid_in_set(file_path):
                self._is_valid = False

            if self.id_set_validator.is_file_has_used_id(file_path):
                self._is_valid = False

            if re.match(TEST_PLAYBOOK_REGEX, file_path, re.IGNORECASE):
                if not self.conf_json_validator.is_test_in_conf_json(collect_ids(file_path)):
                    self._is_valid = False

            elif re.match(INTEGRATION_REGEX, file_path, re.IGNORECASE) or \
                    re.match(INTEGRATION_YML_REGEX, file_path, re.IGNORECASE) or \
                    re.match(IMAGE_REGEX, file_path, re.IGNORECASE):

                image_validator = ImageValidator(file_path)
                if not image_validator.is_valid():
                    self._is_valid = False

                description_validator = DescriptionValidator(file_path)
                if not description_validator.is_valid():
                    self._is_valid = False

            elif re.match(IMAGE_REGEX, file_path, re.IGNORECASE):
                image_validator = ImageValidator(file_path)
                if not image_validator.is_valid():
                    self._is_valid = False

    def validate_no_secrets_found(self, branch_name):
        """Check if any secrets are found in your change set.

        Args:
            branch_name (string): The name of the branch you are working on.
        """
        secrets_found = get_secrets(branch_name, self.is_circle)
        if secrets_found:
            self._is_valid = False

    def validate_no_old_format(self, old_format_files):
        """ Validate there are no files in the old format(unified yml file for the code and configuration).

        Args:
            old_format_files(set): file names which are in the old format.
        """
        invalid_files = []
        for f in old_format_files:
            yaml_data = get_yaml(f)
            if 'toversion' not in yaml_data:  # we only fail on old format if no toversion (meaning it is latest)
                invalid_files.append(f)
        if invalid_files:
            print_error("You must update the following files to the new package format. The files are:\n{}".format(
                '\n'.join(list(invalid_files))))
            self._is_valid = False

    def validate_committed_files(self, branch_name, is_backward_check=True):
        """Validate that all the committed files in your branch are valid

        Args:
            branch_name (string): The name of the branch you are working on.
        """
        modified_files, added_files, old_format_files = self.get_modified_and_added_files(branch_name, self.is_circle)
        schema_changed = False
        for f in modified_files:
            if checked_type(f, [SCHEMA_REGEX]):
                schema_changed = True
        # Ensure schema change did not break BC
        if schema_changed:
            self.validate_all_files()
        else:
            self.validate_no_secrets_found(branch_name)
            self.validate_modified_files(modified_files, is_backward_check)
            self.validate_added_files(added_files)
            self.validate_no_old_format(old_format_files)

    def validate_all_files(self):
        """Validate all files in the repo are in the right format."""
        for regex in CHECKED_TYPES_REGEXES:
            splitted_regex = regex.split(".*")
            directory = splitted_regex[0]
            for root, dirs, files in os.walk(directory):
                if root not in DIR_LIST:  # Skipping in case we entered a package
                    continue
                print_color("Validating {} directory:".format(directory), LOG_COLORS.GREEN)
                for file_name in files:
                    file_path = os.path.join(root, file_name)
                    # skipping hidden files
                    if file_name.startswith('.'):
                        continue

                    print("Validating " + file_name)
                    structure_validator = StructureValidator(file_path)
                    if not structure_validator.is_valid_scheme():
                        self._is_valid = False

                if root in PACKAGE_SUPPORTING_DIRECTORIES:
                    for inner_dir in dirs:
                        file_path = glob.glob(os.path.join(root, inner_dir, '*.yml'))[0]
                        print("Validating " + file_path)
                        structure_validator = StructureValidator(file_path)
                        if not structure_validator.is_valid_scheme():
                            self._is_valid = False

    def is_valid_structure(self, branch_name, is_backward_check=True):
        """Check if the structure is valid for the case we are in, master - all files, branch - changed files.

        Args:
            branch_name (string): The name of the branch we are working on.

        Returns:
            (bool). Whether the structure is valid or not.
        """
        if not self.conf_json_validator.is_valid_conf_json():
            self._is_valid = False

        if branch_name != 'master' and not branch_name.startswith('19.') and not branch_name.startswith('20.'):
            # validates only committed files
            self.validate_committed_files(branch_name, is_backward_check=is_backward_check)
        else:
            # validates all of Content repo directories according to their schemas
            self.validate_all_files()
            if branch_name != 'master':
                self.validate_with_previous_version(branch_name)

        return self._is_valid

    def validate_with_previous_version(self, release_branch_name):
        """Validate all files from previous version

        Args:
            release_branch_name: current release branch name to validate with
        """
        prev_version_name = self.get_previous_release_branch(release_branch_name)
        # Validate previous version only if found it
        if prev_version_name:
            modified_files, added_files, old_format_files = \
                self.get_modified_and_added_files(release_branch_name, self.is_circle, prev_version_name)
            # TODO: Ask whether I should limit the tests
            self.validate_modified_files(modified_files, is_backward_check=True)
        else:
            print_color(
                "Failed BC check. No release version prior to {} found in git.".format(release_branch_name),
                LOG_COLORS.RED)
            sys.exit(1)


def main():
    """Execute FilesValidator checks on the modified changes in your branch, or all files in case of master.

    This script runs both in a local and a remote environment. In a local environment we don't have any
    logger assigned, and then pykwalify raises an error, since it is logging the validation results.
    Therefore, if we are in a local env, we set up a logger. Also, we set the logger's level to critical
    so the user won't be disturbed by non critical loggings
    """
    branches = run_command("git branch")
    branch_name_reg = re.search("\* (.*)", branches)
    branch_name = branch_name_reg.group(1)

    parser = argparse.ArgumentParser(description='Utility CircleCI usage')
    parser.add_argument('-c', '--circle', type=str2bool, default=False, help='Is CircleCi or not')
    parser.add_argument('-b', '--backwardComp', type=str2bool, default=True, help='To check backward compatibility.')
    parser.add_argument('-t', '--test-filter', type=str2bool, default=False, help='Check that tests are valid.')
    options = parser.parse_args()
    is_circle = options.circle
    is_backward_check = options.backwardComp

    logging.basicConfig(level=logging.CRITICAL)

    print_color("Starting validating files structure", LOG_COLORS.GREEN)
    files_validator = FilesValidator(is_circle)
    if not files_validator.is_valid_structure(branch_name, is_backward_check=is_backward_check):
        sys.exit(1)
    if options.test_filter:
        try:
            print_color("Updating idset. Be patient if this is the first time...", LOG_COLORS.YELLOW)
            subprocess.check_output(["./Tests/scripts/update_id_set.py"])
            print_color("Checking that we have tests for all content...", LOG_COLORS.YELLOW)
            try:
                tests_out = subprocess.check_output(["./Tests/scripts/configure_tests.py", "-s", "true"],
                                                    stderr=subprocess.STDOUT)
                print(tests_out)
            except Exception:
                print_color("Recreating idset to be sure that configure tests failure is accurate."
                            " Be patient this can take 15-20 seconds ...", LOG_COLORS.YELLOW)
                subprocess.check_output(["./Tests/scripts/update_id_set.py", "-r"])
                print_color("Checking that we have tests for all content again...", LOG_COLORS.YELLOW)
                subprocess.check_call(["./Tests/scripts/configure_tests.py", "-s", "true"])
        except Exception as ex:
            print_color("Failed validating tests: {}".format(ex), LOG_COLORS.RED)
            sys.exit(1)
    print_color("Finished validating files structure", LOG_COLORS.GREEN)
    sys.exit(0)


if __name__ == "__main__":
    main()
