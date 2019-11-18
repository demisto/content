import os
from abc import abstractmethod

import requests
import yaml

from Tests.scripts.constants import CONTENT_GITHUB_LINK
from Tests.scripts.hook_validations.error_constants import Errors
from Tests.test_utils import print_error, server_version_compare, get_yaml, print_warning
from structure import StructureValidator


class YMLBasedValidator(StructureValidator):
    """

    Attributes:
        file_path (str): the path to the file we are examining at the moment.
       current_file (dict): Json representation of the current script from the branch.
       old_file (dict): Json representation of the current script from master.
    """
    def __init__(self, file_path, is_added_file=False, is_renamed=False, check_git=True, old_file_path=None, old_git_branch='master'):
        self.current_file = get_yaml(file_path)
        self.old_file = {}

        # Gets old file
        if check_git:
            # The replace in the end is for Windows support
            if old_file_path:
                git_hub_path = os.path.join(CONTENT_GITHUB_LINK, old_git_branch, old_file_path).replace("\\", "/")
                file_content = requests.get(git_hub_path, verify=False).content
                self.old_file = yaml.safe_load(file_content)
            else:
                git_hub_path = os.path.join(CONTENT_GITHUB_LINK, old_git_branch, file_path).replace("\\", "/")
            try:
                res = requests.get(git_hub_path, verify=False)
                res.raise_for_status()
                self.old_file = yaml.safe_load(res.content)
            except Exception as e:
                print_warning(Errors.breaking_backwards_no_old_script(e))
        super(YMLBasedValidator, self).__init__(file_path, is_added_file, is_renamed)
        self.is_valid_version()

    @abstractmethod
    def is_backward_compatible(self):
        """Check whether the Integration is backward compatible or not, update the _is_valid field to determine that"""
        if not self.old_file:
            return True

        self.is_context_path_changed()
        self.is_docker_image_changed()
        self.is_added_required_fields()
        self.is_changed_command_name_or_arg()
        self.is_there_duplicates_args()
        self.is_there_duplicate_params()
        self.is_changed_subtype()

        # will move to is_valid_integration after https://github.com/demisto/etc/issues/17949
        self.is_outputs_for_reputations_commands_valid()
        return self.is_valid

    @abstractmethod
    def is_docker_image_changed(self):
        if server_version_compare(self.current_file.get('fromversion', '0'), '5.0.0') < 0:
            if self.old_file.get('script', {}).get('dockerimage', "") != \
                    self.current_file.get('script', {}).get('dockerimage', ""):
                return True
        return False

    @abstractmethod
    def is_context_path_changed(self):
        pass

    @classmethod
    def get_arg_to_required_dict(cls, args_obj, *args, **kwargs):
        """Get a dictionary arg name to its required status.

        Args:
            args_obj (list): args to process

        Returns:
            dict. arg name to its required status.
        """
        arg_to_required = {}
        for arg in args_obj:
            arg_to_required[arg.get('name')] = arg.get('required', False)
        return arg_to_required

    @staticmethod
    def find_duplicates(arg_list):
        arg_set = set()
        duplicates_set = set()
        for arg in arg_list:
            if arg not in arg_set:
                arg_set.add(arg)
            else:
                duplicates_set.add(arg)
        return duplicates_set

    @abstractmethod
    def is_changed_subtype(self):
        pass

    @classmethod
    def _is_sub_set(cls, supposed_bigger_list, supposed_smaller_list):
        """Check if supposed_smaller_list is a subset of the supposed_bigger_list"""
        for check_item in supposed_smaller_list:
            if check_item not in supposed_bigger_list:
                return False
        return True

    def is_valid_version(self, expected_file_version=-1):
        yaml_dict = get_yaml(self.file_path)
        version_number = yaml_dict.get('commonfields', {}).get('version')
        if version_number != expected_file_version:
            print_error(Errors.wrong_version(self.file_path, expected_file_version))
            self.is_valid = False

        return self.is_valid

    def load_data_from_file(self, load_function=yaml.safe_load):
        return super(YMLBasedValidator, self).load_data_from_file(load_function)

    def is_there_duplicates(self, args_go_check):
        duplicates = self.find_duplicates(args_go_check)
        if duplicates:
            self.is_valid = False
            return duplicates
        return False
