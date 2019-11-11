import re
from abc import abstractmethod

from Tests.scripts.hook_validations.error_constants import Errors
from Tests.test_utils import print_warning, run_command, print_error
from structure import StructureValidator


class YMLBasedValidator(StructureValidator):
    def __init__(self, file_path, is_added_file=False, is_renamed=False):
        super(YMLBasedValidator, self).__init__(file_path, is_added_file, is_renamed)

    @abstractmethod
    def is_backward_compatible(self):
        pass

    @abstractmethod
    def is_docker_image_changed(self):
        pass

    @abstractmethod
    def is_context_path_changed(self):
        pass

    @classmethod
    def _get_arg_to_required_dict(cls, json_object, args_to_get):
        """Get a dictionary arg name to its required status.

        Args:
            json_object (dict): Dictionary of the examined script.

        Returns:
            dict. arg name to its required status.
        """
        arg_to_required = {}
        args = json_object.get(args_to_get, [])
        for arg in args:
            arg_to_required[arg.get('name')] = arg.get('required', False)
        return arg_to_required

    @abstractmethod
    def is_arg_changed(self):
        pass

    @abstractmethod
    def is_there_duplicate_args(self):
        pass

    @abstractmethod
    def is_changed_subtype(self):
        pass

    def is_valid_fromversion_on_modified(self, change_string=None):
        """Check that the fromversion property was not changed on existing Content files.

        Args:
            change_string (string): the string that indicates the changed done on the file(git diff)

        Returns:
            bool. Whether the files' fromversion as been modified or not.
        """
        if self.is_renamed:
            print_warning(Errors.from_version_modified_after_rename())
            return True

        if not change_string:
            change_string = run_command("git diff HEAD {0}".format(self.file_path))

        is_added_from_version = re.search(r"\+([ ]+)?fromversion: .*", change_string)
        is_added_from_version_secondary = re.search(r"\+([ ]+)?\"fromVersion\": .*", change_string)

        if is_added_from_version or is_added_from_version_secondary:
            print_error(Errors.from_version_modified(self.file_path))
            self._is_valid = False

        return self._is_valid

    @abstractmethod
    def is_file_id_without_slashes(self):
        """Check if the ID of the file contains any slashes ('/').

        Returns:
            bool. Whether the file's ID contains slashes or not.
        """
        pass

    @classmethod
    def _is_sub_set(cls, supposed_bigger_list, supposed_smaller_list):
        """Check if supposed_smaller_list is a subset of the supposed_bigger_list"""
        for check_item in supposed_smaller_list:
            if check_item not in supposed_bigger_list:
                return False
        return True
