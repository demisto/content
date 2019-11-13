import os
import re
import sys
from abc import abstractmethod

from pykwalify.errors import CoreError

from Tests.test_utils import run_command, print_error

try:
    from pykwalify.core import Core
except ImportError:
    print('Please install pykwalify, you can do it by running: `pip install -I pykwalify`')
    sys.exit(1)


class StructureValidator(object):
    """Structure validator is designed to validate the correctness of the file structure we enter to content repo.

        Attributes:
            file_path (str): the path to the file we are examining at the moment.
            _is_valid (bool): the attribute which saves the valid/in-valid status of the current file.
            is_added_file (bool): whether the file is modified or added.
        """
    SCHEMAS_PATH = "Tests/schemas/"

    def __init__(self, file_path, is_added_file=False, is_renamed=False):
        self._is_valid = self.is_file_valid()
        self.file_path = file_path
        self.is_added_file = is_added_file
        self.is_renamed = is_renamed

    @abstractmethod
    def is_file_valid(self):
        """Checks if given file is valid

        Returns:
            (bool): Is file is valid
        """
        pass

    def _is_valid_scheme(self, schema_name):
        """Validate the file scheme according to the scheme we have saved in SCHEMAS_PATH.

        Args:
            schema_name:

        Returns:
            bool. Whether the scheme is valid on self.file_path.
        """
        c = Core(source_file=self.file_path,
                 schema_files=[os.path.join(self.SCHEMAS_PATH, '{}.yml'.format(schema_name))])
        try:
            c.validate(raise_exception=True)
        except CoreError as err:
            print_error('Failed: {} failed.\n{}'.format(self.file_path, str(err)))
            self._is_valid = False
        return self._is_valid

    @staticmethod
    def is_release_branch():
        """Check if we are working on a release branch."""
        diff_string_config_yml = run_command("git diff origin/master .circleci/config.yml")
        if re.search(r'[+-][ ]+CONTENT_VERSION: ".*', diff_string_config_yml):
            return True
        return False

    @staticmethod
    def is_subset_dictionary(new_dict, old_dict):
        """Check if the new dictionary is a sub set of the old dictionary.

        Args:
            new_dict (dict): current branch result from _get_command_to_args
            old_dict (dict): master branch result from _get_command_to_args

        Returns:
            bool. Whether the new dictionary is a sub set of the old dictionary.
        """
        for arg, required in old_dict.items():
            if arg not in new_dict.keys():
                return False

            if required != new_dict[arg] and new_dict[arg]:
                return False

        for arg, required in new_dict.items():
            if arg not in old_dict.keys() and required:
                return False
        return True
