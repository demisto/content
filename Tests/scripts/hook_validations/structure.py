import os
import os
import re
import sys
from abc import abstractmethod

from pykwalify.errors import CoreError

from Tests.scripts.hook_validations.error_constants import Errors
from Tests.test_utils import run_command, print_error, print_warning, get_release_notes_file_path, \
    get_latest_release_notes_text

try:
    from pykwalify.core import Core
except ImportError:
    print('Please install pykwalify, you can do it by running: `pip install -I pykwalify`')
    sys.exit(1)


class StructureValidator(object):
    """Structure validator is designed to validate the correctness of the file structure we enter to content repo.

        Attributes:
            file_path (str): the path to the file we are examining at the moment.
            is_valid (bool): the attribute which saves the valid/in-valid status of the current file.
            is_added_file (bool): whether the file is modified or added.
        """
    SCHEMAS_PATH = "Tests/schemas/"

    def __init__(self, file_path, is_added_file=False, is_renamed=False):
        self.current_file = self.load_data_from_file()
        self.is_valid = True
        self.file_path = file_path
        self.is_added_file = is_added_file
        self.is_renamed = is_renamed

    @abstractmethod
    def is_file_valid(self, validate_rn=True, *args, **kwargs):
        """Checks if given file is valid

        Returns:
            (bool): Is file is valid
        """
        self.is_file_id_without_slashes()

        if not self.is_added_file:  # In case the file is modified
            self.is_id_not_modified()
            self.is_valid_fromversion_on_modified()
            # In case of release branch we allow to remove release notes
            if validate_rn and not self.is_release_branch():
                self.validate_file_release_notes()

    def is_valid_scheme(self, schema_name):
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
            self.is_valid = False
            return False
        return True

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

    @staticmethod
    def get_file_id_from_loaded_file_data(loaded_file_data):
        file_id = loaded_file_data.get('id')
        if not file_id:
            # In integrations/scripts, the id is under 'commonfields'.
            file_id = loaded_file_data.get('commonfields', {}).get('id')
        if not file_id:
            # In layout, the id is under 'layout'.
            file_id = loaded_file_data.get('layout', {}).get('id')
        return file_id

    @abstractmethod
    def is_valid_version(self):
        pass

    def is_file_id_without_slashes(self):
        """Check if the ID of the file contains any slashes ('/').

        Returns:
            bool. Whether the file's ID contains slashes or not.
        """
        file_id = self.get_file_id_from_loaded_file_data(self.current_file)
        if file_id and '/' in file_id:
            self.is_valid = False
            print_error(Errors.file_id_contains_slashes())
            return False
        return True

    def is_id_not_modified(self, change_string=None):
        """Check if the ID of the file has been changed.

        Args:
            change_string (string): the string that indicates the changes done on the file(git diff)

        Returns:
            bool. Whether the file's ID has been modified or not.
        """
        if self.is_renamed:
            print_warning(Errors.id_might_changed())
            return True

        if not change_string:
            change_string = run_command("git diff HEAD {}".format(self.file_path))

        if re.search("[+-]( {2})?id: .*", change_string):
            print_error(Errors.id_changed(self.file_path))
            self.is_valid = False
        return self.is_valid

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
            self.is_valid = False

        return self.is_valid

    def validate_file_release_notes(self):
        """Validate that the file has proper release notes when modified.
        This function updates the class attribute self._is_valid instead of passing it back and forth.
        """
        if self.is_renamed:
            print_warning("You might need RN please make sure to check that.")
            return

        if os.path.isfile(self.file_path):
            rn_path = get_release_notes_file_path(self.file_path)
            rn = get_latest_release_notes_text(rn_path)

            # check rn file exists and contain text
            if rn is None:
                print_error(Errors.missing_release_notes(self.file_path, rn_path))
                self.is_valid = False

    @abstractmethod
    def load_data_from_file(self):
        """Returns dict"""
        pass
