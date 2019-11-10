import re

from Tests.test_utils import run_command

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

    def __init__(self, file_path, is_added_file=False, is_renamed=False):
        self._is_valid = self.is_file_valid()
        self.file_path = file_path
        self.is_added_file = is_added_file
        self.is_renamed = is_renamed

    def is_file_valid(self):
        """Checks if given file is valid

        Returns:
            (bool): Is file is valid
        """
        pass

    def is_valid_scheme(self):
        """Check if the scheme is valid

        Returns:
            (bool) is the scheme is valid
        """
        pass

    def is_valid_fromversion_on_modified(self, change_string=None):
        """Check that the fromversion property was not changed on existing Content files.

        Args:
            change_string (string): the string that indicates the changed done on the file(git diff)

        Returns:
            bool. Whether the files' fromversion as been modified or not.
        """
        pass

    @staticmethod
    def is_release_branch():
        """Check if we are working on a release branch."""
        diff_string_config_yml = run_command("git diff origin/master .circleci/config.yml")
        if re.search(r'[+-][ ]+CONTENT_VERSION: ".*', diff_string_config_yml):
            return True
        return False

    class Errors(object):
        @staticmethod
        def wrong_filename(filepath, file_type):
            return '"{}" is not a valid {} filename.'.format(filepath, file_type)

        @staticmethod
        def wrong_version(file_path, expected="-1"):
            # type: (str, str) -> str
            return "The version for our files should always be -1, please update the file {}.".format(file_path,
                                                                                                      expected)
